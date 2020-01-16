//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#include "SrvMgr.h"

#include "BitcoinD.h"
#include "PeerMgr.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <utility>

SrvMgr::SrvMgr(const std::shared_ptr<const Options> & options,
               const std::shared_ptr<Storage> & s,
               const std::shared_ptr<BitcoinDMgr> & bdm,
               QObject *parent)
    : Mgr(parent), options(options), storage(s), bitcoindmgr(bdm)
{
    connect(this, &SrvMgr::banIP, this, &SrvMgr::on_banIP);
    connect(this, &SrvMgr::liftIPBan, this, &SrvMgr::on_liftIPBan);
    connect(this, &SrvMgr::banPeersWithSuffix, this, &SrvMgr::on_banPeersWithSuffix);
    connect(this, &SrvMgr::liftPeerSuffixBan, this, &SrvMgr::on_liftPeerSuffixBan);
}

SrvMgr::~SrvMgr()
{
    Debug() << __FUNCTION__ ;
    cleanup();
}

// will throw Exception on error from within TcpServer::tryStart
void SrvMgr::startup()
{
    if (servers.empty()) {
        startServers();
    } else {
        Error() << __PRETTY_FUNCTION__ << " called with servers already active! FIXME!";
    }
}

void SrvMgr::cleanup()
{
    adminServers.clear(); // unique_ptrs, kill all admin servers first (these hold weak_ptrs to peermgr and also naked ptrs to this, so must be killed first)
    peermgr.reset(); // shared_ptr, kill peermgr (if any)
    servers.clear(); // unique_ptrs auto-delete all servers
}

// throw Exception on error
void SrvMgr::startServers()
{
    if (options->peerDiscovery) {
        Log() << "SrvMgr: starting PeerMgr ...";
        peermgr = std::make_shared<PeerMgr>(this, storage, options);
        peermgr->startup(); // may throw
        connect(this, &SrvMgr::allServersStarted, peermgr.get(), &PeerMgr::on_allServersStarted);
        connect(this, &SrvMgr::kickByAddress, peermgr.get(), &PeerMgr::on_kickByAddress);
        connect(this, &SrvMgr::kickPeersWithSuffix, peermgr.get(), &PeerMgr::on_kickBySuffix);
    } else peermgr.reset();

    const auto num = options->interfaces.length() + options->sslInterfaces.length() + options->adminInterfaces.length();
    Log() << "SrvMgr: starting " << num << " " << Util::Pluralize("service", num) << " ...";
    const auto firstSsl = options->interfaces.size();
    int i = 0;
    for (const auto & iface : options->interfaces + options->sslInterfaces) {
        if (i < firstSsl)
            // TCP
            servers.emplace_back(std::make_unique<Server>(iface.first, iface.second, options, storage, bitcoindmgr));
        else
            // SSL
            servers.emplace_back(std::make_unique<ServerSSL>(iface.first, iface.second, options, storage, bitcoindmgr));
        Server *srv = servers.back().get();

        // connect blockchain.headers.subscribe signal
        connect(this, &SrvMgr::newHeader, srv, &Server::newHeader);
        // track client lifecycles for per-ip-address connection limits and other stuff
        connect(srv, &ServerBase::clientConnected, this, &SrvMgr::clientConnected);
        connect(srv, &ServerBase::clientDisconnected, this, &SrvMgr::clientDisconnected);
        // if srv receives this message, it will delete the client then we will get a signal back that it is now gone
        connect(this, &SrvMgr::clientExceedsConnectionLimit, srv, qOverload<IdMixin::Id>(&ServerBase::killClient));
        // same situation here as above -- servers kick the client in question immediately
        connect(this, &SrvMgr::clientIsBanned, srv, qOverload<IdMixin::Id>(&ServerBase::killClient));
        // tally tx broadcasts (lifetime)
        connect(srv, &Server::broadcastTxSuccess, this, [this](unsigned bytes){ ++numTxBroadcasts; txBroadcastBytesTotal += bytes; });

        // kicking
        connect(this, &SrvMgr::kickById, srv, qOverload<IdMixin::Id>(&ServerBase::killClient));
        connect(this, &SrvMgr::kickByAddress, srv, &ServerBase::killClientsByAddress);

        if (peermgr) {
            connect(srv, &ServerBase::gotRpcAddPeer, peermgr.get(), &PeerMgr::on_rpcAddPeer);
            connect(peermgr.get(), &PeerMgr::updated, srv, &ServerBase::onPeersUpdated);
        }

        srv->tryStart();
        ++i;
    }
    // next do admin RPC, if any
    for (const auto & iface : options->adminInterfaces) {
        adminServers.emplace_back( std::make_unique<AdminServer>(this, iface.first, iface.second, options, storage, bitcoindmgr, peermgr) );
        AdminServer *asrv = adminServers.back().get();
        if (peermgr) {
            connect(asrv, &ServerBase::gotRpcAddPeer, peermgr.get(), &PeerMgr::on_rpcAddPeer);
            connect(peermgr.get(), &PeerMgr::updated, asrv, &ServerBase::onPeersUpdated);
        }
        asrv->tryStart();
    }

    emit allServersStarted();
}

void SrvMgr::clientConnected(IdMixin::Id cid, const QHostAddress &addr)
{
    bool clientWillDieAnyway = false;
    addrIdMap.insertMulti(addr, cid);
    const auto maxPerIP = options->maxClientsPerIP;
    if (addrIdMap.count(addr) > maxPerIP) {
        // the below ends up linearly searching through excluded subnets --  this branch is only really taken if the
        // limit is hit .. O(N) where N is probably very small should hopefully be fast enough
        if (Options::Subnet matched; ! options->isAddrInPerIPLimitExcludeSet(addr, &matched) ) {
            Log() << "Connection limit (" << maxPerIP << ") exceeded for " << addr.toString()
                  << ", connection refused for client " << cid;
            emit clientExceedsConnectionLimit(cid);
            clientWillDieAnyway = true;
        } else {
            Debug() << "Client " << cid << " from " << addr.toString() << " would have exceeded the connection limit ("
                    << maxPerIP << ") but its IP matches subnet " << matched.toString() << " from 'subnets_to_exclude_from_per_ip_limits'";
        }
    }

    // lastly, check bans and tally ctr and increment counter anyway -- even if clientWillDieAnyway == true
    const bool banned = isIPBanned(addr, true);

    if (banned && !clientWillDieAnyway) {
        Log() << "Rejecting client " << cid << " from " << addr.toString() << " (banned)";
        emit clientIsBanned(cid);
    }
}

bool SrvMgr::isIPBanned(const QHostAddress &addr, bool increment) const
{
    std::lock_guard g(banMut);
    if (auto it = banMap.find(addr); it != banMap.end()) {
        if (increment)
            ++it.value().rejectedConnectionCount;
        return true;
    }
    return false;
}

namespace {
    QString normalizeHostNameSuffix(const QString &s) {
        QString ret = s.trimmed().toLower();

        // strip leading '.' and '*' chars
        int pos = 0;
        const int len = ret.length();
        static const QChar dot('.'), star('*');
        for (QChar c; pos < len && ( (c = ret.at(pos)) == dot || c == star ) ; ++pos)
        { /* */ }
        if (pos) ret = ret.mid(pos);
        //

        return ret;
    }
}

bool SrvMgr::isPeerHostNameBanned(const QString &h) const
{
    const QString hostName(normalizeHostNameSuffix(h));
    if (hostName.isEmpty())
        return false;
    std::lock_guard g(banMut);
    // we must do a linear search because we support *.host.whatever.com bans (which get normalized to a host.whatever.com suffix search)
    for (auto it = bannedPeerSuffixes.cbegin(); it != bannedPeerSuffixes.cend(); ++it) {
        if (hostName.endsWith(it.key()))
            return true;
    }
    return false;
}


void SrvMgr::clientDisconnected(IdMixin::Id cid, const QHostAddress &addr)
{
    if (auto count = addrIdMap.remove(addr, cid); count > 1) {
        Warning() << "Multiple clients with id: " << cid << ", address " << addr.toString() << " in addrIdMap in " << __func__ << " -- FIXME!";
    } else if (count) {
        //Debug() << "Client id " << cid << " addr " << addr.toString() << " removed from addrIdMap";
        if (const auto size = addrIdMap.size(); size >= 64 && size * 2 <= addrIdMap.capacity()) {
            // save space if we are over 2x capacity vs size
            addrIdMap.squeeze();
        }
    }
}

void SrvMgr::on_banPeersWithSuffix(const QString &hn)
{
    const QString suffix(normalizeHostNameSuffix(hn)); // normalize
    if (suffix.isEmpty())
        return;
    bool newBan = false;
    {
        std::lock_guard g(banMut);
        if (!bannedPeerSuffixes.contains(suffix)) {
            newBan = true;
            auto & info = bannedPeerSuffixes[suffix];
            info.ts = Util::getTime(); // remember when we banned it for stats / admin rpc display
        }
    }
    if (newBan)
        Log() << "Peers with host names matching *" << suffix << " are now banned";
    emit kickPeersWithSuffix(suffix); // tell peer mgr to kick peers it has with that name (if any)
}

void SrvMgr::on_liftPeerSuffixBan(const QString &s)
{
    const QString suffix(normalizeHostNameSuffix(s));
    if (suffix.isEmpty())
        return;
    bool wasBanned = false;
    {
        std::lock_guard g(banMut);
        wasBanned = bannedPeerSuffixes.remove(suffix);
    }
    if (wasBanned)
        Log() << "Peers matching suffix *" << suffix << " are no longer banned";
}

void SrvMgr::on_banIP(const QHostAddress &addr)
{
    if (addr.isNull()) {
        Debug() << __func__ << ": address is null!";
        return;
    }
    bool wasNew = false;
    {
        // place in map if not already there
        std::lock_guard g(banMut);
        if (!banMap.contains(addr)) {
            wasNew = true;
            auto & bi = banMap[addr];
            bi.ts = Util::getTime();
            bi.address = addr;
        }
    }
    int kicks = addrIdMap.count(addr);
    emit kickByAddress(addr); // we must emit this regardless as the PeerMgr also listens for this, and we have no way of knowing from this class if it's connected to the peer in question or has it in queue, etc.
    if (wasNew || kicks)
        Log() << addr.toString() << " is now banned"
              << (kicks ? QString(" (%1 %2 kicked)").arg(kicks).arg(Util::Pluralize("client", kicks)) : QString());
}

void SrvMgr::on_banID(IdMixin::Id cid)
{
    QHostAddress found;
    for (auto it = addrIdMap.cbegin(); it != addrIdMap.cend(); ++it) {
        if (it.value() == cid) {
            found = it.key();
            break;
        }
    }
    if (!found.isNull())
        emit banIP(found);
    else
        Debug() << "Unable to ban client " << cid << "; not found";
}

void SrvMgr::on_liftIPBan(const QHostAddress &addr)
{
    if (addr.isNull()) {
        Debug() << __func__ << ": address is null!";
        return;
    }

    bool wasBanned = false;
    {
        std::lock_guard g(banMut);
        wasBanned = banMap.remove(addr);
    }
    if (wasBanned)
        Log() << "Address " << addr.toString() << " is no longer banned";
}

auto SrvMgr::stats() const -> Stats
{
    QVariantMap m;
    m["donationAddress"] = options->donationAddress;
    m["bannerFile"] = options->bannerFile.toUtf8(); // so we get a nice 'null' if not specified
    QVariantMap serversMap;
    const int timeout = kDefaultTimeout / qMax(int(servers.size()), 1);
    for (const auto & server : servers)
        serversMap.unite( server->statsSafe(timeout).toMap() );
    for (const auto & server : adminServers)
        serversMap.unite( server->statsSafe(timeout).toMap() );
    m["Servers"] = serversMap;
    m["PeerMgr"] = peermgr ? peermgr->statsSafe(kDefaultTimeout/2) : QVariant();
    m["transactions sent"] = qulonglong(numTxBroadcasts.load());
    m["transactions sent (bytes)"] = qulonglong(txBroadcastBytesTotal.load());
    m["number of clients"] = qulonglong(Client::numClients.load());
    m["number of clients (max lifetime)"] = qulonglong(Client::numClientsMax.load());
    m["number of clients (total lifetime connections)"] = qulonglong(Client::numClientsCtr.load());
    m["bans"] = adminRPC_banInfo_threadSafe();
    return m;
}

QVariantMap SrvMgr::adminRPC_banInfo_threadSafe() const
{
    QVariantMap ret;
    std::lock_guard g(banMut);
    QVariantMap ipbans, hostnamebans;
    for (const auto & ban : banMap) {
        QVariantMap m;
        m["connections_rejected"] = ban.rejectedConnectionCount;
        m["age_secs"] = qlonglong(std::round((Util::getTime() - ban.ts)/1e3));
        ipbans[ban.address.toString()] = m;
    }
    for (auto it = bannedPeerSuffixes.begin(); it != bannedPeerSuffixes.end(); ++it) {
        const auto & ban = it.value();
        QVariantMap m;
        m["age_secs"] = qlonglong(std::round((Util::getTime() - ban.ts)/1e3));
        hostnamebans[QString("*") + it.key()] = m;
    }

    ret["Banned_IPAddrs"] = ipbans;
    ret["Banned_Peers"] = hostnamebans;

    return ret;
}

QVariantList SrvMgr::adminRPC_getClients_blocking(int timeout_ms) const
{
    return Util::LambdaOnObject<QVariantList>(this, [this, timeout_ms] {
        const bool infiniteTimeout = timeout_ms <= 0;
        const auto nServers = std::max(int(servers.size()), 1);
        const int timeoutPerServer = infiniteTimeout ? -1 : std::max(timeout_ms / nServers, 1);
        QVariantList ret;
        for (const auto & server : servers)
            ret.push_back( server->statsSafe(timeoutPerServer) );
        return ret;
    }, timeout_ms);
}
