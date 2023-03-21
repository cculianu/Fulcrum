//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "App.h"
#include "BitcoinD.h"
#include "Compat.h"
#include "PeerMgr.h"
#include "ServerMisc.h"
#include "Servers.h"
#include "SSLCertMonitor.h"
#include "Storage.h"
#include "SubsMgr.h"
#include "Util.h"

#include <mutex>
#include <utility>

namespace {
    constexpr size_t tableSqueezeThreshold = 64; ///< used by perIPData and addrIdMap to determing when to auto-squeeze.
    static_assert (tableSqueezeThreshold > 0, "SrvMgr table squeeze threshold must be > 0!");
}

SrvMgr::SrvMgr(const std::shared_ptr<const Options> & options,
               const SSLCertMonitor * certMon,
               const std::shared_ptr<Storage> & s,
               const std::shared_ptr<BitcoinDMgr> & bdm,
               QObject *parent)
    : Mgr(parent), options(options), sslCertMonitor(certMon), storage(s), bitcoindmgr(bdm),
      perIPData(this, tableSqueezeThreshold /* initialCapacity */, tableSqueezeThreshold)
{
    addrIdMap.reserve(tableSqueezeThreshold); // initial capacity
    perIPData.setObjectName("PerIPData");
    connect(this, &SrvMgr::banIP, this, &SrvMgr::on_banIP);
    connect(this, &SrvMgr::banID, this, &SrvMgr::on_banID);
    connect(this, &SrvMgr::liftIPBan, this, &SrvMgr::on_liftIPBan);
    connect(this, &SrvMgr::banPeersWithSuffix, this, &SrvMgr::on_banPeersWithSuffix);
    connect(this, &SrvMgr::liftPeerSuffixBan, this, &SrvMgr::on_liftPeerSuffixBan);
    connect(this, &SrvMgr::requestMaxBufferChange, app(), &App::on_requestMaxBufferChange, Qt::DirectConnection);
    connect(this, &SrvMgr::requestBitcoindThrottleParamsChange, app(), &App::on_bitcoindThrottleParamsChange, Qt::DirectConnection);
}

SrvMgr::~SrvMgr()
{
    Debug() << __func__ ;
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
    stopAllTimers();
    adminServers.clear(); // unique_ptrs, kill all admin servers first (these hold weak_ptrs to peermgr and also naked ptrs to this, so must be killed first)
    peermgr.reset(); // shared_ptr, kill peermgr (if any)
    servers.clear(); // unique_ptrs auto-delete all servers
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

// throw Exception on error
void SrvMgr::startServers()
{
    _net = BTC::NetFromName(storage->getChain()); // set this now since server instances may need this information

    if (options->peerDiscovery) {
        Log() << "SrvMgr: starting PeerMgr ...";
        peermgr = std::make_shared<PeerMgr>(this, storage, options);

        try {
            peermgr->startup();
        } catch (const Exception & e) {
             // startup failed, proceed without PeerMgr, but log the error
            Error() << "ERROR: PeerMgr startup failed: " << e.what();
            Warning() << "SrvMgr: Proceeding anyway, with peering disabled";
            peermgr.reset();
        }

        if (peermgr) {
            connect(this, &SrvMgr::allServersStarted, peermgr.get(), &PeerMgr::on_allServersStarted);
            connect(this, &SrvMgr::kickByAddress, peermgr.get(), &PeerMgr::on_kickByAddress);
            connect(this, &SrvMgr::kickPeersWithSuffix, peermgr.get(), [peermgr=peermgr.get()](const QString &sufIn){
                // we must intercept this signal and do this here because AdminServer also emits this with a potentially
                // un-normalized hostname suffix. Note this lambda executes in the peermgr thread context and thus should
                // *NOT* capture 'this' or touch 'this'.
                const auto suf = normalizeHostNameSuffix(sufIn);
                if (!suf.isEmpty())
                    peermgr->on_kickBySuffix(suf);
            });
        }
    } else peermgr.reset();

    const auto num =   options->interfaces.length() + options->sslInterfaces.length()
                     + options->wsInterfaces.length() + options->wssInterfaces.length()
                     + options->adminInterfaces.length();
    Log() << "SrvMgr: starting " << num << " " << Util::Pluralize("service", num) << " ...";
    const auto firstSsl = options->interfaces.size(),
               firstWs = options->interfaces.size() + options->sslInterfaces.size(),
               firstWss = options->interfaces.size() + options->sslInterfaces.size() + options->wsInterfaces.size();
    int i = 0;
    for (const auto & iface : options->interfaces + options->sslInterfaces + options->wsInterfaces + options->wssInterfaces) {
        if (i < firstSsl) {
            // TCP
            servers.emplace_back(std::make_unique<Server>(this, iface.first, iface.second, options, storage, bitcoindmgr));
        } else if (i < firstWs) {
            // SSL
            servers.emplace_back(std::make_unique<ServerSSL>(this, iface.first, iface.second, options, storage, bitcoindmgr));
        } else if (i < firstWss) {
            // WS
            servers.emplace_back(std::make_unique<Server>(this, iface.first, iface.second, options, storage, bitcoindmgr));
            servers.back()->setUsesWebSockets(true);
        } else {
            // WSS
            servers.emplace_back(std::make_unique<ServerSSL>(this, iface.first, iface.second, options, storage, bitcoindmgr));
            servers.back()->setUsesWebSockets(true);
        }
        Server *srv = servers.back().get();
        ServerSSL *srvSSL = dynamic_cast<ServerSSL *>(srv);

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

        // max_buffer changes
        connect(this, &SrvMgr::requestMaxBufferChange, srv, &ServerBase::applyMaxBufferToAllClients);

        // subs limit reached
        connect(srv, &Server::globalSubsLimitReached, this, &SrvMgr::globalSubsLimitReached);

        if (peermgr) {
            connect(srv, &ServerBase::gotRpcAddPeer, peermgr.get(), &PeerMgr::on_rpcAddPeer);
            connect(peermgr.get(), &PeerMgr::updated, srv, &ServerBase::onPeersUpdated);
        }

        if (srvSSL && sslCertMonitor) {
            // if the cert files change on disk, the server will re-load the cert into into its own class state
            connect(sslCertMonitor, &SSLCertMonitor::certInfoChanged, srvSSL, &ServerSSL::setupSslConfiguration);
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
    addrIdMap.insert(addr, cid); //NB: this is effectively an insertMulti() (deprecated in Qt 5.15)
    const auto maxPerIP = options->maxClientsPerIP;
    if (maxPerIP > 0 && addrIdMap.count(addr) > maxPerIP) {
        const auto ipData = findExistingPerIPData(addr);
        if (ipData) {
            Client::PerIPData::WhiteListState wlstate{Client::PerIPData::WhiteListState::UNINITIALIZED};
            Options::Subnet matched;
            {
                std::shared_lock g(ipData->mut); // shared lock guards ipData->whiteListSubnet
                wlstate = Client::PerIPData::WhiteListState(ipData->whiteListState.load());
                matched = ipData->_whiteListedSubnet; // copy out data with lock held
            }
            switch (wlstate) {
            case Client::PerIPData::WhiteListState::NotWhiteListed:
                // NEW! As of 4/14/2020, this case should never be reached now that we attach the PerIPData very early
                // on in the connection pipeline.  However, this code has been left here just in case for defensive
                // programming purposes.
                Warning() << "Connection limit (" << maxPerIP << ") exceeded for " << addr.toString()
                          << ", connection refused for client " << cid;
                emit clientExceedsConnectionLimit(cid);
                clientWillDieAnyway = true;
                break;
            case Client::PerIPData::WhiteListState::WhiteListed:
                DebugM("Client ", cid, " from ", addr.toString(), " would have exceeded the connection limit (",
                       maxPerIP, ") but its IP matches subnet ", matched.toString(), " from 'subnets_to_exclude_from_per_ip_limits'");
                break;
            default:
                // This should never happen.
                Error() << "Invalid WhiteListState " << int(wlstate) << " for Client " << cid << " from " << addr.toString() << ". FIXME!";
            }
        } else {
            clientWillDieAnyway = true;
            DebugM("Client ", cid, " from ", addr.toString(), " -- missing per-IP data. The client may have been already deleted.");
        }
    }

    // Lastly, check bans and tally ctr and increment counter anyway -- even if clientWillDieAnyway == true!
    const bool banned = isIPBanned(addr, true);

    if (banned && !clientWillDieAnyway) {
        Log() << "Rejecting client " << cid << " from " << addr.toString() << " (banned)";
        emit clientIsBanned(cid);
    }
}

bool SrvMgr::isIPBanned(const QHostAddress &addr, bool increment) const
{
    if (addr.isNull())
        return false;
    std::lock_guard g(banMut);
    if (auto it = banMap.find(addr); it != banMap.end()) {
        if (increment)
            ++it.value().rejectedConnectionCount;
        return true;
    }
    return false;
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
    if (auto count = addrIdMap.remove(addr, cid); UNLIKELY(count > 1)) {
        Warning() << "Multiple clients with id: " << cid << ", address " << addr.toString() << " in addrIdMap in " << __func__ << " -- FIXME!";
    } else if (count) {
        //DebugM("Client id ", cid, " addr ", addr.toString(), " removed from addrIdMap");
        if (const auto size = size_t(addrIdMap.size());
                size >= tableSqueezeThreshold && size * 2U <= size_t(addrIdMap.capacity())) {
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
        DebugM(__func__ , ": address is null!");
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
        DebugM("Unable to ban client ", cid, "; not found");
}

void SrvMgr::on_liftIPBan(const QHostAddress &addr)
{
    if (addr.isNull()) {
        DebugM(__func__ , ": address is null!");
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
    // regular servers
    {
        QVariantMap bloomFilters;
        for (const auto & server : servers) {
            // remove the "bloom filters" submap -- which is the same exact info for each server... we will put it at top level
            QVariantMap m = server->statsSafe(timeout).toMap();
            if (QVariantMap m2 = m.isEmpty() ? QVariantMap{} : m[m.firstKey()].toMap(); !m2.isEmpty()) {
                constexpr auto kBloomFilters = ServerMisc::kBloomFiltersKey;
                // unconditionally remove the "bloom filters" key, and remember it if first time through
                if (QVariant val = m2.take(kBloomFilters); !val.isNull() && bloomFilters.isEmpty())
                    bloomFilters[kBloomFilters] = val;
                m[m.firstKey()] = m2; // re-save the map without "bloom filters" submap
            }
            Compat::MapUnite(serversMap, m);
        }
        // if the shared "bloom filters" submap was found, put it at top level
        Compat::MapUnite(serversMap, bloomFilters);
    }
    // admin servers
    for (const auto & server : adminServers)
        Compat::MapUnite(serversMap, server->statsSafe(timeout).toMap());
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

std::shared_ptr<Client::PerIPData> SrvMgr::getOrCreatePerIPData(const QHostAddress &address)
{
    auto ret = perIPData.getOrCreate(address, true);
    // Note the below has a potential race condition *IF* the same IP address connected multiply from 2 different ServerBase
    // instances (each ServerBase has its own thread) *at the same time* and thus this object was freshly created
    // but is being returned twice in 2 different threads.  We guard against doing redundant work by first not using a mutex
    // to just check the atomic variable.  If the atomic variable is uninitialized, then we grab the mutex in exclusive mode.
    if (ret && ret->whiteListState == Client::PerIPData::WhiteListState::UNINITIALIZED) { // new instance
        std::unique_lock g(ret->mut);
        if (ret->whiteListState == Client::PerIPData::WhiteListState::UNINITIALIZED) { // check again with lock held.
            // Note: this query is a linear search through the exclude set, so hopefully the set is always small
            const bool whiteListed = options->isAddrInPerIPLimitExcludeSet(address, &ret->_whiteListedSubnet);
            ret->whiteListState = whiteListed ? Client::PerIPData::WhiteListState::WhiteListed
                                              : Client::PerIPData::WhiteListState::NotWhiteListed;
            if constexpr (!isReleaseBuild()) {
                if (whiteListed)
                    DebugM(address.toString(), " is whitelisted (subnet: ", ret->_whiteListedSubnet.toString(), ")");
                else
                    DebugM(address.toString(), " is NOT whitelisted");
            }
        }
    }
    return ret;
}

void SrvMgr::globalSubsLimitReached()
{
    // we rate limit this to at most once every 250 ms.
    static constexpr int kPeriod = int(1e3 * ServerMisc::kMaxSubsAutoKickDelaySecs);
    callOnTimerSoon(kPeriod, "+KickMostSubscribedClient",
                    [this, ctr=int(0)]() mutable {
        ++ctr; // increment counter for how many times this callback has executed
        // grab flags to get an idea of the state of the limits
        const auto [activeNearLimit, allNearLimit] = storage->subs()->globalSubsLimitFlags(); // both this and dspSubs() will return the same bools here, so we just grab one

        // request a zombie removal on return
        Defer deferred = [this, allNearLimit=allNearLimit /*<- C++ bugs */] {
            if (allNearLimit) {
                const int when = kPeriod / 2;
                DebugM("Requesting zombie sub removal in ", when, " msec ...");
                // we do it with a delay to give the kick code time to run.
                emit storage->subs()->requestRemoveZombiesSoon(when);
                emit storage->dspSubs()->requestRemoveZombiesSoon(when);
                emit storage->txSubs()->requestRemoveZombiesSoon(when);
            }
        };

        if (!activeNearLimit) {
            // Ok, so there may be zombies. Come back again if there are, and give the zombie reaper a chance to fire.
            DebugM("SrvMgr max subs kicker: Timer fired but we are no longer near the global active subs limit, returning early ...");
            return allNearLimit && ctr < 2; // fire once again later if we are near the limit after zombies are collected.
        }

        int64_t max = 0;
        QHostAddress maxIP;
        int tableSize{};
        {
            int64_t nSubs{};
            // iterate through all known client datas and find the IP address with the most subs to kick
            const auto [table, lock] = perIPData.getTable();
            tableSize = table.size();
            for (auto it = table.cbegin(); it != table.cend(); ++it) {
                if (const auto data = it.value().lock();
                        data && (nSubs = data->nShSubs.load()) > max && !it.key().isNull()) // todo; maybe skip over whitelisted IPs?
                {
                     max = nSubs;
                     maxIP = it.key();
                }
            }
            // lock released at scope end
        }
        if (LIKELY(max > 0)) {
            Log() << "Global subs limit reached, kicking all clients for IP " << maxIP.toString() << " (subs: " << max << ")";
            emit kickByAddress(maxIP); // kick!
        } else {
            DebugM("Global subs limit reached, but could not find a client to kick (num per-IP-datas: ", tableSize, ")");
        }
        return false; // don't keep firing in this execution path.
    });
}

/// Thread-Safe. Returns whether bitcoind currently probes as having the dsproof RPC.
bool SrvMgr::hasDSProofRPC() const { return bitcoindmgr && bitcoindmgr->hasDSProofRPC(); }
