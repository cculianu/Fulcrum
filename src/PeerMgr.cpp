//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "PeerMgr.h"

#include "Compat.h"
#include "Options.h"
#include "Servers.h"
#include "SrvMgr.h"
#include "Storage.h"
#include "Util.h"

#include <QHostInfo>
#include <QMultiMap>
#include <QSet>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>
#include <QVector>

#include <algorithm>
#include <list>
#include <memory>
#include <utility>

namespace {
    constexpr int kStringMax = 80, kHostNameMax = 120;
    constexpr bool debugPrint = false;
    bool isValidPort(unsigned port) { return port != 0u && std::in_range<quint16>(port); }
}

PeerMgr::PeerMgr(const SrvMgr *sm, const std::shared_ptr<Storage> &storage_ , const std::shared_ptr<const Options> &options_)
    : IdMixin(newId()), srvmgr(sm), storage(storage_), options(options_)
{
    assert(srvmgr && storage && options);
    setObjectName("PeerMgr");
    _thread.setObjectName(objectName());

    // setup the Tor proxy -- note if user didn't specify it in config, it simply defaults to 127.0.0.1, port 9050
    proxy.setType(QNetworkProxy::ProxyType::Socks5Proxy);
    proxy.setHostName(options->torProxy.first.toString());
    proxy.setPort(options->torProxy.second);
    proxy.setCapabilities(QNetworkProxy::Capability::TunnelingCapability|QNetworkProxy::Capability::HostNameLookupCapability);
    if (!options->torUser.isEmpty())
        proxy.setUser(options->torUser);
    if (!options->torPass.isEmpty())
        proxy.setPassword(options->torPass);
    // /proxy
}

PeerMgr::~PeerMgr() { cleanup(); /* noop if already stopped */ DebugM(__func__);  }

QVariantMap PeerMgr::makeFeaturesDict(PeerClient *c) const
{
    const bool isBCH = coin == BTC::Coin::BCH;
    return Server::makeFeaturesDictForConnection(c, _genesisHash, *options, srvmgr->hasDSProofRPC(), isBCH,
                                                 storage->getConfiguredRpaStartHeight(), srvmgr->hasSubmitPackageRPC());
}

QString PeerMgr::publicHostNameForConnection(PeerClient *c) const
{
    return options->hostName.value_or(c->localAddress().toString());
}

void PeerMgr::startup()
{
    _genesisHash = storage->genesisHash();
    if (_genesisHash.length() != HashLen)
        throw InternalError("PeerMgr cannot be started until we have a valid genesis hash! FIXME!");

    const auto chain = storage->getChain(); // Note: assumption is that this is always non-empty if PeerMgr was started! (PeerMgr is never started until the db is synched so this is fine)
    const auto coinStr = storage->getCoin();
    // setup this->coin flag -- note that assumption is that storage was aleady setup properly
    if (chain.isEmpty() || (this->coin = BTC::coinFromName(coinStr)) == BTC::Coin::Unknown)
        throw InternalError("PeerMgr cannot be constructed without a valid \"Coin\" and/or \"Chain\" in the database!");
    const auto lcaseCoin = coinStr.trimmed().toLower();
    const auto pathPrefix = QString(":resources/%1/").arg(lcaseCoin);
    const QVector<BTC::Net> knownNets{{BTC::Net::TestNet, BTC::Net::TestNet4, BTC::Net::ScaleNet, BTC::Net::MainNet,
                                       BTC::Net::ChipNet}};
    if (const auto net = BTC::NetFromName(chain); !knownNets.contains(net))
        // can only do peering with testnet or mainnet after they have been defined (no regtest)
        throw InternalError(QString("PeerMgr cannot be started for the given chain \"%1\"").arg(chain));
    else if (net == BTC::Net::TestNet)
        parseServersDotJson(pathPrefix + "servers_testnet.json");
    else if (net == BTC::Net::TestNet4)
        parseServersDotJson(pathPrefix + "servers_testnet4.json"); // BCH & BTC only -- will implicitly throw if somehow the coin is LTC (should never happen)
    else if (net == BTC::Net::ScaleNet)
        parseServersDotJson(pathPrefix + "servers_scalenet.json"); // BCH only -- will implicitly throw if somehow the coin is BTC (should never happen)
    else if (net == BTC::Net::ChipNet)
        parseServersDotJson(pathPrefix + "servers_chipnet.json"); // BCH only -- will implicitly throw if somehow the coin is BTC (should never happen)
    else
        parseServersDotJson(pathPrefix + "servers.json");

    // next, scan all the interfaces configured to determine if we have ipv4 or ipv6 or both
    // this allows us to decide what kinds of addresses to connect to later
    for (const auto & iface : options->interfaces + options->sslInterfaces + options->statsInterfaces) {
        detectProtocol( iface.first );
        if (hasip4 && hasip6)
            break;
    }
    if (!hasip4 && !hasip6)
        Warning() << objectName() << ": Could not determine which protocols are available based on bind addresses.";

    start();
    // wait for thread to start before returning.
    if (auto s = chan.get<QString>(60000); s != "ok") // this will throw to caller if it has a timeout
        throw InternalError("Could not start PeerMgr");
}

void PeerMgr::detectProtocol(const QHostAddress &addr)
{
    if ((hasip4 && hasip6) || addr.isNull())
        return;
    switch (addr.protocol()) {
    case QAbstractSocket::IPv4Protocol:
        hasip4 = true;
        break;
    case QAbstractSocket::IPv6Protocol:
        hasip6 = true;
        break;
    case QAbstractSocket::AnyIPProtocol: {
        // not entirely sure about these heuristics .. or even if this branch can be taken normally.
        const auto astr = addr.toString();
        hasip4 = hasip4 || astr.split('.').size() == 4;
        hasip6 = hasip6 || astr.split(':').size() > 2;
    }
        break;
    default: break;
    }
}

void PeerMgr::parseServersDotJson(const QString &fnIn)
{
    seedPeers.clear();
    const auto backend = Options::isSimdJson() ? Json::ParserBackend::FastestAvailable : Json::ParserBackend::Default; // kind of a hack
    QVariantMap m = Json::parseFile(fnIn, Json::ParseOption::RequireObject, backend).toMap();
    const QString fn = Util::basename(fnIn); // use basename for error messages below, etc
    if (m.isEmpty()) throw InternalError(QString("PeerMgr: %1 file parsed to an empty dict! FIXME!").arg(fn));
    for (auto it = m.begin(); it != m.end(); ++it) {
        PeerInfo info;
        QVariantMap d = it.value().toMap();
        info.hostName = it.key().trimmed().toLower();
        // skip empties/malformed entries, or pruning entries -- for defensive programming.. ideally we include only good entries in servers.json
        if (info.hostName.isEmpty() || d.isEmpty() || (!d.value("pruning").isNull() && d.value("pruning").toString() != "-")) {
            Debug() << "Server \"" << info.hostName << "\" in " << fn << " has either no data or uses pruning, skipping";
            continue;
        }
        bool ok;
        unsigned val = d.value("s", 0).toUInt(&ok);
        if (ok && isValidPort(val))
            info.ssl = quint16(val);
        val = d.value("t", 0).toUInt(&ok);
        if (ok && isValidPort(val))
            info.tcp = quint16(val);
        info.protocolVersion = d.value("version", ServerMisc::MinProtocolVersion.toString()).toString();
        if (!info.isMinimallyValid()) {
            Debug() << "Bad server in " << fn << ": " << info.hostName;
            continue;
        } else if (info.protocolVersion < ServerMisc::MinProtocolVersion || info.protocolVersion > ServerMisc::MaxProtocolVersion) {
            Debug() << "Server in " << fn << " has incompatible protocol version (" << info.protocolVersion.toString() << "), skipping";
            continue;
        }
        seedPeers[info.hostName] = info;
    }
    if (seedPeers.isEmpty())
        throw InternalError(QString("PeerMgr: No valid peers parsed from %1").arg(fn));
    seedPeers.squeeze();
    Debug() << objectName() << ": using " << seedPeers.size() << " peers from " << fn;
}

void PeerMgr::on_started()
{
    ThreadObjectMixin::on_started();
    Debug() << objectName() << ": started ok";
    chan.put("ok");
}

void PeerMgr::cleanup()
{
    stop();
    if (auto num = stopAllTimers(); num)
        Debug() << objectName() << " stopped " << num << Util::Pluralize(" active timer", num);
    // Clean up all clients by deleting them immediately, unconditionally
    auto clientList = clients.values();
    clients.clear();
    for (PeerClient *c : clientList) {
        disconnect(c, &QObject::destroyed, this, nullptr); // must kill the 'destroyed' signal to avoid potential issues
        delete c; // insta-kill
    }
    if (auto num = clientList.size(); num)
        Debug() << objectName() << " deleted " << num << Util::Pluralize(" active client", num);
}

void PeerMgr::on_rpcAddPeer(const PeerInfoList &infos, const QHostAddress &source)
{
    if constexpr (debugPrint) DebugM(__func__, " source: ", source.toString());

    // detect protocols we may have missed on startup. No-op if source isNull or if we have both v4 and v6
    detectProtocol(source);

    for (const auto & pi : infos) {
        // TODO here also check the "good" peers & connections we actively have, and if in there, maybe bump server to
        // refresh its features, then exit loop early. Also we need a way to keep track of "recently verified bad" as a
        // DoS defense here? Hmm...
        // NB: assumption here is pi.hostName is already trimmed and toLower()
        if (queued.contains(pi.hostName) || clients.contains(pi.hostName) || (good.contains(pi.hostName) && !pi.isGoodServerNeedingRefresh())) {
            // already added... no need to do DNS lookup or any further processing
            if constexpr (debugPrint) DebugM("add_peer: ", pi.hostName, " already queued or in process");
            continue;
        } else if (source.isNull() && (failed.contains(pi.hostName) || bad.contains(pi.hostName))) {
            // source was not the server itself, so we ignore this request since it may have come from a
            // server.peers.subscribe and may be stale.  We will retry failed servers ourselves eventually...

            // TODO FIXME: we are optimistically going to update the ports on failed/bad with the new ports that came in
            // as a hack to support servers changing ports and our detecting that change and eventually being able to
            // connect to their new ports.  This needs tuning and more thought and consideration, however.
            for (auto map : {&failed, &bad}) { ///< go thru the failed and bad maps and update the ports if we find this hostName in them...
                if (auto it = map->find(pi.hostName); it != map->end()) {
                    it.value().tcp = pi.tcp;
                    it.value().ssl = pi.ssl;
                }
            }
            if constexpr (debugPrint) DebugM("add_peer: ", pi.hostName, " was already deemed bad/failed, skipping (for now)");
            continue;
        }
        if (pi.isTor()) {
            if (source.isNull()) {
                // .onion must go through proxy to resolve.. so skip the resolve test. But we only allow adding .onion
                // from *outside* the public RPC interface (that's why source has to be isNull()).
                addPeerVerifiedSource(pi, QHostAddress());
            } else {
                DebugM("add_peer: Refusing to add a .onion peer from the public rpc interface, ignoring ", pi.hostName);
            }
            return;
        }
        // For each peer in the list, do a DNS lookup and verify that the source address matches at least one
        // of the resolved addresses.  If that is the case, we can proceed with the peer add (addPeerVerifiedSource).
        // Otherwise, we reject add_peer requests from random sources.
        auto lookupId = std::make_shared<std::optional<int>>();
        *lookupId = QHostInfo::lookupHost(pi.hostName, this, [this, pi, source, lookupId](const QHostInfo &result){
            lookupId->reset(); // signify we no longer need a cancellation .. calls reset on the std::optional (not on the shared_ptr)
            if (result.error() != QHostInfo::NoError) {
                DebugM("add_peer: Host lookup error for ", pi.hostName, ": ", result.errorString());
                PeerInfo & p2 = failed[pi.hostName] = pi;
                p2.failureReason = result.errorString();
                p2.setFailureTsIfNotSet();
                return;
            }
            int skipped = 0;
            std::list<QHostAddress> addressesPri;
            static const QSet<QAbstractSocket::NetworkLayerProtocol>
                    acceptableProtos = { QAbstractSocket::IPv4Protocol, QAbstractSocket::IPv6Protocol };
            // loop through the addresses and enqueue them in `addressesPri` in a prioritized order based on some
            // heuristics about which protocols we prefer.
            for (const auto & addr : result.addresses()) {
                if (auto proto = addr.protocol(); !acceptableProtos.contains(proto)) {
                    ++skipped; // some unknown protocol. tally it as skipped so we can indicate this in the error message at the end.
                } else if (proto == QAbstractSocket::IPv4Protocol && !hasip4) {
                    addressesPri.push_back(addr); // we may not have ipv4, so put this address at the back of the line to try last
                } else if (proto == QAbstractSocket::IPv6Protocol && !hasip6) {
                    addressesPri.push_back(addr); // we may not have ipv6, so put this address at the back of the line to try last
                } else {
                    addressesPri.push_front(addr); // we have this protocol, so put this address at the front of the line to try first
                }
            }
            // now, loop through the queue we created and prefer the addresses at the front over ones at the back.
            for (const auto & addr : addressesPri) {
                if (source.isNull() || addr == source) {
                    if constexpr (debugPrint)
                        DebugM("add_peer: ", pi.hostName, " address (", addr.toString(), ") ok for source (",
                               source.toString(), "), processing further ...");
                    addPeerVerifiedSource(pi, addr);
                    return;
                }
            }
            DebugM("add_peer: Rejected because source (", source.toString(), ") does not match resolved address (",
                   result.addresses().isEmpty() ? QString() : result.addresses().front().toString(), ")",
                   skipped ? " (some of the resolved addresses were skipped due us lacking the capability to connect"
                             " to their advertised IP protocol)" : "");
        });
        Util::AsyncOnObject(this, [this, lookupId, pi] {
            if (lookupId->has_value()) {
                QHostInfo::abortHostLookup(**lookupId);
                PeerInfo & p2 = failed[pi.hostName] = pi;
                p2.failureReason = "DNS timed out";
                p2.setFailureTsIfNotSet();
                DebugM("add_peer: hostname lookup for ", pi.hostName, " timed out after ",
                       QString::number(kDNSTimeout, 'f', 1), " secs");
            }
        }, static_cast<int>(kDNSTimeout * 1e3));
    }
}

void PeerMgr::addPeerVerifiedSource(const PeerInfo &piIn, const QHostAddress & addr)
{
    if constexpr (debugPrint) DebugM(__func__, " peer ", piIn.hostName, " ipaddr: ", addr.toString());

    PeerInfo pi(piIn);
    pi.addr = addr;
    pi.failureReason = ""; // Note: here we just clear the message but leave the failureTs (if any) unchanged
    queued[pi.hostName] = pi;
    failed.remove(pi.hostName);
    bad.remove(pi.hostName);
    DebugM("add_peer: ", pi.hostName, " added to queue");
    processSoon();
}

void PeerMgr::on_allServersStarted()
{
    if (gotAllServersStartedSignal) // paranoia
        return;
    DebugM(__func__);

    gotAllServersStartedSignal = true;

    if (options->peerAnnounceSelf && options->torHostName.has_value() && (options->torSsl.has_value() || options->torTcp.has_value())) {
        if (const auto torHostName = *options->torHostName; !torHostName.isEmpty()) {
            // Add/update our Tor identity to seed peers (even if it's already there) -- this is so we can end up in our
            // *own* server.peers.subscribe() list -- so that the Tor route can get picked up by our peers; this is
            // because we cannot directly add our Tor route via add_peer on our peers (source address verification
            // fails)... So this is another way to end up in our peers' peer lists... by connecting to self later and
            // verifying self. Then when a peer asks us for server.peers.subscribe, we will be in our OWN peer list,
            // and our peers can opt to pick the .onion up from there. (Such circular logic!!)
            PeerInfo torpi;
            torpi.hostName = torHostName;
            torpi.ssl = options->torSsl.value_or(0);
            torpi.tcp = options->torTcp.value_or(0);
            if (torpi.isMinimallyValid()) {
                seedPeers.insert(torHostName, torpi);
                DebugM("Added our tor hostname to the seed peer list: ", torHostName);
            }
        }
    }

    // start out with the seedPeers
    queued = seedPeers;

    processSoon();

    // next, set up the "failed peer retry" timer which runs every kFailureRetryTime seconds (10 mins)
    callOnTimerSoon(int(kFailureRetryTime*1e3), "failedPeerRetry", [this]{
        retryFailedPeers();
        return true;
    });
    // next, set up the "bad peer retry" timer which runs every kBadPeerRetryTime seconds (60 mins)
    callOnTimerSoon(int(kBadPeerRetryTime*1e3), "badPeerRetry", [this]{
        retryFailedPeers(true);
        return true;
    });
    // lastly, set up the "good peer refresh" timer which runs every kGoodPeerRefreshInterval minute, or at half the kGoodPeerRefreshInterval, whichever is smaller
    callOnTimerSoon(std::min<int>(60'000, kGoodPeerRefreshInterval*0.5*1e3), "goodPeerRefresh", [this]{
        refreshGoodPeers();
        return true;
    });
}

namespace {
    QString ageHoursString(const std::optional<double> &age) {
        QString ret;
        if (age.has_value())
            ret = QString::number(*age / (60.*60.), 'f', 2) + " hours";
        return ret;
    }
}

void PeerMgr::retryFailedPeers(bool useBadMap)
{
    size_t ctr = 0;
    auto & failed = (useBadMap ? this->bad : this->failed);
    for (const auto & pi : failed) {
        if (!queued.contains(pi.hostName) && !clients.contains(pi.hostName) && !good.contains(pi.hostName)) {
            if (auto fa = pi.failureAge(); fa.has_value() && *fa > kExpireFailedPeersTime && !seedPeers.contains(pi.hostName)) {
                // We purge peers that have been bad or failed for >24 hours. However we never purge seedPeers since
                // they are our lifeline to the outside world.  It's possible ALL peers can be failed/bad for a long
                // time if we lose internet connectivity for an extended period due to an outage.  In that scenario,
                // when we come back, we don't want the server to have lost its ability to announce itself to the world.
                // So we always keep the seedPeers even if they remain 'failed' for years. The assumption here is that
                // the seed peers list is reasonably good and worth keeping around.  Removing failed peers is an
                // optimization to not waste memory on defunct peers and is not a requirement for correctness.
                // Keeping the seedPeers around indefinitely even if 'failed' does very little harm since the seedPeer
                // list is bounded and small, and it does good (in the case of an extended connectivity outage).
                Log() << "Purging failed peer " << pi.hostName << " because it has been unavailable for " <<  ageHoursString(pi.failureAge());
                continue;
            }
            auto it = queued.insert(pi.hostName, pi);
            it.value().addr.clear(); // make sure addr is null so we do lookup again in case peer IP address has changed
            ++ctr;
        }
    }
    failed.clear();
    failed.squeeze();
    if (ctr) {
        DebugM("Retrying ", ctr, " ", (useBadMap ? "'bad'" : "'failed'"), Util::Pluralize(" peer", ctr), " ...");
        processSoon();
    }
}

void PeerMgr::refreshGoodPeers()
{
    if constexpr (debugPrint) Debug() << __func__ << " wakeup ...";
    size_t ctr = 0;
    for (const auto & pi : std::as_const(good)) {
        if (!queued.contains(pi.hostName) && !clients.contains(pi.hostName)) {
            if (pi.isGoodServerNeedingRefresh()) {
                // refresh this good peer after 10 mins to pick up new information from it, ensure it's good, etc
                DebugM("Enqueuing good peer ", pi.hostName, " (last good age: ", QString::number(pi.lastGoodAge().value_or(-1.), 'f', 1),
                       " seconds) for refresh");
                auto it = queued.insert(pi.hostName, pi);
                it.value().addr.clear(); // make sure addr is null so we do lookup again in case peer IP address has changed
                ++ctr;
            }
        }
    }
    if (ctr) {
        DebugM("Refreshing ", ctr, " ", "'good'" , Util::Pluralize(" peer", ctr), " ...");
        processSoon();
    }
}

void PeerMgr::processSoon()
{
    callOnTimerSoonNoRepeat(int(kProcessSoonInterval * 1e3), __func__, [this]{process();});
}

void PeerMgr::updateSoon()
{
    callOnTimerSoonNoRepeat(int(kProcessSoonInterval * 1e3), __func__, [this]{
        // the below happens in a rate-limited fashion after a small delay (currently 1 sec)
        const PeerInfoList goodPeers = good.values();
        if constexpr (debugPrint) {
            DebugM("emitting updated() signal for peers: ", good.keys().join(", "));
        }
        emit updated(goodPeers);
    });
}

void PeerMgr::process()
{
    if (queued.isEmpty())
        return;
    const PeerInfo pi = queued.take(queued.begin().key());
    if (const bool isTor = pi.isTor(); pi.addr.isNull() && !isTor) {
        if constexpr (debugPrint)
            DebugM("PeerInfo.addr was null for ", pi.hostName, ", calling on_rpcAddPeer to resolve address");
        on_rpcAddPeer(PeerInfoList({pi}), pi.addr);
    } else if (!isTor && srvmgr->isIPBanned(pi.addr, false)) {
        DebugM("peer IP address ", pi.addr.toString(), " is banned, ignoring peer");
    } else if (srvmgr->isPeerHostNameBanned(pi.hostName)) {
        DebugM("peer hostname ", pi.hostName, " is banned, ignoring peer");
    } else if (!isTor && options->peeringEnforceUniqueIPs && peerIPAddrs.contains(pi.addr)) {
        if constexpr (debugPrint)
            DebugM(pi.hostName, " (", pi.addr.toString(), ") already in peer set, skipping ...");
    } else {
        auto client = newClient(pi);
        client->connectToPeer();
    }
    if (!queued.isEmpty())
        AGAIN();
    else
        queued.squeeze();
}

PeerClient * PeerMgr::newClient(const PeerInfo &pi)
{
    PeerClient *client = clients.take(pi.hostName);
    if (client) {
        Warning() << "Already had a client for " << pi.hostName << ", deleting ...";
        client->deleteLater();
    }
    client = new PeerClient(options->peerAnnounceSelf, pi, newId(), this, 256*1024);
    connect(client, &PeerClient::connectFailed, this, &PeerMgr::on_connectFailed);
    connect(client, &PeerClient::good, this, &PeerMgr::on_good);
    connect(client, &PeerClient::bad, this, &PeerMgr::on_bad);
    connect(client, &PeerClient::gotPeersSubscribeReply, this, &PeerMgr::on_rpcAddPeer);
    connect(client, &QObject::destroyed, this, [this, hostName = pi.hostName, addr = pi.addr](QObject *obj) {
        if (const auto it = std::as_const(clients).find(hostName); it != clients.end() && it.value() == obj) {
            clients.erase(it);
            peerIPAddrs.remove(addr); // mark it as gone from the set
            if constexpr (debugPrint) DebugM("Removed peer from clients map: ", hostName);
        } else {
            if constexpr (debugPrint) DebugM("Peer not found in clients map: ", hostName);
        }
    });
    connect(client, &PeerClient::lostConnection, this, [](AbstractConnection *c){
        assert(c != nullptr);
        PeerClient *client = dynamic_cast<PeerClient *>(c);
        DebugM((client ? client->info.hostName : QString{"???"}), ": Socket disconnect");
        if (client && !client->verified) {
            Log() << "Failed to verify peer " << client->info.hostName << " (" << client->info.addr.toString() << ")";
        }
        c->deleteLater();
    });
    connect(client, &PeerClient::connectionEstablished, this, [this](PeerClient *client){
        if constexpr (debugPrint)
            DebugM("Connection established for ", client->info.hostName, " ...");
        detectProtocol(client->peerAddress()); // this is so that we learn about whether we really can do IPv6 as the app runs.
    });

    peerIPAddrs.insert(pi.addr);
    clients[pi.hostName] = client;
    return client;
}

void PeerMgr::on_good(PeerClient *c)
{
    const auto &hostName = c->info.hostName;
    if (hostName.isEmpty()) [[unlikely]] {
        Warning() << "Client " << c->id << " has an empty hostname! This should never happen! FIXME!";
        return;
    }
    c->info.setGoodTs();
    good[hostName] = c->info;
    bad.remove(hostName);
    failed.remove(hostName);
    updateSoon();
    // NB: we don't disconnect right away since maybe client needs to send server.add_peer
}

void PeerMgr::on_bad(PeerClient *c)
{
    const auto &hostName = c->info.hostName;
    if (hostName.isEmpty())
        return;
    c->info.setFailureTsIfNotSet();
    c->info.genesisHash.clear();
    if (!c->wasKicked) {
        good.remove(hostName);
        bad[hostName] = c->info;
    }
    c->deleteLater(); // drop connection
    updateSoon();
}

void PeerMgr::on_connectFailed(PeerClient *c)
{
    const auto &hostName = c->info.hostName;
    if (hostName.isEmpty())
        return;
    if (c->info.failureReason.startsWith("!!")) {
        c->info.failureReason = c->info.failureReason.mid(2); // pick up reason override (timed-out connections override the reason)
    } else if (const auto r = c->socket ? c->socket->errorString() : QString();
            // pick up the new failure reason, but only if it's not empty.. however if we had no failureReason before,
            // then we synthesize one here so /stats looks informative
            !r.isEmpty() || c->info.failureReason.isEmpty()) {
        c->info.failureReason = r;
        if (c->info.failureReason.isEmpty())
            c->info.failureReason = "Connection failed";
    }
    c->info.setFailureTsIfNotSet();
    c->info.genesisHash.clear();
    if (!c->wasKicked) {
        good.remove(hostName);
        if (QString lcReason; c->info.tcp && c->info.ssl && !c->info.preferSsl
            && ( (lcReason = c->info.failureReason.trimmed().toLower()) == "connection refused"
                || lcReason == "connection failed: timed out")) {
            // We just failed on the TCP port, try the SSL port instead in case server is misconfigured and reports
            // non-working TCP ports but has a working SSL port. We tolerate this misoconfiguration since most wallets
            // are SSL-only anyway, and we want to grab up as many "good" servers as we can for wallets.
            c->info.preferSsl = true;
            Log() << "Connection failed for peer " << hostName << " (" << c->info.addr.toString() << ")"
                  << " to TCP port " << c->info.tcp << ", enqueing retry to SSL port " << c->info.ssl << " instead";
            queued[hostName] = c->info; // re-enqueue, this time we will try the SSL port, note: no DNS lookup will occur the second time through
            processSoon();
        } else {
            // Normal failure processing, mark it as failed
            c->info.preferSsl = false; // clear flag if set, so we start fresh with the TCP port next time we retry this server
            failed[hostName] = c->info;
        }
    }
    c->deleteLater(); // clean up
    updateSoon();
}

void PeerMgr::on_kickByAddress(const QHostAddress &addr)
{
    if (addr.isNull())
        return;
    QSet<QString> hostnames;
    // first, loop through all the inactive maps and search for this addr
    for (PeerInfoMap *m : {&seedPeers, &queued, &bad, &failed, &good} ) {
        for (auto it = m->begin(); it != m->end() ; /**/) {
            if (it->addr == addr) {
                DebugM(__func__, " removing peer ", it.key(), " ", addr.toString());
                hostnames.insert(it->hostName);
                it = m->erase(it);
            } else
                ++it;
        }
    }
    // lastly, loop through the active/connected clients and tell them all to delete themselves
    for (PeerClient *c : std::as_const(clients)) {
        if (c->peerAddress() == addr || c->info.addr == addr) {
            DebugM(__func__, " kicked connected peer ", c->info.hostName, " ", addr.toString());
            hostnames.insert(c->info.hostName);
            c->wasKicked = true;
            c->deleteLater(); // this will call us back to remove it from the hashmap, etc
        }
    }
    if (const auto uniqs = hostnames.size(); uniqs)
        Log() << uniqs << Util::Pluralize(" entry", uniqs) << " matching IP " << addr.toString() << " removed from the PeerMgr";
}

void PeerMgr::on_kickBySuffix(const QString &suffix)
{
    if (suffix.isEmpty())
        return;
    // NB: the suffix comes in pre-normalized from SrvMgr.
    QSet<QString> hostnames;
    // first, loop through all the inactive maps and search for this addr
    for (PeerInfoMap *m : {&seedPeers, &queued, &bad, &failed, &good} ) {
        for (auto it = m->begin(); it != m->end() ; /**/) {
            if (it->hostName.endsWith(suffix)) {
                DebugM(__func__, " removing peer ", it.key(), " ", it->hostName);
                hostnames.insert(it->hostName);
                it = m->erase(it);
            } else
                ++it;
        }
    }
    // lastly, loop through the active/connected clients and tell them all to delete themselves
    for (PeerClient *c : std::as_const(clients)) {
        if (c->info.hostName.endsWith(suffix)) {
            DebugM(__func__, " kicked connected peer ", c->info.hostName, " ", c->info.addr.toString());
            hostnames.insert(c->info.hostName);
            c->wasKicked = true;
            c->deleteLater(); // this will call us back to remove it from the hashmap, etc
        }
    }
    if (const auto uniqs = hostnames.size(); uniqs)
        Log() << "Removed " << uniqs << Util::Pluralize(" entry", uniqs) << " matching *" << suffix;
}

auto PeerMgr::stats() const -> Stats
{
    QVariantMap ret;
    QVariantMap m0;
    for (const auto & client : clients)
        m0[client->info.hostName] = client->stats();
    ret["verifying"] = m0;

    // NB: FulcrumAdmin script expects the good peers to live under the "peers" key
    m0.clear();
    for (const auto & pi : good) {
        auto m1 = pi.toStatsMap();
        // FulcrumAdmin script expects this to exist here for verified peers, if this is false it will print "Verifying"
        // for the peer, otherwise it will print "Good" if true.
        m1["verified"] = not clients.contains(pi.hostName);
        // FulcrumAdmin also expects this key here to indicate how long it's been "good"
        m1["connectedTime"] = pi.firstGoodAge().value_or(0.);

        m0[pi.hostName] = std::move(m1);
    }
    ret["peers"] = m0;

    m0.clear();
    for (const auto & info : bad) {
        m0[info.hostName] = QVariantList{{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), ageHoursString(info.failureAge()), info.failureReason }};
    }
    ret["bad"] = m0;

    m0.clear();
    for (const auto & info : queued) {
        m0[info.hostName] = QVariantList{{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), ageHoursString(info.failureAge()), info.failureReason }};
    }
    ret["queued"] = m0;

    m0.clear();
    for (const auto & info : failed) {
        m0[info.hostName] = QVariantList{{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), ageHoursString(info.failureAge()), info.failureReason }};
    }
    ret["failed"] = m0;

    ret["peering"] = options->peerDiscovery;
    ret["announce"] = options->peerAnnounceSelf;
    ret["activeTimers"] = activeTimerMapForStats();

    return ret;
}

QVariantMap PeerInfo::toStatsMap() const
{
    QVariantMap m;
    m["addr"] = addr.toString();
    m["server_version"] = subversion;
    m["protocolVersion"] = protocolVersion.toString();
    m["protocol_min"] = protocolMin.toString();
    m["protocol_max"] = protocolMax.toString();
    m["hash_function"] = hashFunction;
    m["genesis_hash"] = genesisHash.toHex();
    m["tcp_port"] = tcp;
    m["ssl_port"] = ssl;
    m["isTor?"] = isTor();
    if (const auto s = ageHoursString(firstGoodAge()); !s.isEmpty())
        m["firstGoodAge"] = s;
    if (const auto s = ageHoursString(lastGoodAge()); !s.isEmpty())
        m["lastGoodAge"] = s;
    if (const auto s = ageHoursString(failureAge()); !s.isEmpty())
        m["failureAge"] = s;
    return m;
}

auto PeerClient::stats() const -> Stats
{
    QVariantMap m = RPC::ElectrumConnection::stats().toMap();
    Compat::MapUnite(m, info.toStatsMap());
    m["verified"] = verified;
    return m;
}

auto PeerMgr::headerToVerifyWithPeer() const -> std::optional<HeightHeaderPair>
{
    std::optional<HeightHeaderPair> ret;
    const auto optCurHeight = storage->latestHeight();
    if (optCurHeight.has_value()) {
        const auto curHeight = *optCurHeight;
        constexpr unsigned cutoff = BTC::DefaultBCHFinalizationDepth + 1;
        if (cutoff < curHeight) {
            const auto height = curHeight - cutoff;
            QString err = "Bad size";
            auto optHdr = storage->headerForHeight(height, &err);
            if ( optHdr.value_or(Storage::Header{}).length() == BTC::GetBlockHeaderSize() ) {
                ret.emplace(height, optHdr.value());
            } else
                Warning() << "PeerMgr: Failed to retrieve header " << height << ": " << err;
        } else {
            Warning() << "PeerMgr: Block height is not greater than " << cutoff << ", cannot verify peer header";
        }
    }
    return ret;
}

PeerClient::PeerClient(bool announce, const PeerInfo &pi, IdMixin::Id id_, PeerMgr *mgr, int maxBuffer)
    : RPC::ElectrumConnection(nullptr, id_, mgr, maxBuffer), announceSelf(announce), info(pi), mgr(mgr)
{
    setObjectName(QStringLiteral("Peer %1").arg(pi.hostName));

   constexpr int kStaleThresholdMS = 30'000; ///< if a peer hasn't responded at all to a request in 30 seconds, consider it "stale"
   this->pingtime_ms = kStaleThresholdMS / 2; // member of AbstractConnection base class
   this->stale_threshold = kStaleThresholdMS; // member of AbstractConnection base class
   const bool preferSsl = pi.preferSsl && pi.ssl;
    if (pi.tcp && !preferSsl) { // if tcp exists and !preferSsl, prefer tcp since it's faster
        socket = new QTcpSocket(this);
    } else if (pi.ssl) {
        QSslSocket *ssl = new QSslSocket(this);
        socket = ssl;
        // modify the configuration to be extremely permissive, because this is what ElectrumX does and half the
        // servers online have self-signed or otherwise funky certs.
        // TODO: Get all the server admins to use real certs?  Make the level of strictness for SSL configurable?
        auto conf = ssl->sslConfiguration();
        conf.setPeerVerifyMode(QSslSocket::PeerVerifyMode::VerifyNone);
        conf.setProtocol(QSsl::SslProtocol::AnyProtocol);
        ssl->setSslConfiguration(conf);
    }
    if (socket) {
        // on any errors we just assume the connection is down, tell PeerMgr to put it in the connect failed list
        connect(socket, Compat::SocketErrorSignalFunctionPtr(), this, [this](QAbstractSocket::SocketError){ emit connectFailed(this); });
        // Call base class which connects more signals
        socketConnectSignals();
    } else {
        Warning() << "!ssl && !tcp for " << pi.hostName << "! FIXME!";
    }

    connect(this, &RPC::ConnectionBase::gotMessage, this, &PeerClient::handleReply);
    auto OnErr = [this]([[maybe_unused]]  auto arg1, [[maybe_unused]] auto arg2){
        // this should never happen with a good peer -- indicates peer is bad
        info.failureReason = "Got an unexpected JSON-RPC error response or a JSON-RPC parse error";
        emit bad(this);
    };
    connect(this, &RPC::ConnectionBase::gotErrorMessage, this, OnErr);
    connect(this, &RPC::ConnectionBase::peerError, this, OnErr);

    // if the connection either fails or succeeds, unconditionally kill the timeout timer
    connect(this, &PeerClient::connectFailed, this, [this]{ stopTimer(kConnectTimerName); });
    connect(this, &PeerClient::connectionEstablished, this, [this]{ stopTimer(kConnectTimerName); });
}

PeerClient::~PeerClient() {
    if constexpr (debugPrint) DebugM(__func__, ": ", info.hostName);
}

void PeerClient::connectToPeer()
{
    if (!socket) return;
    QSslSocket *ssl = dynamic_cast<QSslSocket *>(socket);
    QString msgXtra = "", connectAddr = info.addr.toString(); // default is to use the address as the "host" for connecting

    info.failureReason.clear(); // clear reason now, start with no reason

    if (info.isTor()) {
        msgXtra = " via Tor proxy";
        socket->setProxy(mgr->getProxy());
        connectAddr = info.hostName;  // however, we resolve-on-connect for .onion
    }
    if (ssl) {
        DebugM(info.hostName, ": connecting to SSL ", connectAddr, ":", info.ssl, msgXtra);
        connect(ssl, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), ssl, [ssl, hostName = info.hostName](auto errs) {
            for (const auto & err : errs) {
                DebugM("Ignoring SSL error for ", hostName, ": ", err.errorString());
            }
            ssl->ignoreSslErrors();
        });
        ssl->connectToHostEncrypted(connectAddr, info.ssl, info.hostName);
    } else {
        DebugM(info.hostName, ": connecting to TCP ", connectAddr, ":", info.tcp, msgXtra);
        socket->connectToHost(connectAddr, info.tcp);
    }

    // 30 second timer -- if we fail to connect in this time, emit this signal.
    // This was added after Fulcrum 1.3.2 when it was observed that in particular with bad tor_proxy settings, it was
    // possible for the PeerClient to remain in limbo forever on socket connect, never connecting but never failing
    // either.
    callOnTimerSoonNoRepeat(kConnectTimeoutMS, kConnectTimerName, [this]{
        if (socket) socket->abort(); // immediately kill connection attempt
        // reasons prefixed with !! override any socket errors we may get from abort()
        info.failureReason = "!!Connection failed: timed out";
        emit connectFailed(this);
    }, true);
}

void PeerClient::do_disconnect(bool graceful)
{
    RPC::ElectrumConnection::do_disconnect(graceful);
    if (graceful)
        // 2 second grace period to gracefully disconnect otherwise force-delete this insance
        callOnTimerSoonNoRepeat(kGracefulDisconnectTime, kGracefulDisconnectTimerName, [this]{ deleteLater(); });
    else
        // non-graceful disconnect -- kill us asap
        deleteLater();
}

void PeerClient::do_ping()
{
    // Note, we don't actually do any pings. We just use the built-in "ping" mechanism to detect a stale socket
    // (peer hasn't responded to queries in a while), and if so, we maybe mark the peer as bad and disconnect from it.
    if (isStale()) {
        if (!verified) {
            Log() << info.hostName << ": Connection is stale, marking peer as bad";
            info.failureReason = "!!Timed out waiting for a reply";
            emit bad(this);
        } else {
            DebugM(info.hostName, ": Connection is stale, but peer is already verified, disconnecting");
            do_disconnect(true);
        }
    }
}

void PeerClient::on_connected()
{
    RPC::ElectrumConnection::on_connected();
    emit connectionEstablished(this);
    // query peer immediately upon connection
    DebugM("Querying peer ", info.hostName);
    // this kicks off the chain of handleReply below which is really a simple state machine
    emit sendRequest(newId(), "server.version",
                     QVariantList(
                          // Arg 1
                         {ServerMisc::AppSubVersion,
                          // Arg 2: A tuple of [min, max]; Electrum Cash protocol expects this form for servers doing peering
                          QVariantList({ServerMisc::MinProtocolVersion.toString(), ServerMisc::MaxProtocolVersion.toString()})}
                     ));
}

void PeerClient::handleReply(IdMixin::Id, const RPC::BatchId, const RPC::Message & reply)
{
    auto Bad = [this](const QString & reason = QString()) {
        QString res = reason;
        if (res.isNull()) res = "Got an unexpected or malformed response from peer";
        Warning() << info.hostName <<": " << res;
        info.failureReason = res;
        emit bad(this);
    };
    if (!reply.isResponse()) {
        Bad();
        return;
    }
    if (reply.method == "server.version") {
        QVariantList l = reply.result().toList();
        if (l.size() != 2) {
            Bad("Bad response to server.version");
            return;
        }
        info.subversion = l.front().toString();
        Version pver = l.back().toString();
        if (!pver.isValid() || pver > ServerMisc::MaxProtocolVersion || pver < ServerMisc::MinProtocolVersion) {
            Bad(QString("Protocol version '%1' is incompatible with us").arg(pver.toString()));
            return;
        }
        info.protocolVersion = pver; // save
        emit sendRequest(newId(), "server.features");
    } else if (reply.method == "server.features") {
        // handle
        if constexpr (debugPrint) {
            QString dbgstr;
            try { dbgstr = Json::toUtf8(reply.result(), false); } catch (...) {}
            DebugM(info.hostName, ": features responded: ", dbgstr);
        }
        PeerInfoList pl;
        try {
            pl = PeerInfo::fromFeaturesMap(reply.result().toMap());
            const auto remoteAddr = peerAddress();
            for (auto & pi : pl)  {
                if (!pi.isTor())
                    // fill-in address right now since we know it, just to be tidy
                    pi.addr = remoteAddr;
                else
                    pi.addr.clear();
            }
        } catch (const BadFeaturesMap &e) {
            DebugM("Peer ", info.hostName, " gave us a bad features mep: ", e.what());
            Bad(QString("Bad features map: ") + e.what());
            return;
        }
        bool found = false;
        const bool weAreSsl = isSsl();
        const quint16 remotePort = peerPort();
        for (const auto & pi : std::as_const(pl)) {
            // find a hostname match and also port match for what we are connected to
            if (pi.hostName == info.hostName
                    // see if ports match what we are connected to
                    && ( weAreSsl ? pi.ssl == remotePort : pi.tcp == remotePort ))
            {
                // see if genesis hash matches
                if (pi.genesisHash != mgr->genesisHash()) {
                    Bad("Genesis hash mistmach");
                    return;
                } else if (pi.hashFunction != info.hashFunction) {
                    Bad("Hash function mismatch");
                    return;
                }
                found = true;
                updateInfoFromRemoteFeaturesMap(pi);
                info.genesisHash = mgr->genesisHash(); // tweak to point to same underlying bytes
                break;
            }
        }
        if (!found) {
            Bad("Cannot find an entry in 'features' that matches the same hostname AND that is also advertising the port we are connected to");
            return;
        }
        headerToVerify = mgr->headerToVerifyWithPeer();
        if (headerToVerify.has_value()) [[likely]] {
            // this is the likely branch -- verify that this peer is not on a different chain such as BSV, etc
            if constexpr (debugPrint) DebugM(info.hostName, " requesting header for height ", headerToVerify->first);
            emit sendRequest(newId(), "blockchain.block.header", QVariantList{headerToVerify->first, 0});
        } else {
            // this should never happen -- but if it does, get its peers.subscribe list and just keep going.
            // next time around we should have a header ready if we reach this very strange corner case where
            // we have no headers.  (This branch is entirely in the interests of defensive programming and should never really be taken).
            Warning() << info.hostName << ": our db returned no header to verify against peer; proceeding anyway with peer.  "
                      << "If this keeps happening, please contact the developers.";
            emit sendRequest(newId(), "server.peers.subscribe");
        }
    } else if (reply.method == "blockchain.block.header") {
        if constexpr (debugPrint) DebugM(info.hostName, " ", reply.method, " response");
        if (!headerToVerify.has_value()) {
            Bad("Unexpected header response");
            return;
        }
        const auto  hdr = Util::ParseHexFast(reply.result().toString().trimmed().left(BTC::GetBlockHeaderSize()*2).toLower().toUtf8());
        if (hdr != headerToVerify.value().second) {
            Bad(QString("Peer appears to be on a different chain (header verification failed for height %1)").arg(headerToVerify.value().first));
            return;
        }
        headerToVerify.reset(); // clear the optional now to release the header's memory
        // go on to next phase, get its peers.subscribe list
        emit sendRequest(newId(), "server.peers.subscribe");
    } else if (reply.method == "server.peers.subscribe") {
        // handle
        if constexpr (debugPrint) {
            QString dbgstr;
            try { dbgstr = Json::toUtf8(reply.result(), true); } catch (...) {}
            DebugM(info.hostName, ": subscribe responded ... ", dbgstr);
        }
        PeerInfoList candidates;
        try {
            candidates = PeerInfo::fromPeersSubscribeList(reply.result().toList());
        } catch (const BadPeerList & e) {
            Bad(QString("Failed to parse add_peer list: ") + e.what());
            return;
        }
        // tell peermgr about some new candidates (note peermgr filters out already-added or candidates that may be dupes, etc).
        emit gotPeersSubscribeReply(candidates, QHostAddress());
        bool waitForAddPeerReply = false;
        if (announceSelf) {
            bool foundMe = false;
            const QString phn = mgr->publicHostNameForConnection(this);
            for (const auto & pi : std::as_const(candidates)) {
                if (!foundMe && pi.hostName == phn) {
                    foundMe = true;
                    break;
                }
            }
            if (!foundMe) {
                waitForAddPeerReply = true;
                emit sendRequest(newId(), "server.add_peer", QVariantList{mgr->makeFeaturesDict(this)});
            }
        }
        if (!verified) {
            verified = true;
            emit good(this); // updates peermgr good map, sets the goodTs, etc
            Log() << "Verified peer " << info.hostName << " (" << info.addr.toString() << ")";
            // Handle disconnecting. Note that older Fulcrum versions never disconnect explicitly. This was added
            // at the behest of the ElectrumX devs to not eat up connection slots idling.
            if (waitForAddPeerReply) {
                if constexpr (debugPrint) DebugM(info.hostName, ": will wait ", kVerifiedPeerWaitForAddPeerReplyTime, " msec for server.add_peer reply ...");
                callOnTimerSoonNoRepeat(kVerifiedPeerWaitForAddPeerReplyTime, kVerifiedPeerWaitForAddPeerReplyTimerName, [this]{
                    do_disconnect(/* graceful = */ false);
                });
            } else {
                if constexpr (debugPrint) DebugM(info.hostName, ": will disconnect ASAP");
                do_disconnect(/* graceful = */ true);
            }
        }
    } else if (reply.method == "server.add_peer") {
        // handle
        if constexpr (debugPrint) DebugM(info.hostName, ": add_peer... result = ", reply.result().toBool());
        if (!verified) [[unlikely]]
            // This should never happen; programming error if it does
            Warning() << info.hostName << ": Got server.add_peer reply but PeerClient instance is not 'verified'! FIXME!";
        stopTimer(kVerifiedPeerWaitForAddPeerReplyTimerName);
        do_disconnect(/* graceful = */ true);
    } else
        Bad();
}

PeerInfoList PeerInfo::fromPeersSubscribeList(const QVariantList &l)
{
    PeerInfoList ret;
    for (const auto & item : l) {
        QVariantList l2 = item.toList();
        if (l2.length() < 3)
            throw BadPeerList("short item count");
        PeerInfo pi;
        pi.hostName = l2.at(1).toString().trimmed().left(kHostNameMax).toLower();
        if (pi.hostName.isEmpty()) {
            DebugM("skipping empty hostname for ", pi.addr.toString());
            continue;
        }
        if (pi.isTor()) {
            // allow bad address if tor.. don't even parse address in that case
        } else {
            // otherwise require good address
            pi.addr.setAddress(l2.at(0).toString().trimmed().left(kStringMax));
            if (pi.addr.isNull()) {
                DebugM("skipping null address");
                continue;
            }
        }
        const QVariantList l3 = l2.at(2).toList();
        bool isPruning = false;
        for (const auto & v : l3) {
            const QString s(v.toString().trimmed().left(kStringMax));
            if (s.isEmpty()) continue;
            if (s.startsWith('v', Qt::CaseInsensitive)) {
                pi.protocolVersion = s;
            } else if (s.startsWith('t', Qt::CaseInsensitive)) {
                bool ok;
                unsigned p = s.mid(1).toUInt(&ok);
                if (!ok || !isValidPort(p))
                    continue;
                pi.tcp = quint16(p);
            } else if (s.startsWith('s', Qt::CaseInsensitive)) {
                    bool ok;
                    unsigned p = s.mid(1).toUInt(&ok);
                    if (!ok || !isValidPort(p))
                        continue;
                    pi.ssl = quint16(p);
            } else if (s.startsWith('p', Qt::CaseInsensitive) && s.mid(1).toInt()) {
                // skip 'p' = pruning
                isPruning = true;
                break;
            }
        }
        if (isPruning)
            DebugM("PeerInfo ", pi.hostName, " is a pruning peer, skipping ...");
        else if (pi.isMinimallyValid())
            ret.push_back(pi);
        else
            DebugM("PeerInfo ", pi.hostName, " not minimally valid, skipping ...");
    }
    return ret;
}

void PeerClient::updateInfoFromRemoteFeaturesMap(const PeerInfo &o)
{
    PeerInfo & p{info};
    if (&p == &o)
        return;

    p.subversion = o.subversion;
    p.protocolMin = o.protocolMin;
    p.protocolMax = o.protocolMax;
    p.hashFunction = o.hashFunction;
    p.genesisHash = o.genesisHash;
    p.ssl = o.ssl;
    p.tcp = o.tcp;
    p.addr = o.addr;
    p.failureReason.clear();
}

/* static */ PeerInfoList PeerInfo::fromFeaturesMap(const QVariantMap &m)
{
    PeerInfoList ret;

    if (!m.value("pruning").isNull())
        throw BadFeaturesMap("Pruning not supported");

    PeerInfo base;

    base.subversion = m.value("server_version", "Unknown").toString().trimmed().left(kStringMax);
    base.protocolMin = m.value("protocol_min").toString().trimmed().left(kStringMax);
    base.protocolMax = m.value("protocol_max").toString().trimmed().left(kStringMax);
    base.genesisHash = QByteArray::fromHex(m.value("genesis_hash").toString().trimmed().toUtf8()).left(HashLen+1);
    if (base.genesisHash.length() != HashLen)
        throw BadFeaturesMap("Bad genesis hash");
    base.hashFunction = m.value("hash_function").toString().trimmed().toLower();
    if (base.hashFunction != ServerMisc::HashFunction)
        throw BadFeaturesMap("Bad/incompatible hash function");

    if (!base.protocolMin.isValid() || !base.protocolMax.isValid() || base.protocolMin > base.protocolMax)
        throw BadFeaturesMap("Bad protocol min/max");
    if (base.protocolMin > ServerMisc::MaxProtocolVersion || base.protocolMax < ServerMisc::MinProtocolVersion)
        throw BadFeaturesMap("Incompatible server protocol");

    const auto hosts = m.value("hosts").toMap();

    if (hosts.size() > 4)
        // Disallow huge maps
        throw BadFeaturesMap("Hosts map cannot have more than 4 hosts in it!");

    // now, parse each host
    for (auto it = hosts.begin(); it != hosts.end(); ++it) {
        PeerInfo pi(base); // copy c'tor of base, but fill in host, tcp, and ssl
        pi.hostName = it.key().trimmed().toLower().left(kHostNameMax); // we don't support super long hostnames as a paranoia defense
        const auto m = it.value().toMap(); // <--- note to self: shadows outer scope 'm'
        if (!m.value("tcp_port").isNull()) {
            bool ok;
            unsigned val = m.value("tcp_port", 0).toUInt(&ok);
            if (!ok || !isValidPort(val))
                throw BadFeaturesMap("Bad tcp_port");
            pi.tcp = quint16(val);
        }
        if (!m.value("ssl_port").isNull()) {
            bool ok;
            unsigned val = m.value("ssl_port", 0).toUInt(&ok);
            if (!ok || !isValidPort(val))
                throw BadFeaturesMap("Bad ssl_port");
            pi.ssl = quint16(val);
        }
        if (!pi.isMinimallyValid())
            throw BadFeaturesMap(QString("Bad host: ") + pi.hostName);
        ret.push_back(pi);
    }

    if (ret.isEmpty())
        throw BadFeaturesMap("No hosts!");

    return ret;
}
