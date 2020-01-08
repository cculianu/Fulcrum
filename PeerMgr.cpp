#include "PeerMgr.h"

#include "Options.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <QHostInfo>
#include <QSet>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>

namespace {
    constexpr int kStringMax = 80, kHostNameMax = 120;
}

PeerMgr::PeerMgr(const std::shared_ptr<Storage> &storage_ , const std::shared_ptr<const Options> &options_)
    : IdMixin(newId()), storage(storage_), options(options_)
{
    setObjectName("PeerMgr");
    _thread.setObjectName(objectName());
}

PeerMgr::~PeerMgr() { stop(); /* noop if already stopped */ Debug() << __func__;  }

QVariantMap PeerMgr::makeFeaturesDict(PeerClient *c) const
{
    return Server::makeFeaturesDictForConnection(c, _genesisHash, *options);
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

    if (const auto chain = storage->getChain(); !QSet<QString>{"test", "main"}.contains(chain))
        // can only do peering with testnet or mainnet after they have been defined (no regtest)
        throw InternalError(QString("PeerMgr cannot be started for the given chain \"%1\"").arg(chain));
    else if (chain == "test")
        parseServersDotJson(":resources/servers_testnet.json");
    else
        parseServersDotJson(":resources/servers.json");

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
    QVariantMap m = Util::Json::parseFile(fnIn).toMap();
    const QString fn = Util::basename(fnIn); // use basename for error messages below, etc
    if (m.isEmpty()) throw InternalError(QString("PeerMgr: %1 file parsed to an empty dict! FIXME!").arg(fn));
    for (auto it = m.begin(); it != m.end(); ++it) {
        PeerInfo info;
        QVariantMap d = it.value().toMap();
        info.hostName = it.key().trimmed().toLower();
        // skip empties/malformed entries, or pruning entries -- thisdefensive programming.. ideally we include only good entries in servers.json
        if (info.hostName.isEmpty() || d.isEmpty() || (!d.value("pruning").isNull() && d.value("pruning").toString() != "-")) {
            Debug() << "Server \"" << info.hostName << "\" in " << fn << " has either no data or uses pruning, skipping";
            continue;
        }
        bool ok;
        unsigned val = d.value("s", 0).toUInt(&ok);
        if (ok && val && val <= USHRT_MAX)
            info.ssl = quint16(val);
        val = d.value("t", 0).toUInt(&ok);
        if (ok && val && val <= USHRT_MAX)
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
    Debug() << objectName() << ": started ok";
}

void PeerMgr::cleanup()
{

}

void PeerMgr::on_rpcAddPeer(const PeerInfoList &infos, const QHostAddress &source)
{
    Debug() << __func__ << " source: " << source.toString();

    // detect protocols we may have missed on startup. No-op if source isNull or if we have both v4 and v6
    detectProtocol(source);

    for (const auto & pi : infos) {
        // TODO here also check the "good" connections we actively have, and if in there, maybe bump server to refresh its features,
        // then exit loop early. Also we need a way to keep track of "recently verified bad" as a DoS defense here? Hmm...
        if (queued.contains(pi.hostName) || clients.contains(pi.hostName)) { // NB: assumption here is hostName is already trimmed and toLower()
            // already added... no need to do DNS lookup or any further processing
            Debug() << "add_peer: " << pi.hostName << " already queued or in process";
            continue;
        } else if (source.isNull() && (failed.contains(pi.hostName) || bad.contains(pi.hostName))) {
            // source was not the server itself, so we ignore this request since it may have come from a server.peers.subscribe
            // and may be stale.  We will retry failed servers ourselves eventually...

            // TODO FIXME: we are optimistically going to update the ports on failed/bad with the new ports that came in
            // as a hack to support servers changing ports and our detecting that change and eventually being able to
            // connect to their new ports.  This needs tuning and more thought and consideration, however.
            for (auto map : {&failed, &bad}) { ///< go thru the failed and bad maps and update the ports if we find this hostName in them...
                if (auto it = map->find(pi.hostName); it != map->end()) {
                    it.value().tcp = pi.tcp;
                    it.value().ssl = pi.ssl;
                }
            }
            Debug() << "add_peer: " << pi.hostName << " was already deemed bad/failed, skipping";
            continue;
        }
        // For each peer in the list, do a DNS lookup and verify that the source address matches at least one
        // of the resolved addresses.  If that is the case, we can proceed with the peer add (addPeerVerifiedSource).
        // Otherwise, we reject add_peer requests from random sources.
        std::shared_ptr<std::optional<int>> lookupId = std::make_shared<decltype(lookupId)::element_type>();
        *lookupId = QHostInfo::lookupHost(pi.hostName, this, [this, pi, source, lookupId](const QHostInfo &result){
            lookupId->reset(); // signify we no longer need a cancellation .. calls reset on the std::optional (not on the shared_ptr)
            if (result.error() != QHostInfo::NoError) {
                Debug() << "add_peer: Host lookup error for " << pi.hostName << ": " << result.errorString();
                PeerInfo & p2 = failed[pi.hostName] = pi;
                p2.failureReason = result.errorString();
                return;
            }
            int skipped = 0;
            for (const auto & addr : result.addresses()) {
                if (auto proto = addr.protocol(); proto == QAbstractSocket::IPv4Protocol && !hasip4) {
                    ++skipped;
                    continue;
                } else if (proto == QAbstractSocket::IPv6Protocol && !hasip6) {
                    ++skipped;
                    continue;
                }
                if (source.isNull() || addr == source) {
                    Debug() << "add_peer: " << pi.hostName << " address (" << addr.toString() << ") ok for source (" << source.toString() << "), processing further ...";
                    addPeerVerifiedSource(pi, addr);
                    return;
                }
            }
            Debug() << "add_peer: Rejected because source (" << source.toString() << ") does not match resolved address ("
                    << (result.addresses().isEmpty() ? QString() : result.addresses().front().toString()) << ")"
                    << (skipped ? " (some of the resolved addresses were skipped due us lacking the capability to connect to their advertised IP protocol)" : "");
        });
        QTimer::singleShot(int(kDNSTimeout*1e3), this, [this, lookupId, pi] {
            if (lookupId->has_value()) {
                QHostInfo::abortHostLookup(lookupId->value());
                PeerInfo & p2 = failed[pi.hostName] = pi;
                p2.failureReason = "DNS timed out";
                Debug() << "add_peer: hostname lookup for " << pi.hostName << " timed out after " << QString::number(kDNSTimeout, 'f', 1) << " secs";
            }
        });
    }
}

void PeerMgr::addPeerVerifiedSource(const PeerInfo &piIn, const QHostAddress & addr)
{
    Debug() << __func__ << " peer " << piIn.hostName << " ipaddr: " << addr.toString();

    // *** TODO here -- keep a set of IP addresses of peers and not add dupe peers with different hostnames (but same
    // IP).  This would be a sybil attack defense measure!  TODO ****

    PeerInfo pi(piIn);
    pi.addr = addr;
    pi.failureReason = "";
    queued[pi.hostName] = pi;
    failed.remove(pi.hostName);
    bad.remove(pi.hostName);
    Debug() << "add_peer: " << pi.hostName << " added to queue";
    processSoon();
}

void PeerMgr::allServersStarted()
{
    if (QThread::currentThread() != thread()) {
        Util::AsyncOnObject(this, [this] {allServersStarted();});
        return;
    }
    // TODO ...
    Debug() << __func__;

    // start out with the seedPeers
    queued = seedPeers;
    processSoon();

    // next, set up the "failed retry time" which runs every kFailureRetryTime seconds (10 mins)
    callOnTimerSoon(int(kFailureRetryTime*1e3), "failedPeerRetry", [this]{
        retryFailedPeers();
        return true;
    });
    // next, set up the "bad retry time" which runs every kBadPeerRetryTime seconds (60 mins)
    callOnTimerSoon(int(kBadPeerRetryTime*1e3), "badPeerRetry", [this]{
        retryFailedPeers(true);
        return true;
    });
}

void PeerMgr::retryFailedPeers(bool useBadMap)
{
    int ctr = 0;
    auto & failed = (useBadMap ? this->bad : this->failed);
    for (const auto & pi : failed) {
        if (!queued.contains(pi.hostName) && !clients.contains(pi.hostName)) {
            queued.insert(pi.hostName, pi);
            ++ctr;
        }
    }
    failed.clear();
    failed.squeeze();
    if (ctr) {
        Debug() << "Retrying " << ctr << " " << (useBadMap ? "'bad'" : "'failed'") << Util::Pluralize(" peer", ctr) << " ...";
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
        PeerInfoList copy;
        {
            ExclusiveLock g(mut);
            sharedPeers.clear();
            for (const auto & client : clients) {
                if (client->isGood() && !client->isStale() && !client->info.genesisHash.isEmpty())
                    sharedPeers.push_back(client->info);
            }
            copy = sharedPeers; // take a copy now for signal below (this is O(1) due to implicit sharing)
        }
        emit updated(copy);
    });
}

PeerInfoList PeerMgr::peers() const {
    SharedLock g(mut);
    return sharedPeers;
}

void PeerMgr::process()
{
    if (queued.isEmpty())
        return;
    PeerInfo pi = queued.take(queued.begin().key());
    if (pi.addr.isNull()) {
        Debug() << "PeerInfo.addr was null for " << pi.hostName << ", calling on_rpcAddPeer to resolve address";
        on_rpcAddPeer(PeerInfoList{pi}, pi.addr);
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
    client = new PeerClient(options->peerAnnounceSelf, pi, newId(), this, 64*1024);
    connect(client, &PeerClient::connectFailed, this, &PeerMgr::on_connectFailed);
    connect(client, &PeerClient::bad, this, &PeerMgr::on_bad);
    connect(client, &PeerClient::gotPeersSubscribeReply, this, &PeerMgr::on_rpcAddPeer);
    connect(client, &QObject::destroyed, this, [this, hostName = pi.hostName](QObject *obj) {
        auto client = clients.value(hostName, nullptr);
        if (client == obj) {
            clients.remove(hostName);
            updateSoon();
            Debug() << "Removed peer from map: " << hostName;
        } else {
            Debug() << "Peer not found in map: " << hostName;
        }
    });
    connect(client, &PeerClient::lostConnection, this, [](AbstractConnection *c){
        PeerClient *client = dynamic_cast<PeerClient *>(c);
        Debug() << (client ? client->info.hostName : QString("???")) << ": Socket disconnect";
        c->deleteLater();
    });

    clients[pi.hostName] = client;
    updateSoon();
    return client;
}

void PeerMgr::on_bad(PeerClient *c)
{
    if (c->info.hostName.isEmpty())
        return;
    bad[c->info.hostName] = c->info;
    c->deleteLater(); // drop connection
}

void PeerMgr::on_connectFailed(PeerClient *c)
{
    if (c->info.hostName.isEmpty())
        return;
    if (c->info.failureReason.isEmpty()) {
        c->info.failureReason = c->socket ? c->socket->errorString() : "";
        if (c->info.failureReason.isEmpty())
            c->info.failureReason = "Connection failed";
    }
    failed[c->info.hostName] = c->info;
    c->deleteLater(); // clean up
}

auto PeerMgr::stats() const -> Stats
{
    QVariantMap ret;
    QVariantMap m0;
    for (const auto & client : clients)
        m0[client->info.hostName] = client->stats();
    ret["peers"] = m0;
    m0.clear();
    for (const auto & info : bad) {
        m0[info.hostName] = QVariantList{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), info.failureReason };
    }
    ret["bad"] = m0;
    m0.clear();
    for (const auto & info : queued) {
        m0[info.hostName] = QVariantList{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), info.failureReason };
    }
    ret["queued"] = m0;
    m0.clear();
    for (const auto & info : failed) {
        m0[info.hostName] = QVariantList{ info.addr.toString(), info.tcp, info.ssl, info.subversion, info.protocolVersion.toString(), info.failureReason };
    }
    ret["failed"] = m0;
    ret["peering"] = options->peerDiscovery;
    ret["announce"] = options->peerAnnounceSelf;
    return ret;
}

auto PeerClient::stats() const -> Stats
{
    QVariantMap m = RPC::LinefeedConnection::stats().toMap();
    m["addr"] = info.addr.toString();
    m["server_version"] = info.subversion;
    m["protocolVersion"] = info.protocolVersion.toString();
    m["protocol_min"] = info.protocolMin.toString();
    m["protocol_max"] = info.protocolMax.toString();
    m["hash_function"] = info.hashFunction;
    m["genesis_hash"] = info.genesisHash.toHex();
    m["tcp_port"] = info.tcp;
    m["ssl_port"] = info.ssl;
    m["isTor?"] = info.isTor();
    return m;
}

PeerClient::PeerClient(bool announce, const PeerInfo &pi, IdMixin::Id id_, PeerMgr *mgr, int maxBuffer)
    : RPC::LinefeedConnection({}, id_, mgr, maxBuffer), announceSelf(announce), info(pi), mgr(mgr)
{
    setObjectName(QString("Peer %1").arg(pi.hostName));

    pingtime_ms = int(PeerMgr::kConnectedPeerRefreshInterval * 1e3);
    stale_threshold = pingtime_ms * 2;

    if (pi.tcp) { // prefer tcp -- it's faster
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
    // on any errors we just assume the connection is down, tell PeerMgr to put it in the connect failed list
    connect(socket, qOverload<QAbstractSocket::SocketError>(&QAbstractSocket::error), this,
            [this](QAbstractSocket::SocketError){ emit connectFailed(this); });

    if (socket) {
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
}

PeerClient::~PeerClient() {
    Debug() << __func__ << ": " << info.hostName;
}


void PeerClient::connectToPeer()
{
    if (!socket) return;
    QSslSocket *ssl = dynamic_cast<QSslSocket *>(socket);
    if (ssl) {
        Debug() << info.hostName << ": connecting to SSL " << info.addr.toString();
        connect(ssl, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), ssl, [ssl, hostName = info.hostName](auto errs) {
            for (const auto & err : errs) {
                Debug() << "Ignoring SSL error for " << hostName << ": " << err.errorString();
            }
            ssl->ignoreSslErrors();
        });
        ssl->connectToHostEncrypted(info.addr.toString(), info.ssl, info.hostName);
    } else {
        Debug() << info.hostName << ": connecting to TCP " << info.addr.toString();
        socket->connectToHost(info.addr, info.tcp);
    }
}

void PeerClient::do_disconnect([[maybe_unused]] bool graceful)
{
    RPC::LinefeedConnection::do_disconnect(false);
    deleteLater();
}

void PeerClient::on_connected()
{
    RPC::LinefeedConnection::on_connected();
    // refresh immediately upon connection
    refresh();
}

void PeerClient::do_ping()
{
    Debug() << info.hostName << ": pinging ... ";
    // the "ping" here is to grab server.features and server.peer.subscribe periodically
    refresh();
}

void PeerClient::refresh()
{
    if (!sentVersion) {
        // this kicks off the chain of handleReply below which is really a simple state machine
        emit sendRequest(newId(), "server.version", QVariantList{ServerMisc::AppSubVersion, ServerMisc::MinProtocolVersion.toString()});
        sentVersion = true;
    } else {
        // we already sent version -- kick off the state machine from its second state
        emit sendRequest(newId(), "server.features");
    }

}

void PeerClient::handleReply(IdMixin::Id, const RPC::Message & reply)
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
        Debug() << info.hostName << ": features responded ...";
        PeerInfoList pl;
        try {
            pl = PeerInfo::fromFeaturesMap(reply.result().toMap());
            const auto remoteAddr = peerAddress();
            for (auto & pi : pl)  {
                // fill-in address right now since we know it, just to be tidy
                pi.addr = remoteAddr;
            }
        } catch (const BadFeaturesMap &e) {
            Debug() << "Peer " << info.hostName << " gave us a bad features mep: " << e.what();
            Bad(QString("Bad features map: ") + e.what());
            return;
        }
        bool found = false;
        const bool weAreSsl = isSsl();
        const quint16 remotePort = peerPort();
        for (const auto & pi : pl) {
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
                break;
            }
        }
        if (!found) {
            Bad("Cannot find an entry in 'features' that matches the same hostname AND that is also advertising the port we are connected to");
            return;
        }
        emit sendRequest(newId(), "server.peers.subscribe");
    } else if (reply.method == "server.add_peer") {
        // handle
        Debug() << info.hostName << ": add_peer... result = " << reply.result().toBool();
    } else if (reply.method == "server.peers.subscribe") {
        // handle
        QString dbgstr;
        try { dbgstr = Util::Json::toString(reply.result(), true); } catch (...) {}
        Debug() << info.hostName << ": subscribe responded ... " << dbgstr;
        PeerInfoList candidates;
        try {
            candidates = PeerInfo::fromPeersSubscribeList(reply.result().toList());
        } catch (const BadPeerList & e) {
            Bad(QString("Failed to parse add_peer list: ") + e.what());
            return;
        }
        // tell peermgr about some new candidates (note peermgr filters out already-added or candidates that may be dupes, etc).
        emit gotPeersSubscribeReply(candidates, QHostAddress());
        if (announceSelf) {
            bool foundme = false;
            for (const auto & pi : candidates) {
                if (pi.hostName == mgr->publicHostNameForConnection(this)) {
                    foundme = true;
                    break;
                }
            }
            if (!foundme) {
                emit sendRequest(newId(), "server.add_peer", QVariantList{mgr->makeFeaturesDict(this)});
            }
        }
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
        pi.addr.setAddress(l2.at(0).toString().trimmed().left(kStringMax));
        if (pi.addr.isNull()) {
            Debug() << "skipping null address";
            continue;
        }
        pi.hostName = l2.at(1).toString().trimmed().left(kHostNameMax).toLower();
        if (pi.hostName.isEmpty()) {
            Debug() << "skipping empty hostname for " << pi.addr.toString();
            continue;
        }
        QVariantList l3 = l2.at(2).toList();
        for (const auto & v : l3) {
            QString s(v.toString().trimmed().left(kStringMax));
            if (s.isEmpty()) continue;
            if (s.startsWith('v', Qt::CaseInsensitive))
                pi.protocolVersion = s;
            else if (s.startsWith('t', Qt::CaseInsensitive)) {
                bool ok;
                unsigned p = s.mid(1).toUInt(&ok);
                if (!p || !ok || p > USHRT_MAX)
                    continue;
                pi.tcp = quint16(p);
            } else if (s.startsWith('s', Qt::CaseInsensitive)) {
                    bool ok;
                    unsigned p = s.mid(1).toUInt(&ok);
                    if (!p || !ok || p > USHRT_MAX)
                        continue;
                    pi.ssl = quint16(p);
                }
        }
        if (pi.isMinimallyValid())
            ret.push_back(pi);
        else
            Debug() << "PeerInfo " << pi.hostName << " not minimally valid, skipping ...";
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

/* static */ QList<PeerInfo> PeerInfo::fromFeaturesMap(const QVariantMap &m)
{
    QList<PeerInfo> ret;

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
            if (!ok || !val || val > USHRT_MAX) throw BadFeaturesMap("Bad tcp_port");
            pi.tcp = quint16(val);
        }
        if (!m.value("ssl_port").isNull()) {
            bool ok;
            unsigned val = m.value("ssl_port", 0).toUInt(&ok);
            if (!ok || !val || val > USHRT_MAX) throw BadFeaturesMap("Bad ssl_port");
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
