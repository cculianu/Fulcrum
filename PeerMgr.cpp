#include "PeerMgr.h"

#include "Options.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <QHostInfo>
#include <QSet>

PeerMgr::PeerMgr(const std::shared_ptr<Storage> &storage_ , const std::shared_ptr<const Options> &options_)
    : IdMixin(newId()), storage(storage_), options(options_)
{
    setObjectName("PeerMgr");
    _thread.setObjectName(objectName());
}

PeerMgr::~PeerMgr() { stop(); /* noop if already stopped */ Debug() << __func__;  }

void PeerMgr::startup()
{
    if (storage->genesisHash().length() != HashLen)
        throw InternalError("PeerMgr cannot be started until we have a valid genesis hash! FIXME!");
    if (const auto chain = storage->getChain(); !QSet<QString>{"test", "main"}.contains(chain))
        // can only do peering with testnet or mainnet after they have been defined (no regtest)
        throw InternalError(QString("PeerMgr cannot be started for the given chain \"%1\"").arg(chain));
    else if (chain == "test")
        parseServersDotJson(":resources/servers_testnet.json");
    else
        parseServersDotJson(":resources/servers_testnet.json");
    start();
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

    // TODO: perhaps put all these in a queue and collapse dupes down -- as it stands clients can spam the same request
    // over and over and cause us to waste time doing network lookups.

    for (const auto & pi : infos) {
        // For each peer in the list, do a DNS lookup and verify that the source address matches at least one
        // of the resolved addresses.  If that is the case, we can proceed with the peer add (addPeerVerifiedSource).
        // Otherwise, we reject add_peer requests from random sources.
        std::shared_ptr<std::optional<int>> lookupId = std::make_shared<decltype(lookupId)::element_type>();
        *lookupId = QHostInfo::lookupHost(pi.hostName, this, [this, pi, source, lookupId](const QHostInfo &result){
            lookupId->reset(); // signify we no longer need a cancellation .. calls reset on the std::optional (not on the shared_ptr)
            if (result.error() != QHostInfo::NoError) {
                Debug() << "add_peer: Host lookup error for " << pi.hostName << ": " << result.errorString();
                return;
            }
            for (const auto & addr : result.addresses()) {
                if (addr == source) {
                    Debug() << "add_peer: " << pi.hostName << " address (" << addr.toString() << ") matches source (" << source.toString() << "), processing further ...";
                    addPeerVerifiedSource(pi, addr);
                    return;
                }
            }
            Debug() << "add_peer: Rejected because source (" << source.toString() << ") does not match resolved address ("
                    << (result.addresses().isEmpty() ? QString() : result.addresses().front().toString()) << ")";
        });
        QTimer::singleShot(DNSTimeoutMS, this, [lookupId, hostName = pi.hostName]{
            if (lookupId->has_value()) {
                QHostInfo::abortHostLookup(lookupId->value());
                Debug() << "add_peer: hostname lookup for " << hostName << " timed out after " << QString::number(DNSTimeoutMS/1e3, 'f', 1) << " secs";
            }
        });
    }
}

void PeerMgr::addPeerVerifiedSource(const PeerInfo &piIn, const QHostAddress & addr)
{
    PeerInfo pi(piIn);
    pi.addr = addr;
    Debug() << __func__ << " peer " << pi.hostName << " ipaddr: " << pi.addr.toString();
    // TODO ...
}

void PeerMgr::allServersStarted()
{
    // TODO ...
    Debug() << __func__;
}


/* static */ QList<PeerInfo> PeerInfo::fromFeaturesMap(const QVariantMap &m)
{
    QList<PeerInfo> ret;

    if (!m.value("pruning").isNull())
        throw BadFeaturesMap("Pruning not supported");

    PeerInfo base;

    base.subversion = m.value("server_version", "Unknown").toString().trimmed().left(80);
    base.protocolMin = m.value("protocol_min").toString().trimmed().left(80);
    base.protocolMax = m.value("protocol_max").toString().trimmed().left(80);
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
        pi.hostName = it.key().trimmed().toLower().left(120); // we don't support super long hostnames as a paranoia defense
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
