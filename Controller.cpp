#include "Controller.h"
#include "SrvMgr.h"
#include "EXMgr.h"
#include "TcpServer.h"

Controller::Controller(SrvMgr *srv, EXMgr *ex)
    : Mgr(nullptr/* top-level because thread*/), srvMgr(srv), exMgr(ex)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
    connect(srvMgr, SIGNAL(newTcpServer(TcpServer *)), this, SLOT(onNewTcpServer(TcpServer *)));
    connect(exMgr, SIGNAL(gotListUnspentResults(const AddressUnspentEntry &)), this, SLOT(onListUnspentResults(const AddressUnspentEntry &)));
    connect(exMgr, SIGNAL(gotNewBlockHeight(int)), this, SLOT(onNewBlockHeight(int)));
}

Controller::~Controller()
{
    cleanup();
}

void Controller::cleanup()
{
    stop(); // no-op if not running
}

void Controller::startup()
{
    start(); // start thread
    if (chan.get<QString>(10000).isEmpty())
        throw Exception("Controller startup timed out after 10 seconds");
}

QObject *Controller::qobj() { return this; }

void Controller::on_started()
{
    ThreadObjectMixin::on_started();
    Log() << objectName() << " started";
    chan.put("ok");
}

void Controller::on_finished()
{
    ThreadObjectMixin::on_finished();
    Debug() << objectName() << " finished.";
}

void Controller::onNewTcpServer(TcpServer *srv)
{
    // NB: assumption is TcpServer lives for lifetime of this object. If this invariant changes,
    // please update this code.
    Debug() << __FUNCTION__ << ": " << srv->objectName();

    // attach signals to our slots so we get informed of relevant state changes
    connect(srv, &TcpServer::newShuffleSpec, this, &Controller::onNewShuffleSpec);
    connect(srv, &TcpServer::clientDisconnected, this, &Controller::onClientDisconnected);
    const QString srvName(srv->objectName());
    connect(srv, &QObject::destroyed, this, [srvName]{
        /// defensive programming reminder if invariant is violated by future code changes.
        /// this won't normally ever be reached, as assumption is the controller always dies first.
        Error() << "TcpServer \"" << srvName << "\" destroyed while Controller still alive! FIXME!";
    });
}

#define server_boilerplate \
    TcpServer *server = dynamic_cast<TcpServer *>(sender()); \
    if (!server) { \
        Error() << __FUNCTION__ << " sender() is either NULL or not a TcpServer! FIXME!"; \
        return; \
    }
void Controller::onClientDisconnected(qint64 clientId)
{
    server_boilerplate
    Debug() << __FUNCTION__ << ": clientid: " << clientId << ", server: " << server->objectName();

    int flushCt = 0;
    if (auto mapServer = clientIdToServerMap.take(clientId) /*client is dead, remove entry from map*/;
            mapServer && mapServer != server) {
        // mapServer may be null and that's ok, if client never sent a spec.
        // more defensive programming
        Warning() << __FUNCTION__ << " clientId: " << clientId << " had server: " << mapServer->objectName()
                  << " in map, but sender was: " << server->objectName();
    } else if (mapServer)
        ++flushCt;
    // remove client from cache, if any
    for (auto it = addressUnspentCache.begin(); it != addressUnspentCache.end(); ++it)
        if (it.value().clientSet.remove(clientId))
            ++flushCt;
    if (flushCt)
        Debug("Record of client %lld removed from %d internal data structures", clientId, flushCt);
}
void Controller::onNewShuffleSpec(const ShuffleSpec &spec)
{
    server_boilerplate
    Debug() << __FUNCTION__ << "; got spec: " << spec.toDebugString() << ", server: " << server->objectName();
    if (spec.isValid())
        // remember which server this client came from.
        clientIdToServerMap[spec.clientId] = server;
    else {
        Warning() << "Ignoring invalid ShuffleSpec! FIXME!";
        return;
    }

    // TODO: here we will need to run through spec, check cache, update from listunspent in EX for any unknown UTXOs, etc...
}
#undef server_boilerplate
void Controller::onNewBlockHeight(int height)
{
    // from exMgr
    Debug() << __FUNCTION__ << "; got new block height: " << height;

    // TODO: use this information towards seeing if addressUnspentCache needs refreshing, etc
}
void Controller::onListUnspentResults(const AddressUnspentEntry &entry)
{
    // from exMgr
    Debug() << __FUNCTION__ <<"; got list unspent results: " << entry.toDebugString();
    // TODO: handle, process, etc
}

QString ShuffleSpec::toDebugString() const
{
    QString ret;
    {
        QTextStream ts(&ret);

        ts << "(Shuffle Spec; clientId: " << clientId << "; refId: " << refId << "; <amounts: ";
        for (const auto amt : amounts)
            ts << amt << ", ";
        ts << ">; shuffleAddr: " << shuffleAddr.toString() << "; changeAddr: " << changeAddr.toString();
        ts << "; <utxos: ";
        for (auto it = addrUtxo.begin(); it != addrUtxo.end(); ++it) {
            for (const auto & utxo : it.value()) {
                ts << it.key().toString() << "/" << utxo.toString() << ", ";
            }
        }
        ts << ">)";
    }
    return ret;
}

QString AddressUnspentEntry::toDebugString() const
{
    QString ret;
    {
        QTextStream ts(&ret);
        ts << "(AddressUnspentEntry; address: " << address.toString() << "; heightVerified: " << heightVerified << "; tsVerified: " << tsVerified
           << "; <clients: ";
        for (const auto c : clientSet) {
            ts << c << ", ";
        }
        ts << ">; <UTXO Amounts: ";
        for (auto it = utxoAmounts.begin(); it != utxoAmounts.end(); ++it) {
            ts << it.key().toString() << "=" << it.value() << " sats, ";
        }
        ts << ">; <UTXO Unconf. Amounts: ";
        for (auto it = utxoUnconfAmounts.begin(); it != utxoUnconfAmounts.end(); ++it) {
            ts << it.key().toString() << "=" << it.value() << " sats, ";
        }
        ts << ">)";
    }
    return ret;
}
