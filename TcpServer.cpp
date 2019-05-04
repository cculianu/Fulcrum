#include "TcpServer.h"
#include "Controller.h"
#include <QCoreApplication>
#include <QtNetwork>

TcpServerError::~TcpServerError() {} // for vtable

TcpServer::TcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), IdMixin(newId()), addr(a), port(p)
{
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());
    setupMethods();
}

TcpServer::~TcpServer()
{
    Debug() << __FUNCTION__;
    stop();
}

QString TcpServer::hostPort() const
{
    return QString("%1:%2").arg(addr.toString()).arg(port);
}

QString TcpServer::prettyName() const
{
    return QString("Srv %1 (id: %2)").arg(hostPort()).arg(id);
}

void TcpServer::tryStart()
{
    if (!_thread.isRunning()) {
        ThreadObjectMixin::start(); // call super
        Log() << "Starting listener service for " << prettyName() << " ...";
        if (auto result = chan.get<QString>(); result != "ok") {
            result = result.isEmpty() ? "Startup timed out!" : result;
            throw TcpServerError(result);
        }
        Log() << "Service started, listening for connections on " << hostPort();
    } else {
        throw TcpServerError(prettyName() + " already started");
    }
}

void TcpServer::on_started()
{
    QString result = "ok";
    connect(this, SIGNAL(newConnection()), this, SLOT(on_newConnection()));
    connect(this, SIGNAL(acceptError(QAbstractSocket::SocketError)), this, SLOT(on_acceptError(QAbstractSocket::SocketError)));
    connect(this, &TcpServer::tellClientSpecRejected, this, &TcpServer::_tellClientSpecRejected);
    connect(this, &TcpServer::tellClientSpecAccepted, this, &TcpServer::_tellClientSpecAccepted);
    connect(this, &TcpServer::tellClientSpecPending, this, &TcpServer::_tellClientSpecPending);
    if (!listen(addr, port)) {
        result = errorString();
        result = result.isEmpty() ? "Error binding/listening for connections" : result;
        Debug() << __FUNCTION__ << " listen failed";
    } else {
        Debug() << "started ok";
    }
    chan.put(result);
}

void TcpServer::on_finished()
{
    disconnect(this, &TcpServer::tellClientSpecRejected, this, &TcpServer::_tellClientSpecRejected);
    disconnect(this, &TcpServer::tellClientSpecAccepted, this, &TcpServer::_tellClientSpecAccepted);
    disconnect(this, &TcpServer::tellClientSpecPending, this, &TcpServer::_tellClientSpecPending);
    disconnect(this, SIGNAL(newConnection()), this, SLOT(on_newConnection()));
    disconnect(this, SIGNAL(acceptError(QAbstractSocket::SocketError)), this, SLOT(on_acceptError(QAbstractSocket::SocketError)));
    close(); /// stop listening
    chan.put("finished");
    Debug() << objectName() << " finished.";
    ThreadObjectMixin::on_finished();
}

static inline QString prettySock(QAbstractSocket *sock)
{
    return QString("%1:%2")
            .arg(sock ? sock->peerAddress().toString() : "(null)")
            .arg(sock ? sock->peerPort() : 0);
}

void TcpServer::on_newConnection()
{
    QTcpSocket *sock = nextPendingConnection();
    if (sock) {
        Debug() << "Got connection from: " << prettySock(sock);
        newClient(sock);
    } else {
        Warning() << __FUNCTION__ << ": nextPendingConnection returned a nullptr! Called at the wrong time? FIXME!";
    }
}

void TcpServer::on_acceptError(QAbstractSocket::SocketError e)
{
    Error() << objectName() << "; error acceptError, code: " << int(e);
}

Client *
TcpServer::newClient(QTcpSocket *sock)
{
    const auto clientId = newId();
    auto ret = clientsById[clientId] = new Client(_rpcMethods, clientId, this, sock);
    // if deleted, we need to purge it from map
    auto on_destroyed = [clientId, this](QObject *o) {
        // this whole call is here so that delete client->sock ends up auto-removing the map entry
        // as a convenience.
        Debug() << "Client nested 'on_destroyed' called";
        auto client = clientsById.take(clientId);
        if (client) {
            if (client != o) {
                Error() << " client != passed-in pointer to on_destroy in " << __FILE__ << " line " << __LINE__  << ". FIXME!";
            }
            Debug("client id %ld purged from map", long(clientId));
        }
    };
    connect(ret, &QObject::destroyed, this, on_destroyed);
    connect(ret, &AbstractConnection::lostConnection, this, [this,clientId](AbstractConnection *cl){
        if (auto client = dynamic_cast<Client *>(cl) ; client) {
            Debug() <<  client->prettyName() << " lost connection";
            emit clientDisconnected(client->id);
            killClient(client);
        } else {
            Error() << "Internal error: lostConnection callback received null client! (expected client id: " << clientId << ")";
        }
    });
    connect(ret, &RPC::Connection::gotMessage, this, &TcpServer::onMessage);
    connect(ret, &RPC::Connection::gotErrorMessage, this, &TcpServer::onErrorMessage);
    connect(ret, &RPC::Connection::peerError, this, &TcpServer::onPeerError);
    return ret;
}

void TcpServer::killClient(Client *client)
{
    if (!client)
        return;
    Debug() << __FUNCTION__ << " (id: " << client->id << ")";
    clientsById.remove(client->id); // ensure gone from map asap so future lookups fail
    client->do_disconnect();
}
void TcpServer::killClient(qint64 clientId)
{
    killClient(clientsById.take(clientId));
}


void TcpServer::setupMethods()
{
    QString m, p;
    m = "server.version";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [\"=2\"] }").arg(m), // in schema  (asynch req. client -> us) -- enforce must have 2 string args
        RPC::schemaResult + QString(" { \"result\" : [\"=2\"] }"), // result schema (synch. us -> client) -- we send them results.. enforce must have 2 string args
        RPC::Schema() // out schema  -- we never invoke this on the client so disable.
    )));

    m = "server.ping";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethodNoParams, // in schema, ping from client to us
        RPC::schemaResult + QString(" { \"result\" : null }"), // result schema -- 'result' arg should be there and be null.
        RPC::schemaMethodNoParams // out schema, ping to client takes no args
    )));

    p = "{ \"amounts\" : [1], \"utxos\" : [{\"addr\" : \"x\", \"utxo\" : \"x\"}], \"shuffleAddr\" : \"x\", \"changeAddr\" : \"x\" }";
    m = "shuffle.spec";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [%2] }").arg(m).arg(p), // in schema (asynch req)
        RPC::schemaResult + QString(" { \"result\" : \"ok!\" }"), // result schema -- 'result' arg should be there and be the string "ok". On error we send an error response
        RPC::Schema() // we never invoke this on client
    )));

}

void TcpServer::onMessage(qint64 clientId, const RPC::Message &m)
{
    Debug() << "onMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        if (m.method == "server.version") {
            if (QVariantList l = m.data.toList(); m.isRequest() && l.size() == 2) {
                c->info.userAgent = l[0].toString();
                c->info.protocolVersion = l[1].toString();
                Debug() << "Client (id: " << c->id << ") sent version: \"" << c->info.userAgent << "\" / \"" << c->info.protocolVersion << "\"";
            } else {
                Error() << "Bad server version message! Schema should have handled this. FIXME! Json: " << m.toJsonString();
            }
            emit c->sendResult(m.id, m.method, QStringList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
        } else if (m.method == "server.ping") {
            if (m.isResult()) {
                Debug() << "Got ping reply from client (id: " << c->id << ")";
            } else if (m.isRequest()) {
                Debug() << "Got ping from client (id: " << c->id << "), responding...";
                emit c->sendResult(m.id, m.method);
            } else {
                Error() << "Bad client ping message! Schema should have handled this. FIXME! Json: " << m.toJsonString();
            }
        } else if (m.method == "shuffle.spec") {
            if (QString errMsg; !processSpec(clientId, m, errMsg)) {
                Debug() << "Got bad spec from client (id: " << c->id << "), sending error reply";
                emit c->sendError(false, -290, errMsg, m.id);
            } else {
                // don't tell client anything yet -- wait for Controller to return a response.
                //c->sendResult(m.id, m.method, "ok");
            }
        } else {
            Error() << "Unknown method: \"" << m.method << "\". Schema should have handled this. FIXME! Json: " << m.toJsonString();
        }
    } else {
        Debug() << "Unknown client: " << clientId;
    }
}
void TcpServer::onErrorMessage(qint64 clientId, const RPC::Message &m)
{
    Debug() << "onErrorMessage: " << clientId << " json: " << m.toJsonString();
}
void TcpServer::onPeerError(qint64 clientId, const QString &what)
{
    Debug() << "onPeerError, client " << clientId << " error: " << what;
    if (Client *c = getClient(clientId); c) {
        if (++c->info.errCt >= 5) {
            Warning() << "Excessive errors (5) for: " << c->prettyName() << ", disconnecting";
            killClient(c);
            return;
        }
    }
}

bool TcpServer::processSpec(qint64 clientId, const RPC::Message &m, QString & errMsg)
{
    /* sample json for testing:
      {"id":64,"jsonrpc":"2.0","method":"shuffle.spec","params":[{"amounts":[10000,100000,1000000,10000000],"utxos":[{"addr":"1NNi1ac2f7wQQ1qoYq8AwPZUfL71RqmWYP","utxo":"932e34ad34d2b3c44c7e01247611dc8fbd3cb0fedf230a5c30b230ecaa9be335:7"},{"addr":"1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ","utxo":"f6b0fc46aa9abb446b3817f9f5898f45233b274692d110203e2fe38c2f9e9ee3:12"}], "shuffleAddr" : "15YiSmUtzKXicZWxoGEKvFruQRDov7duTx", "changeAddr" : "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ"}]}
    */
    struct ErrorOut : public Exception { using Exception::Exception; };

    try {
        if (!m.isRequest() && !m.isList())
            throw ErrorOut("Bad shuffle spec");
        ShuffleSpec spec;
        spec.clientId = clientId;
        spec.refId = m.id;
        auto list = m.data.toList();
        if (list.length() != 1)
            throw ErrorOut("Bad shuffle spec");
        auto map = list.front().toMap();
        QVariantList amounts = map.value("amounts").toList(), utxos = map.value("utxos").toList();
        if (amounts.isEmpty() || utxos.isEmpty())
            throw ErrorOut("Amounts or utxos empty");
        spec.shuffleAddr = map.value("shuffleAddr").toString();
        spec.changeAddr = map.value("changeAddr").toString();
        if (!spec.shuffleAddr.isValid() || !spec.changeAddr.isValid())
            throw ErrorOut("Bad change or shuffle address");
        if (spec.shuffleAddr == spec.changeAddr)
            throw ErrorOut("Shuffle and change address must be different addresses!");
        for (const auto & var : amounts) {
            bool ok;
            quint64 amt;
            amt = var.toULongLong(&ok);
            if (!ok || !amt)
                throw ErrorOut(QString("Bad amount \"%1\"").arg(var.toString()));
            if (spec.amounts.contains(amt))
                throw ErrorOut(QString("Dupe amount \"%1\"").arg(amt));
            spec.amounts.insert(amt);
        }
        for (const auto & var : utxos) {
            auto umap = var.toMap();
            BTC::Address addr(umap.value("addr").toString());
            if (!addr.isValid())
                throw ErrorOut("Bad or missing address in nested utxo dict");
            if (addr == spec.shuffleAddr)
                throw ErrorOut("Shuffle output address cannot be in utxo list. It should be a new address.");
            BTC::UTXO utxo(umap.value("utxo").toString());
            if (!utxo.isValid())
                throw ErrorOut("Bad or missing utxo in nested utxo dict");
            if (spec.addrUtxo[addr].contains(utxo))
                throw ErrorOut(QString("Dupe utxo: \"%1\"").arg(utxo.toString()));
            spec.addrUtxo[addr].insert(utxo);
        }
        if (!spec.isValid())
            throw ErrorOut("Spec evaluates to invalid");
        Debug() << "Got Spec -----> " << spec.toDebugString();
        emit newShuffleSpec(spec);
    } catch (const std::exception & e) {
        errMsg = e.what();
        return false;
    }
    errMsg = "";
    return true;
}

void TcpServer::_tellClientSpecRejected(qint64 clientId, qint64 refId, const QString & reason)
{
    if (Client *client = getClient(clientId); client) {
        client->sendError(false, -290, reason, refId);
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}
void TcpServer::_tellClientSpecAccepted(qint64 clientId, qint64 refId) {
    if (Client *client = getClient(clientId); client) {
        client->sendResult(refId, "shuffle.spec", "accepted");
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}
void TcpServer::_tellClientSpecPending(qint64 clientId, qint64 refId) {
    if (Client *client = getClient(clientId); client) {
        client->sendResult(refId, "shuffle.spec", "pending");
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}

Client::Client(const RPC::MethodMap & mm, qint64 id, TcpServer *srv, QTcpSocket *sock)
    : RPC::Connection(mm, id, sock, /*maxBuffer=1MB*/1000000), srv(srv)
{
    socket = sock;
    Q_ASSERT(socket->state() == QAbstractSocket::ConnectedState);
    status = Connected ; // we are always connected at construction time.
    errorPolicy = ErrorPolicySendErrorMessage;
    setObjectName("Client");
    on_connected();
    Debug() << prettyName() << " new client";
}

Client::~Client()
{
    Debug() << __PRETTY_FUNCTION__;
    socket = nullptr; // NB: we are a child of socket. this line here is added in case some day I make AbstractClient delete socket on destruct.
}

void Client::do_disconnect(bool graceful)
{
    const bool wasConnected = socket ? socket->state() == QAbstractSocket::ConnectedState : false;
    AbstractConnection::do_disconnect(graceful); // if 'graceful' *AND* was connected, a disconnected state will be entered later at which point we will delete socket.
    if (socket && (!graceful || !wasConnected))
        /// delete the socket if we weren't connected or if !graceful.
        /// If graceful && connected, then a disconnect signal will be sent later and then we will
        /// reenter here and delete the socket.
        socket->deleteLater(); // side-effect: will implicitly delete 'this' because we are a child of the socket!
    else if (socket && graceful)
        Debug() << __FUNCTION__ << " (graceful); delayed socket delete (wait for disconnect) ...";
}

void Client::do_ping()
{
    if (Util::getTime() - lastGood >= pingtime_ms * 2) {
        Debug() << prettyName() << ": idle timeout after " << ((pingtime_ms*2.0)/1e3) << " sec., will close connection";
        emit sendError(true, -300, "Idle time exceeded");
        return;
    }
    // Don't send clients pings, because the reqId we send them may clash with one
    // they sent us. Instead, rely on them to ping us else disconnect them if idle for too long.
    //emit sendRequest(srv->newId(), "server.ping");
}
