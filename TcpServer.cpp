#include "TcpServer.h"
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
    disconnect(this, SIGNAL(newConnection()), this, SLOT(on_newConnection()));
    close(); /// stop listening
    chan.put("finished");
    Debug() << __FUNCTION__ << " finished.";
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
    QString m;
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
}

void TcpServer::onMessage(qint64 clientId, const RPC::Message &m)
{
    Debug() << "onMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        if (m.method == "server.version") {
            QVariantList l = m.data.toList();
            if (l.size() == 2) {
                c->info.userAgent = l[0].toString();
                c->info.protocolVersion = l[1].toString();
                Debug() << "Client (id: " << c->id << ") sent version: \"" << c->info.userAgent << "\" / \"" << c->info.protocolVersion << "\"";
            } else {
                Error() << "Bad server version message! Schema should have handled this. FIXME! Json: " << m.toJsonString();
            }
            emit c->sendResult(m.id, m.method, QStringList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
        } else if (m.method == "server.ping") {
            if (m.jsonData.count("result")) {
                Debug() << "Got ping reply from client (id: " << c->id << ")";
            } else if (m.jsonData.count("params")) {
                Debug() << "Got ping from client (id: " << c->id << "), responding...";
                emit c->sendResult(m.id, m.method);
            } else {
                Error() << "Bad client ping message! Schema should have handled this. FIXME! Json: " << m.toJsonString();
            }
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
    emit sendRequest(srv->newId(), "server.ping");
}
