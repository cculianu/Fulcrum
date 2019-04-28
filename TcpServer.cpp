#include "TcpServer.h"
#include <QCoreApplication>
#include <QtNetwork>

TcpServerError::~TcpServerError() {} // for vtable

TcpServer::TcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), IdMixin(newId()), addr(a), port(p)
{
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());
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
    const auto id = newId();
    auto ret = clientsById[id] = new Client(id, this, sock);
    // if deleted, we need to purge it from map
    auto on_destroyed = [id, this](QObject *o) {
        // this whole call is here so that delete client->sock ends up auto-removing the map entry
        // as a convenience.
        Debug() << __PRETTY_FUNCTION__ << " called";
        auto client = clientsById.take(id);
        if (client) {
            if (client != o) {
                Error() << " client != passed-in pointer to on_destroy in " << __FILE__ << " line " << __LINE__  << ". FIXME!";
            }
            Debug("client id %ld purged from map", long(id));
        }
    };
    connect(ret, &QObject::destroyed, this, on_destroyed);
    connect(ret, &AbstractClient::lostConnection, this, [this,id](AbstractClient *cl){
        if (auto client = dynamic_cast<Client *>(cl) ; client) {
            Debug() <<  client->prettyName() << " lost connection";
            killClient(client);
        } else {
            Error() << "Internal error: lostConnection callback received null client! (expected client id: " << id << ")";
        }
    });
    return ret;
}

void TcpServer::killClient(Client *client)
{
    if (!client)
        return;
    Debug() << __FUNCTION__ << " (id: " << client->id << ")";
    clientsById.remove(client->id); // ensure gone from map asap so future lookups fail
    client->boilerplate_disconnect();
}
void TcpServer::killClient(qint64 id)
{
    killClient(clientsById.take(id));
}


Client::Client(qint64 id, TcpServer *srv, QTcpSocket *sock)
    : AbstractClient(id, sock, /*maxBuffer=1MB*/1000000), srv(srv)
{
    Debug() << __PRETTY_FUNCTION__;
    socket = sock;
    on_connected();
}

Client::~Client()
{
    Debug() << __PRETTY_FUNCTION__;
    socket = nullptr; // NB: we are a child of socket. this line here is added in case some day I make AbstractClient delete socket on destruct.
}

void Client::on_readyRead()
{
    Debug() << prettyName() << " " << __FUNCTION__;
    while (socket->canReadLine()) {
        auto line = socket->readLine();
        nReceived = line.size();
        line = line.trimmed();
        Debug() << "Got line: " << line;
        lastGood = Util::getTime();
        send("Thanks fam.\n");
    }
    if (socket->bytesAvailable() > MAX_BUFFER) {
        // bad server.. sending us garbage data not containing newlines. Kill connection.
        Error() << QString("client has sent us more than %1 bytes without a newline! Bad client? (id: %2)").arg(MAX_BUFFER).arg(id);
        boilerplate_disconnect();
        status = Bad;
    }
}

void Client::boilerplate_disconnect()
{
    AbstractClient::boilerplate_disconnect();
    if (socket) socket->deleteLater(); // will implicitly delete this because we are a child of the socket
}

void Client::do_ping()
{
    send("Sup gee?\n");
}
