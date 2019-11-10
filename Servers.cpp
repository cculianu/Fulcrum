#include "Servers.h"
#include <QCoreApplication>
#include <QtNetwork>
#include <QString>
#include <QTextStream>
#include <QByteArray>
#include <QTextCodec>
#include <QTimer>

#include <cstdlib>

TcpServerError::~TcpServerError() {} // for vtable

AbstractTcpServer::AbstractTcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), IdMixin(newId()), addr(a), port(p)
{
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());
}

AbstractTcpServer::~AbstractTcpServer()
{
    Debug() << __FUNCTION__;
    stop();
}

QString AbstractTcpServer::hostPort() const
{
    return QString("%1:%2").arg(addr.toString()).arg(port);
}

QString AbstractTcpServer::prettyName() const
{
    return QString("Srv %1 (id: %2)").arg(hostPort()).arg(id);
}

void AbstractTcpServer::tryStart()
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

void AbstractTcpServer::on_started()
{
    QString result = "ok";
    conns.push_back(connect(this, SIGNAL(newConnection()), this,SLOT(pvt_on_newConnection())));
    conns.push_back(connect(this, &QTcpServer::acceptError, this, [this](QAbstractSocket::SocketError e){ on_acceptError(e);}));
    if (!listen(addr, port)) {
        result = errorString();
        result = result.isEmpty() ? "Error binding/listening for connections" : result;
        Debug() << __FUNCTION__ << " listen failed";
    } else {
        Debug() << "started ok";
    }
    chan.put(result);
}

void AbstractTcpServer::on_finished()
{
    close(); /// stop listening
    chan.put("finished");
    Debug() << objectName() << " finished.";
    ThreadObjectMixin::on_finished();
}

void AbstractTcpServer::on_acceptError(QAbstractSocket::SocketError e)
{
    Error() << objectName() << "; error acceptError, code: " << int(e);
}

/*static*/
QString AbstractTcpServer::prettySock(QAbstractSocket *sock)
{
    return QString("%1:%2")
            .arg(sock ? sock->peerAddress().toString() : "(null)")
            .arg(sock ? sock->peerPort() : 0);
}

void AbstractTcpServer::pvt_on_newConnection()
{
    QTcpSocket *sock = nextPendingConnection();
    if (sock) {
        Debug() << "Got connection from: " << prettySock(sock);
        on_newConnection(sock);
    } else {
        Warning() << __FUNCTION__ << ": nextPendingConnection returned a nullptr! Called at the wrong time? FIXME!";
    }
}


SimpleHttpServer::SimpleHttpServer(const QHostAddress &listenAddr, quint16 listenPort, qint64 maxBuffer, qint64 timeLimit)
    : AbstractTcpServer(listenAddr, listenPort), MAX_BUFFER(maxBuffer > 0 ? maxBuffer : DEFAULT_MAX_BUFFER),
      TIME_LIMIT(timeLimit)
{
    // re-set name for debug/logging
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());
}

QString SimpleHttpServer::prettyName() const
{
    return QString("Http%1").arg(AbstractTcpServer::prettyName());
}

void SimpleHttpServer::on_newConnection(QTcpSocket *sock)
{
    sock->setReadBufferSize(MAX_BUFFER);
    const QString sockName(prettySock(sock));
    connect(sock, &QAbstractSocket::disconnected, this, [sock,sockName] {
        Debug() << sockName << " disconnected";
        sock->deleteLater();
    });
    connect(sock, &QObject::destroyed, this, [sockName](QObject *){
        Debug() << sockName << " destroyed";
    });
    connect(sock, &QAbstractSocket::readyRead, this, [sock,sockName,this] {
        try {
            while(sock->canReadLine()) {
                auto line = QString(sock->readLine()).trimmed();
                //Debug() << sockName << " Got line: " << line;
                if (QString loc = sock->property("req-loc").toString(); loc.isEmpty()) {
                    auto toks = line.split(" ");
                    if (toks.length() != 3 || (toks[0] != "GET" && toks[1] != "POST") || toks[2] != "HTTP/1.1")
                        throw Exception(QString("Invalid request: %1").arg(line));
                    Trace() << sockName << " " << line;
                    sock->setProperty("req-loc", toks[1]);
                    sock->setProperty("req-meth", toks[0]);
                    sock->setProperty("req-ver", toks[2]);
                } else if (auto loc = sock->property("req-loc").toString(),
                                meth = sock->property("req-meth").toString(),
                                ver = sock->property("req-ver").toString();
                            line.isEmpty() && !loc.isEmpty() && !meth.isEmpty() && !ver.isEmpty()) {
                    // got line by itself, prepare response
                    Request req;
                    auto & response = req.response;
                    req.httpVersion = ver;
                    req.method = meth == "GET" ? Method::GET : Method::POST;
                    auto vmap = sock->property("req-header").toMap();
                    for (auto it = vmap.begin(); it != vmap.end(); ++it)
                        // save header
                        req.header[it.key()] = it.value().toString();
                    if (auto i = loc.indexOf('?'); i > -1) {
                        req.queryString = loc.mid(i+1);
                        req.endPoint = loc.left(i);
                    } else
                        req.endPoint = loc;
                    if (auto it = endPoints.find(req.endPoint); it != endPoints.end() || (it=endPoints.find("*")) != endPoints.end()) {
                        it.value()(req); // call lambda
                    } else {
                        // could not find any enpoints that match, set up a 404 response
                        response.status = 404;
                        response.statusText = "Unknown resource";
                        response.data = err404Msg.toUtf8();
                    }
                    // setup header
                    QByteArray responseHeader;
                    {
                        QTextStream ss(&responseHeader, QIODevice::WriteOnly);
                        ss.setCodec(QTextCodec::codecForName("UTF-8"));
                        ss << "HTTP/1.1 " << response.status << " " << req.response.statusText.trimmed() << "\r\n";
                        ss << "Content-Type: " << response.contentType.trimmed() << "\r\n";
                        ss << "Content-Length: " << response.data.length() << "\r\n";
                        ss << response.headerExtra;
                        ss << "\r\n";
                    }
                    const qint64 respTotalLen = responseHeader.length() + response.data.length();
                    sock->setProperty("resp-len", respTotalLen);
                    // write out header
                    sock->write(responseHeader);
                    if (response.data.length())
                        // write out response data
                        sock->write(response.data);
                } else {
                    // save params
                    auto vmap = sock->property("req-header").toMap();
                    auto toks = line.split(": ");
                    if (toks.length() >= 2) {
                        auto name = toks.front(); toks.pop_front();
                        auto value = toks.join(": ");
                        vmap[name] = value;
                        sock->setProperty("req-header", vmap);
                    } else
                        throw Exception("garbage data, closing connection");
                }
            }

            if (sock->bytesAvailable() > MAX_BUFFER)
                throw Exception("too much data, closing connection");

        } catch (const std::exception &e) {
            Warning() << "Client: " << sockName << "; " << e.what();
            sock->abort();
            sock->deleteLater();
        }
    });
    connect(sock, &QAbstractSocket::bytesWritten, this, [sock, sockName](qint64 bytes) {
        qint64 nWrit = sock->property("resp-written").toLongLong() + bytes;
        sock->setProperty("resp-written", nWrit);
        auto var = sock->property("resp-len");
        if (const auto n2write = var.toLongLong(); !var.isNull() && nWrit >= n2write) {
            // graceful disconnect
            Debug() << sockName << " wrote " << nWrit << "/" << n2write << " bytes, disconnecting";
            sock->disconnectFromHost();
        } else {
            Trace() << sockName << " wrote: " << bytes << " bytes";
        }
    });
    if (TIME_LIMIT > 0) {
        QTimer::singleShot(TIME_LIMIT, sock, [sock, sockName, this]{
            Debug() << sockName << " killing connection after " << (TIME_LIMIT/1e3) << " seconds";
            sock->abort();
            sock->deleteLater();
        });
    }
}

void SimpleHttpServer::addEndpoint(const QString &endPoint, const Lambda &callback)
{
    if (!endPoint.startsWith("/") && endPoint != "*")
        Warning() << __FUNCTION__ << " endPoint " << endPoint << " does not start with '/' -- it will never be reached!  FIXME!";
    endPoints[endPoint] = callback;
}

Server::Server(const QHostAddress &a, quint16 p)
    : AbstractTcpServer(a, p)
{
    // re-set name for debug/logging
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());
    StaticData::init(); // only does something first time it's called, otherwise a no-op
}

Server::~Server() { stop(); } // paranoia about pure virtual, and vtable consistency, etc

QString Server::prettyName() const
{
    return QString("Tcp%1").arg(AbstractTcpServer::prettyName());
}

// this must be called in the thread context of this thread
QVariantMap Server::stats() const
{
    QVariantMap ret;
    ret["num_clients"] = clientsById.count();
    return ret;
}

void Server::on_started()
{
    AbstractTcpServer::on_started();
    conns.push_back(connect(this, &Server::tellClientScriptHashStatus, this, &Server::_tellClientScriptHashStatus));
}

void Server::on_newConnection(QTcpSocket *sock) { newClient(sock); }

Client *
Server::newClient(QTcpSocket *sock)
{
    const auto clientId = newId();
    auto ret = clientsById[clientId] = new Client(rpcMethods(), clientId, this, sock);
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
    connect(ret, &RPC::ConnectionBase::gotMessage, this, &Server::onMessage);
    connect(ret, &RPC::ConnectionBase::gotErrorMessage, this, &Server::onErrorMessage);
    connect(ret, &RPC::ConnectionBase::peerError, this, &Server::onPeerError);
    return ret;
}

void Server::killClient(Client *client)
{
    if (!client)
        return;
    Debug() << __FUNCTION__ << " (id: " << client->id << ")";
    clientsById.remove(client->id); // ensure gone from map asap so future lookups fail
    client->do_disconnect();
}
void Server::killClient(qint64 clientId)
{
    killClient(clientsById.take(clientId));
}
void Server::onMessage(qint64 clientId, const RPC::Message &m)
{
    Trace() << "onMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        auto member = StaticData::dispatchTable.value(m.method);
        if (!member)
            Error() << "Unknown method: \"" << m.method << "\". This shouldn't happen. FIXME! Json: " << m.toJsonString();
        else
            // call ptr to member
            (this->*member)(c, m);
    } else {
        Debug() << "Unknown client: " << clientId;
    }
}
void Server::onErrorMessage(qint64 clientId, const RPC::Message &m)
{
    Trace() << "onErrorMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        // we never expect client to send us errors. Always return invalid request, disconnect client.
        emit c->sendError(true, RPC::Code_InvalidRequest, "Not a valid request object");
    }
}
void Server::onPeerError(qint64 clientId, const QString &what)
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

// --- RPC METHODS ---
// checks to make sure we didn't make a typo inputting the above tables... called at class c'tor once globally.
void Server::rpc_server_version(Client *c, const RPC::Message &m)
{
    if (QVariantList l = m.paramsList(); m.isRequest() && l.size() == 2) {
        c->info.userAgent = l[0].toString();
        c->info.protocolVersion = l[1].toString();
        Trace() << "Client (id: " << c->id << ") sent version: \"" << c->info.userAgent << "\" / \"" << c->info.protocolVersion << "\"";
    } else {
        Error() << "Bad server version message! Other code should have handled this. FIXME! Json: " << m.toJsonString();
    }
    emit c->sendResult(m.id, m.method, QStringList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
}
void Server::rpc_server_ping(Client *c, const RPC::Message &m)
{
    if (m.isRequest()) {
        Trace() << "Got ping from client (id: " << c->id << "), responding...";
        emit c->sendResult(m.id, m.method);
    } else {
        Error() << "Bad client ping message! This shouldn't happen. FIXME! Json: " << m.toJsonString();
    }
}
void Server::rpc_blockchain_scripthash_subscribe(Client *c, const RPC::Message &m)
{
    if (QVariantList l = m.paramsList(); m.isRequest() && l.size() == 1) {
        // TESTING TODO FIXME THIS IS FOR TESTING ONLY
        const auto clientId = c->id;
        QByteArray sh = QByteArray::fromHex(l.front().toString().toUtf8());
        if (sh.length() != 32) {
            emit c->sendError(false, RPC::Code_InvalidParams, "Invalid scripthash", m.id);
            return;
        }
        emit tellClientScriptHashStatus(clientId, m.id, QByteArray(32, 0));
        QTimer *t = new QTimer(c);
        connect(t, &QTimer::timeout, this, [sh, clientId, this] {
            auto val = QRandomGenerator::global()->generate64();
            emit tellClientScriptHashStatus(clientId, RPC::Message::Id(), QByteArray(reinterpret_cast<char *>(&val), sizeof(val)), sh);
        });
        t->setSingleShot(false); t->start(3000);
    } else {
        Error() << "Bad subscribe message! This shouldn't happen. FIXME! Json: " << m.toJsonString();
    }
}
// --- Server::StaticData Definitions ---
#define HEY_COMPILER_PUT_STATIC_HERE(x) decltype(x) x
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::dispatchTable);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::methodMap);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::registry){
/*  ==> Note: Add stuff to this table when adding new RPC methods.
    { {"rpc.name",              allow_requests, allow_notifications, nPosArgs, (QSet<QString> note: {} means undefined optional)}, &method_to_call }     */
    { {"server.ping",                     true,               false,        0,      RPC::KeySet{} },          &Server::rpc_server_ping },
    { {"server.version",                  true,               false,        2,                    },          &Server::rpc_server_version },
    { {"blockchain.scripthash.subscribe", true,               false,        1,                    },          &Server::rpc_blockchain_scripthash_subscribe },
};
#undef HEY_COMPILER_PUT_STATIC_HERE
/*static*/
void Server::StaticData::init()
{
    if (!dispatchTable.empty())
        return;
    for (const auto & r : registry) {
        if (!r.member) {
            Error() << "Runtime check failed: RPC Method " << r.method << " has a nullptr for its .member! See Server class! FIXME!";
            std::_Exit(EXIT_FAILURE);
        }
        methodMap[r.method] = r;
        dispatchTable[r.method] = r.member;
    }
}
// --- /Server::StaticData Definitions ---
// --- /RPC METHODS ---


void Server::_tellClientScriptHashStatus(qint64 clientId, const RPC::Message::Id & refId, const QByteArray & status, const QByteArray & scriptHash)
{
    if (Client *client = getClient(clientId); client) {
        if (scriptHash.isEmpty())
            // immediate scripthash status result
            client->sendResult(refId, "blockchain.scripthash.subscribe", status.toHex());
        else {
            // notification, no id.
            client->sendNotification("blockchain.scripthash.subscribe", {scriptHash.toHex(), status.toHex()});
        }
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}

Client::Client(const RPC::MethodMap & mm, qint64 id_in, Server *srv, QTcpSocket *sock)
    : RPC::LinefeedConnection(mm, id_in, sock, /*maxBuffer=4MB*/4000000), srv(srv)
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
    // Don't send clients pings.
    // Instead, rely on them to ping us else disconnect them if idle for too long.
    // The below just checks idle.
    if (Util::getTime() - lastGood >= stale_threshold) {
        Debug() << prettyName() << ": idle timeout after " << ((stale_threshold)/1e3) << " sec., will close connection";
        emit sendError(true, RPC::Code_Custom+1, "Idle time exceeded");
        return;
    }
}
