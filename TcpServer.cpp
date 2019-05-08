#include "TcpServer.h"
#include "Controller.h"
#include <QCoreApplication>
#include <QtNetwork>
#include <QString>
#include <QTextStream>
#include <QByteArray>
#include <QTextCodec>

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
                    Debug() << sockName << " " << line;
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
            Debug() << sockName << " wrote: " << bytes << " bytes";
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

TcpServer::TcpServer(const QHostAddress &a, quint16 p)
    : AbstractTcpServer(a, p)
{
    // re-set name for debug/logging
    _thread.setObjectName(prettyName());
    setObjectName(prettyName());

    setupMethods();
}

TcpServer::~TcpServer() { stop(); } // paranoia about pure virtual, and vtable consistency, etc

QString TcpServer::prettyName() const
{
    return QString("Tcp%1").arg(AbstractTcpServer::prettyName());
}

void TcpServer::on_started()
{
    AbstractTcpServer::on_started();
    conns.push_back(connect(this, &TcpServer::tellClientSpecRejected, this, &TcpServer::_tellClientSpecRejected));
    conns.push_back(connect(this, &TcpServer::tellClientSpecAccepted, this, &TcpServer::_tellClientSpecAccepted));
    conns.push_back(connect(this, &TcpServer::tellClientSpecPending, this, &TcpServer::_tellClientSpecPending));
}

void TcpServer::on_newConnection(QTcpSocket *sock) { newClient(sock); }

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
    QString m, p, p2;
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
        RPC::schemaMethodOptionalParams + QString(" { \"method\" : \"%1!\" } ").arg(m), // in schema, ping from client to us
        RPC::schemaResult + QString(" { \"result\" : null }"), // result schema -- 'result' arg should be there and be null.
        RPC::Schema() /* for now we never ping clients. */
    )));

    p = "{ \"amounts\" : [1], \"utxos\" : [{\"addr\" : \"x\", \"utxo\" : \"x\"}], \"shuffleAddr\" : \"x\", \"changeAddr\" : \"x\" }";
    p2 = "\"=1\""; // notification back to client is a single string -- either "pending" or "accepted" -- anything else is an error string.
    m = "shuffle.spec";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [%2] }").arg(m).arg(p), // in schema (asynch req)
        RPC::schemaResult + QString(" { \"result\" : \"ok!\" }"), // result schema -- 'result' arg should be there and be the string "ok". On error we send an error response
        RPC::schemaNotif + QString(" { \"method\" : \"%1!\", \"params\" : [%2] }").arg(m).arg(p2) // out schema (notification of status change)
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
            qint64 amt;
            amt = var.toLongLong(&ok);
            if (!ok || amt <= 0)
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
        if (refId != NO_ID)
            client->sendError(false, -290, reason, refId);
        else
            client->sendNotification("shuffle.spec", QVariantList({reason}));
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}
void TcpServer::_tellClientSpecAccepted(qint64 clientId, qint64 refId) {
    if (Client *client = getClient(clientId); client) {
        if (refId != NO_ID)
            client->sendResult(refId, "shuffle.spec", "accepted");
        else
            client->sendNotification("shuffle.spec", QVariantList({QString("accepted")}));
    } else {
        Debug() << "ClientId: " << clientId << " not found.";
    }
}
void TcpServer::_tellClientSpecPending(qint64 clientId, qint64 refId) {
    if (Client *client = getClient(clientId); client) {
        if (refId != NO_ID)
            client->sendResult(refId, "shuffle.spec", "pending");
        else
            client->sendNotification("shuffle.spec", QVariantList({QString("pending")}));
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
    // Don't send clients pings, because it's more trouble than it's worth.
    // Instead, rely on them to ping us else disconnect them if idle for too long.
    // The below just checks idle.
    if (Util::getTime() - lastGood >= pingtime_ms * 2) {
        Debug() << prettyName() << ": idle timeout after " << ((pingtime_ms*2.0)/1e3) << " sec., will close connection";
        emit sendError(true, -300, "Idle time exceeded");
        return;
    }
}
