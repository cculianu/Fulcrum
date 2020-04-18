//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Servers.h"

#include "App.h"
#include "BitcoinD.h"
#include "BTC_Address.h"
#include "Merkle.h"
#include "PeerMgr.h"
#include "ServerMisc.h"
#include "SrvMgr.h"
#include "Storage.h"
#include "SubsMgr.h"
#include "ThreadPool.h"
#include "WebSocket.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QtNetwork>
#include <QString>
#include <QTextCodec>
#include <QTextStream>
#include <QTimer>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <list>
#include <utility>

TcpServerError::~TcpServerError() {} // for vtable

AbstractTcpServer::AbstractTcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), IdMixin(newId()), addr(a), port(p)
{
    assert(qobj()); // Runtime check that derived class followed the rules outlined at the top of Mixins.h
    resetName();
}

void AbstractTcpServer::resetName()
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
    return QStringLiteral("%1:%2").arg(addr.toString()).arg(port);
}

QString AbstractTcpServer::prettyName() const
{
    return QStringLiteral("Srv %1").arg(hostPort());
}

void AbstractTcpServer::tryStart(ulong timeout_ms)
{
    if (!_thread.isRunning()) {
        ThreadObjectMixin::start(); // call super
        Log() << "Starting listener service for " << prettyName() << " ...";
        if (auto result = chan.get<QString>(timeout_ms); result != "ok") {
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
        result = result.isEmpty() ? "Error binding/listening for connections" : QString("Could not bind to %1: %2").arg(hostPort()).arg(result);
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
    unsigned ctr = 0;
    // from Qt docs: it's possible for more than 1 connection to be ready on a signal emission of nextPendingConnection
    // if we are at or above maxPendingConnections() on a QTcpServer, so we do this: grab as many connections as we can
    // at once in a loop.
    for (QTcpSocket *sock = nullptr; (sock = nextPendingConnection()); ++ctr) {
        Debug() << "Got connection from: " << prettySock(sock);
        on_newConnection(sock);
        // The below is to prevent malicious clients from choking the event loop.
        // We only process 10 connections at a time, then call ourselves again asynchronously.
        if (ctr >= 9 && hasPendingConnections()) {
            Warning() << __func__ << ": nextPendingConnection yielding to event loop after 10 connections processed, will try again shortly.";
            Util::AsyncOnObject(this, [this]{pvt_on_newConnection();});
            return;
        }
    }
}


SimpleHttpServer::SimpleHttpServer(const QHostAddress &listenAddr, quint16 listenPort, qint64 maxBuffer, qint64 timeLimit)
    : AbstractTcpServer(listenAddr, listenPort), MAX_BUFFER(maxBuffer > 0 ? maxBuffer : DEFAULT_MAX_BUFFER),
      TIME_LIMIT(timeLimit)
{
    // re-set name for debug/logging
    resetName();
}

QString SimpleHttpServer::prettyName() const
{
    return QStringLiteral("Http%1").arg(AbstractTcpServer::prettyName());
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
                    auto toks = line.split(' ');
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
                    auto toks = line.split(QStringLiteral(": "));
                    if (toks.length() >= 2) {
                        auto name = toks.front(); toks.pop_front();
                        auto value = toks.join(QStringLiteral(": "));
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


// ---- Classes Server & Client ----

// class Server constants
namespace {
    // TODO: maybe move these to a more global place? For now here is fine.
    namespace Constants {
        constexpr int kMaxServerVersionLen = 80,  ///< the maximum server version length we accept to prevent memory exhaustion attacks
                      kMaxTxHex = 2*1024*1024, ///< >1MB raw tx max (over 1 MiB, 1 traditional PoT MB should be enough).
                      kMaxErrorCount = 10; ///< The maximum number of errors we tolerate from a Client before disconnecting them.

        // types in a Message.params object that we accept as booleans
        const std::set<QVariant::Type> acceptableBoolVariantTypes = {
            QVariant::Type::Bool, QVariant::Type::Int, QVariant::Type::UInt, QVariant::Type::LongLong,
            QVariant::Type::ULongLong, QVariant::Type::Double,
        };

    }
    using namespace Constants;

    std::pair<bool, bool> parseBoolSemiLooselyButNotTooLoosely(const QVariant &v) {
        std::pair<bool, bool> ret{false, false};
        if (acceptableBoolVariantTypes.count(v.type()))
            ret = {v.toBool(), true};
        return ret;
    }

    QString formatBitcoinDErrorResponseToLookLikeDumbElectrumXPythonRepr(const RPC::Message &errResponse){
        constexpr auto escapeSingleQuote = [](const QString &s) -> QString {
            const QByteArray b = s.toUtf8();
            QByteArray ret;
            ret.reserve(int(b.length()*1.5));
            bool inesc = false;
            for (int i = 0; i < b.size(); ++i) {
                const char c = b[i];
                if (c == '\\')
                    inesc = !inesc;
                else if (c == '\'' && !inesc)
                    ret.push_back('\\');
                else
                    inesc = false;
                ret.push_back(c);
            }
            return QString::fromUtf8(ret);
        };
        return QStringLiteral("daemon error: DaemonError({'code': %1, 'message': '%2'})")
                .arg(errResponse.errorCode()).arg(escapeSingleQuote(errResponse.errorMessage()));
    }

    /// used internally by RPC methods. Given a hashHex, ensure it's 32 bytes (or DataLen) of hash data and nothing else.
    /// Returns DataLen (default=32) bytes of valid hex decoded data or an empty QByteArray on failure.
    QByteArray validateHashHex(const QString & hashHex, const int DataLen = HashLen) {
        QByteArray ret = hashHex.trimmed().left(DataLen*2).toUtf8();
        // ugh, QByteArray returns dummy bytes at the end if it can't fully parse. So we have to check the original
        // hash byte length as well.
        if (ret.length() != DataLen*2 || (ret = QByteArray::fromHex(ret)).length() != DataLen)
            ret.clear();
        return ret;
    }
}

ServerBase::ServerBase(SrvMgr *sm,
                       const RPC::MethodMap & methods, const DispatchTable & dispatchTable,
                       const QHostAddress & a, quint16 p, const std::shared_ptr<const Options> & opts,
                       const std::shared_ptr<Storage> & st, const std::shared_ptr<BitcoinDMgr> & bdm)
    : AbstractTcpServer(a, p), srvmgr(sm), methods(methods), dispatchTable(dispatchTable), options(opts), storage(st), bitcoindmgr(bdm)
{
}
ServerBase::~ServerBase() { stop(); }

// this must be called in the thread context of this thread
QVariant ServerBase::stats() const
{
    QVariantMap m;
    m["numClients"] = clientsById.count();
    QVariantList clientList;
    for (const auto & client : clientsById) {
        // note we call this thread-unsafe function stats() here because client lives in our thread. but if that design
        // changes, update this to call client->statsSafe(100) instead
        auto map = client->stats().toMap();
        auto name = map.take("name").toString();
        map["version"] = QVariantList({client->info.uaVersion().toString(), client->info.protocolVersion.toString()});
        map["userAgent"] = client->info.userAgent;
        map["errCt"] = client->info.errCt;
        map["nRequestsRcv"] = client->info.nRequestsRcv;
        map["isSubscribedToHeaders"] = client->isSubscribedToHeaders;
        map["nSubscriptions"] = client->nShSubs.load();
        map["nTxSent"] = client->info.nTxSent;
        map["nTxBytesSent"] = client->info.nTxBytesSent;
        map["nTxBroadcastErrors"] = client->info.nTxBroadcastErrors;
        // data from the per-ip structure
        {
            QVariantMap m;
            m["nClients"] = qlonglong(client->perIPData->nClients.load());
            m["nSubscriptions"] = qlonglong(client->perIPData->nShSubs.load());
            m["nBitcoinDRequests"] = qlonglong(client->perIPData->bdReqCtr_cum.load());
            m["isWhiteListed"] = client->perIPData->isWhitelisted();
            map["perIPData"] = m;
        }
        // the below don't really make much sense for this class (they are always 0 or empty)
        map.remove("nDisconnects");
        map.remove("nSocketErrors");
        map.remove("lastSocketError");
        map.remove("nUnansweredRequests");
        map.remove("nRequestsSent");
        clientList.append(QVariantMap({{name, map}}));
    }
    m["clients"] = clientList;
    return QVariantMap{{prettyName(), m}};
}

void ServerBase::on_started()
{
    AbstractTcpServer::on_started();

    // refresh bitcionD version info, server version & subversion, whenever it comes back (in case user upgraded bitcoind from under our feet!)
    conns += connect(bitcoindmgr.get(), &BitcoinDMgr::gotFirstGoodConnection, this, &ServerBase::refreshBitcoinDNetworkInfo);
    // try and refresh once now as soon as we come alive (usually we don't come alive until bitcoind connections are established so this is ok)
    refreshBitcoinDNetworkInfo();
}

void ServerBase::on_newConnection(QTcpSocket *sock) {
    if (!sock) // paranoia
        return;
    if (sock->state() == QAbstractSocket::SocketState::ConnectedState) {
        newClient(sock);
    } else {
        Debug() << "Got a connection from " << sock->peerAddress().toString()
                << ", but before we could handle it, it was closed; deleting socket and ignoring.";
        sock->deleteLater();
    }
}

// -- Client :: PerIPDataHolder_Temp
Client::PerIPDataHolder_Temp::PerIPDataHolder_Temp(std::shared_ptr<Client::PerIPData> && ref, QTcpSocket *socket)
    : QObject(socket), perIPData(std::move(ref))
{
    setObjectName(kName);
    if (perIPData) ++perIPData->nClients;
}
Client::PerIPDataHolder_Temp::~PerIPDataHolder_Temp() { if (perIPData) --perIPData->nClients; }
/*static*/
std::shared_ptr<Client::PerIPData> Client::PerIPDataHolder_Temp::take(QTcpSocket *s)
{
    std::shared_ptr<PerIPData> ret;
    /* We use a recursive search for the PerIPData because in the WebSocket::Wrapper case, it may live in
     * the nested wrapped QTcpSocket child of `s` */
    auto holder = s->findChild<PerIPDataHolder_Temp *>(kName, Qt::FindChildrenRecursively);
    if (holder) {
        // transfer ownership.
        ret.swap(holder->perIPData);
        holder->deleteLater();
    }
    return ret;
}
// -- /Client :: PerIPDataHolder_Temp

bool ServerBase::attachPerIPDataAndCheckLimits(QTcpSocket *socket)
{
    bool ok = true;
    if (const auto addr = socket->peerAddress(); LIKELY(!addr.isNull())) {
        auto holder = new Client::PerIPDataHolder_Temp(srvmgr->getOrCreatePerIPData(addr), socket);
        const auto maxPerIP = options->maxClientsPerIP;
        // check limit immediately
        if (maxPerIP > 0 && !holder->perIPData->isWhitelisted() && holder->perIPData->nClients > maxPerIP) {
            // reject connection here
            Log() << "Connection limit (" << maxPerIP << ") exceeded for " << addr.toString() << ", connection refused";
            ok = false;
        }
    } else {
        // this should never happen
        Error() << "INTERNAL ERROR: could not create per-IP data object in ServerBase::incomingConnection -- invalid peer address!";
        ok = false;
    }
    if (!ok) {
        socket->abort();
        socket->deleteLater();
    }
    return ok;
}

/// Used internally by both this incomingConnection implementation and ServerSSL's implementation.
/// SockType must be QTcpSocket or QSslSocket.
template <typename SockType, typename /* enable if .. */>
SockType *ServerBase::createSocketFromDescriptorAndCheckLimits(qintptr socketDescriptor)
{
    auto socket = new SockType(this);
    if (!socket->setSocketDescriptor(socketDescriptor)) {
        /// This won't ever happen unless somehow this class or a derived class ends up being radically misused.
        /// It means the socket engine doesn't recognize the fd.  We added this here simply for defensive programming.
        Error() << __func__ << ": setSocketDescriptor returned false! Socket fd will now leak. Error was: " << socket->errorString();
        delete socket;
        return nullptr;
    }
    // we do this thing here to check connection limits as early as possible in the connection pipeline
    if (!attachPerIPDataAndCheckLimits(socket))
        // called function already called socekt->deleteLater() for us in this branch.
        return nullptr;
    return socket;
}
bool ServerBase::startWebSocketHandshake(QTcpSocket *socket)
{
    auto ws = new WebSocket::Wrapper(socket, this); // <--- the wrapper `ws` becomes parent of the socket, and `this` is now parent of the wrapper.
    assert(socket->parent() == ws);
    // do not access `socket` below this line, use `ws` instead.
    auto tmpConnections = std::make_shared<QList<QMetaObject::Connection>>();
    *tmpConnections += connect(ws, &WebSocket::Wrapper::handshakeSuccess, this, [this, ws, tmpConnections] {
        for (const auto & conn : *tmpConnections)
            disconnect(conn);
        addPendingConnection(ws);
        emit newConnection(); // <-- we must emit here because we went asynch and are doing this 'some time later', and the calling code emitted a spurous newConnection() on our behalf previously.. and this is the *real* newConnection()
    });
    const auto peerName = ws->peerAddress().toString() + ":" + QString::number(ws->peerPort());
    *tmpConnections += connect(ws, &WebSocket::Wrapper::handshakeFailed, this, [ws, peerName](const QString &reason) {
        Warning() << "WebSocket handshake failed for " << peerName << ", reason: " << (reason.length() > 60 ? (reason.left(49) + QStringLiteral(u"…") + reason.right(10)) : reason);
        ws->deleteLater();
    });
    if (!ws->startServerHandshake()) {
        // This shouldn't normally happen unless we somehow misuse the WebSocket::Wrapper class in some future use of this code.
        Error() << "Unable to start WebSocket handshake for " << peerName << ", closing socket";
        delete ws; ws = nullptr;
        return false;
    }
    return true;
}
void ServerBase::incomingConnection(qintptr socketDescriptor)
{
    auto socket = createSocketFromDescriptorAndCheckLimits<QTcpSocket>(socketDescriptor);
    if (!socket)
        // low-level error, fail. Error was already logged.
        return;

    if (!usesWS) {
        // Classic non-WebSocket mode.  We are done; enqueue the connection.
        // `newConnection` signal will be emitted for us by the calling code in QAbstractSocket when we return.
        addPendingConnection(socket);
        return;
    }

    // WebSockets mode -- create the wrapper object and further negotiate the handshake.  Later on newConnection() will
    // be emitted again on success, or the socket will be auto-deleted on failure.
    startWebSocketHandshake(socket);
}

Client *
ServerBase::newClient(QTcpSocket *sock)
{
    const auto clientId = newId();
    auto ret = clientsById[clientId] = new Client(rpcMethods(), clientId, sock, options->maxBuffer.load());
    const auto addr = ret->peerAddress();

    ret->perIPData = Client::PerIPDataHolder_Temp::take(sock); // take ownership of the PerIPData ref, implicitly delete the temp holder attacked to the socket
    if (UNLIKELY(!ret->perIPData)) {
        // This branch should never happen.  But we left it in for defensive programming.
        Error() << "INTERNAL ERROR: Tcp Socket " << sock->peerAddress().toString() << ":" << sock->peerPort() << " had no PerIPData! FIXME!";
        // FUDGE it.
        ret->perIPData = srvmgr->getOrCreatePerIPData(addr);
        ++ret->perIPData->nClients; // increment client counter now
    }
    assert(ret->perIPData);

    // if deleted, we need to purge it from map
    const auto on_destructing = [clientId, addr, this](Client *c) {
        // this whole call is here so that delete client->sock ends up auto-removing the map entry
        // as a convenience.
        Debug() << "Client " << clientId << " destructing";
        if (const auto client = clientsById.take(clientId); client) {
            // purge from map
            if (UNLIKELY(client != c))
                Error() << " client != passed-in pointer to on_destroy in " << __FILE__ << " line " << __LINE__  << " client " << clientId << ". FIXME!";
            Debug() << "client id " << clientId << " purged from map";
        }
        assert(c->perIPData);
        if (UNLIKELY(c->nShSubs < 0))
            Error() << "nShSubs for client " << c->id << " is " << c->nShSubs << ". FIXME!";
        // decrement per-IP subs ctr for this client.
        const auto nSubsIP = c->perIPData->nShSubs -= c->nShSubs;
        if (UNLIKELY(nSubsIP < 0))
            Error() << "nShSubs for IP " << addr.toString() << " is " << nSubsIP << ". FIXME!";
        if (nSubsIP == 0 && c->nShSubs)
            Debug() << "PerIP: " << addr.toString() << " is no longer subscribed to any scripthashes";
        --c->perIPData->nClients; // decrement client counter
        // tell SrvMgr this client is gone so it can decrement its clients-per-ip count.
        emit clientDisconnected(clientId, addr);
    };
    assert(ret->thread() == this->thread()); // the DirectConnection below requires this client to live in the same thread as us. Which is always the case.
    connect(ret, &Client::clientDestructing, this, on_destructing, Qt::DirectConnection);
    connect(ret, &AbstractConnection::lostConnection, this, [this, clientId](AbstractConnection *cl){
        if (auto client = dynamic_cast<Client *>(cl) ; client) {
            Debug() <<  client->prettyName() << " lost connection";
            killClient(client);
        } else {
            Debug() << "lostConnection callback received null client! (expected client id: " << clientId << ")";
        }
    });
    connect(ret, &RPC::ConnectionBase::gotMessage, this, &ServerBase::onMessage);
    connect(ret, &RPC::ConnectionBase::gotErrorMessage, this, &ServerBase::onErrorMessage);
    connect(ret, &RPC::ConnectionBase::peerError, this, &ServerBase::onPeerError);

    // tell SrvMgr about this client so it can keep track of clients-per-ip and other statistics, and potentially
    // kick the client if it exceeds its connection limit.
    emit clientConnected(clientId, addr);

    return ret;
}

void ServerBase::killClient(Client *client)
{
    if (!client)
        return;
    Debug() << __func__ << " (id: " << client->id << ")";
    clientsById.remove(client->id); // ensure gone from map asap so future lookups fail
    client->do_disconnect();
}
// public slot
void ServerBase::killClient(IdMixin::Id clientId)
{
    killClient(clientsById.take(clientId));
}
// public slot
void ServerBase::killClientsByAddress(const QHostAddress &address)
{
    std::list<Client *> clientsMatched;
    int ctr = 0;
    for (auto it = clientsById.begin(); it != clientsById.end(); ++it) {
        if (auto client = it.value(); client->peerAddress() == address)
            clientsMatched.push_back(client); // save to list so as to not mutate hashtable while iterating...
    }
    for (auto & client : clientsMatched) {
        killClient(client);
        ++ctr;
    }
    if (ctr)
        Debug() << "Killed " << ctr << Util::Pluralize(" client", ctr) << " matching address: " << address.toString();
}
// public slot
void ServerBase::applyMaxBufferToAllClients(int newMax)
{
    if (!Options::isMaxBufferSettingInBounds(newMax))
        return;
    newMax = Options::clampMaxBufferSetting(newMax);
    int ctr = 0;
    for (auto & client : clientsById) {
        client->setMaxBuffer(newMax);
        ++ctr;
    }
    Debug() << "Applied new max_buffer setting of " << newMax << " to " << ctr << Util::Pluralize(" client", ctr);
}


void ServerBase::onMessage(IdMixin::Id clientId, const RPC::Message &m)
{
    Trace() << "onMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        const auto member = dispatchTable.value(m.method);
        if (!member)
            Error() << "Unknown method: \"" << m.method << "\". This shouldn't happen. FIXME! Json: " << m.toJsonString();
        else {
            // indicate a good request, accepted request
            ++c->info.nRequestsRcv;
            try {
                // call ptr to member -- note member is free to throw if it wants to send an error immediately
                (this->*member)(c, m);
            } catch (const RPCError & e) {
                emit c->sendError(e.disconnect, e.code, e.what(), m.id);
            } catch (const std::exception & e) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError,
                                  QString("internal error: %1").arg(e.what()),  m.id);
            } catch (...) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError, "internal error: unknown", m.id);
            }
        }
    } else {
        Debug() << "Unknown client: " << clientId;
    }
}
void ServerBase::onErrorMessage(IdMixin::Id clientId, const RPC::Message &m)
{
    Trace() << "onErrorMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        // we never expect client to send us errors. Always return invalid request, disconnect client.
        emit c->sendError(true, RPC::Code_InvalidRequest, "Not a valid request object");
    }
}
void ServerBase::onPeerError(IdMixin::Id clientId, const QString &what)
{
    Debug() << "onPeerError, client " << clientId << " error: " << what;
    if (Client *c = getClient(clientId); c) {
        if (++c->info.errCt - c->info.nRequestsRcv >= kMaxErrorCount) {
            Warning() << "Excessive errors (" << kMaxErrorCount << ") for: " << c->prettyName() << ", disconnecting";
            killClient(c);
            return;
        }
    }
}

void ServerBase::refreshBitcoinDNetworkInfo()
{
    bitcoindmgr->submitRequest(this, newId(), "getnetworkinfo", QVariantList(),
        // success
        [this](const RPC::Message & reply) {
            const QVariantMap networkInfo = reply.result().toMap();
            bool ok = false;
            const auto val = networkInfo.value("version", 0).toUInt(&ok);
            if (ok) {
                // e.g. 0.20.6 comes in like this from bitcoind (as an unsigned int): 200600
                bitcoinDInfo.version = Version(val, Version::BitcoinD);
                //Debug() << "Refreshed version info from bitcoind";
            } else {
                Warning() << "Failed to get version info from bitcoind";
            }
            bitcoinDInfo.relayFee = networkInfo.value("relayfee", 0.0).toDouble();
            bitcoinDInfo.subversion = networkInfo.value("subversion", "").toString();
            bitcoinDInfo.warnings = networkInfo.value("warnings", "").toString();
        });
}

void ServerBase::onPeersUpdated(const PeerInfoList &pl)
{
    peers = pl;
}

// --- RPC METHODS ---
namespace {
    ThreadPool::FailFunc defaultTPFailFunc(Client *c, const RPC::Message::Id &id) {
        return [c, id](const QString &what) {
            emit c->sendError(false, RPC::Code_InternalError, QString("internal error: %1").arg(what), id);
        };
    }
    BitcoinDMgr::FailF defaultBDFailFunc(Client *c, const RPC::Message::Id &id) {
        return [c, id](const RPC::Message::Id &, const QString &what) {
            c->bdReqCtr -= std::min(c->bdReqCtr, 1LL); // decrease throttle counter (per-client, owned by this thread)
            --c->perIPData->bdReqCtr; // decrease bitcoind request counter (per-IP, owned by multiple threads)
            emit c->sendError(false, RPC::Code_InternalError, QString("internal error: %1").arg(what), id);
        };
    }
}

ServerBase::RPCError::~RPCError() {}
ServerBase::RPCErrorWithDisconnect::~RPCErrorWithDisconnect() {}

void ServerBase::generic_do_async(Client *c, const RPC::Message::Id &reqId, const std::function<QVariant ()> &work, int priority)
{
    if (LIKELY(work)) {
        struct ResErr {
            QVariant results;
            bool error = false, doDisconnect = false;
            QString errMsg;
            int errCode = 0;
        };

        auto reserr = std::make_shared<ResErr>(); ///< shared with lambda for both work and completion. this is how they communicate.

        (asyncThreadPool ? asyncThreadPool : ::AppThreadPool())->submitWork(
            c, // <--- all work done in client context, so if client is deleted, completion not called
            // runs in worker thread, must not access anything other than reserr and work
            [reserr,work]{
                try {
                    QVariant result = work();
                    reserr->results.swap( result ); // constant-time copy
                } catch (const RPCError & e) {
                    reserr->error = true;
                    reserr->doDisconnect = e.disconnect;
                    reserr->errMsg = e.what();
                    reserr->errCode = e.code;
                }
            },
            // completion: runs in client thread (only called if client not already deleted)
            [c, reqId, reserr] {
                if (reserr->error) {
                    emit c->sendError(reserr->doDisconnect, reserr->errCode, reserr->errMsg, reqId);
                    return;
                }
                // no error, send results to client
                emit c->sendResult(reqId, reserr->results);
            },
            // default fail function just sends json rpc error "internal error: <message>"
            defaultTPFailFunc(c, reqId),
            // lower is sooner, higher is later. Default 0.
            priority
        );
    } else
        Error() << "INTERNAL ERROR: work must be valid! FIXME!";
}

void ServerBase::generic_async_to_bitcoind(Client *c, const RPC::Message::Id & reqId, const QString &method,
                                           const QVariantList & params,
                                           const BitcoinDSuccessFunc & successFunc,
                                           const BitcoinDErrorFunc & errorFunc)
{
    if (UNLIKELY(QThread::currentThread() != c->thread())) {
        // Paranoia, in case I or a future programmer forgets this rule.
        Warning() << __FUNCTION__ << " is meant to be called from the Client thread only. The current thread is not the"
                  << " Client thread. This may cause problems if the Client is deleted while submitting the request. FIXME!";
    }
    // Throttling support
    {
        const int bdReqHi = options->bdReqThrottleParams.load().hi;
        ++c->perIPData->bdReqCtr; // increase bitcoind request counter (per-IP, owned by multiple threads)
        ++c->perIPData->bdReqCtr_cum; // increase cumulative bitcoind request counter (per-IP, owned by multiple threads)
        if (++c->bdReqCtr/*<- incr. per-client counter*/ >= bdReqHi && !c->isReadPaused()) {
            Debug() << c->prettyName() << " has bitcoinD req ctr: " << c->bdReqCtr << " (PerIP ctr: "
                    << c->perIPData->bdReqCtr << "), PAUSING reads from socket";
            c->setReadPaused(true); // pause reading from this client -- they exceeded threshold.
            // if timer not already active, start timer to decay ctr over time --
            constexpr auto kTimerName = "+BDR_DecayTimer";
            static constexpr int kPollFreqHz = 5; //<-- we "poll" 5 times per second so as to detect situations where bitcoind is faster than our heuristics estimate it to be, and then wake up clients faster in that case
            static_assert (kPollFreqHz > 0 && kPollFreqHz <= 100); // for sanity
            c->callOnTimerSoon(1000/kPollFreqHz /*=200ms*/, kTimerName, [c, this, iCtr=unsigned(0)]() mutable {
                const auto [bdReqHi, bdReqLo, decayPerSec] = options->bdReqThrottleParams.load();
                if ((++iCtr % kPollFreqHz) == 0) // every kPollFreqHz iterations = every 1 second, decay the counter by decayPerSec amount
                    c->bdReqCtr -= std::min(qint64(decayPerSec), c->bdReqCtr);
                if (c->isReadPaused() && c->bdReqCtr <= bdReqLo) {
                    Debug() << c->prettyName() << " has bitcoinD req ctr: " << c->bdReqCtr  << " (PerIP ctr: "
                            << c->perIPData->bdReqCtr << "), RESUMING reads from socket";
                    c->setReadPaused(false);
                }
                return c->bdReqCtr > 0; // return false when ctr reaches 0, which stops the recurring decay timer
            });
        }
    }
    // /Throttling support
    bitcoindmgr->submitRequest(c, newId(), method, params,
        // success
        [c, reqId, successFunc](const RPC::Message & reply) {
            c->bdReqCtr -= std::min(c->bdReqCtr, 1LL); // decrease throttle counter
            --c->perIPData->bdReqCtr; // decrease bitcoind request counter (per-IP, owned by multiple threads)
            try {
                const QVariant result = successFunc ? successFunc(reply) : reply.result(); // if no successFunc specified, use default which just copies the result to the client.
                emit c->sendResult(reqId, result);
            } catch (const RPCError &e) {
                emit c->sendError(e.disconnect, e.code, e.what(), reqId);
            } catch (const std::exception &e) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError, e.what(), reqId);
            }
        },
        // error
        [c, reqId, errorFunc](const RPC::Message & errorReply) {
            c->bdReqCtr -= std::min(c->bdReqCtr, 1LL); // decrease throttle counter
            --c->perIPData->bdReqCtr; // decrease bitcoind request counter (per-IP, owned by multiple threads)
            try {
                if (errorFunc)
                    errorFunc(errorReply); // this should throw RPCError
                throw RPCError(errorReply.errorMessage(), RPC::Code_App_DaemonError);
            } catch (const RPCError &e) {
                emit c->sendError(e.disconnect, e.code, e.what(), reqId);
            } catch (const std::exception &e) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError, QString("internal error: %1").arg(e.what()),
                                  reqId);
            }
        },
        // use default function on failure, sends json rpc error "internal error: <message>"
        defaultBDFailFunc(c, reqId)
    );
}

Server::Server(SrvMgr *sm, const QHostAddress &a, quint16 p, const std::shared_ptr<const Options> & opts,
               const std::shared_ptr<Storage> &s, const std::shared_ptr<BitcoinDMgr> &bdm)
    : ServerBase(sm, StaticData::methodMap, StaticData::dispatchTable, a, p, opts, s, bdm)
{
    StaticData::init(); // only does something first time it's called, otherwise a no-op
    // re-set name for debug/logging
    resetName();
    setMaxPendingConnections(std::max(options->maxPendingConnections, options->minMaxPendingConnections)); // default in Options is 60 pending connections
}

Server::~Server() { stop(); }

QString Server::prettyName() const
{
    return (usesWS ? QStringLiteral("Ws%1") : QStringLiteral("Tcp%1")).arg(AbstractTcpServer::prettyName());
}

void Server::rpc_server_add_peer(Client *c, const RPC::Message &m)
{
    const auto map = m.paramsList().front().toMap();
    if (map.isEmpty())
        throw RPCError(QString("%1 expected a non-empty dictionary argument").arg(m.method));
    bool retval = true;
    try {
        const auto peerList = PeerInfo::fromFeaturesMap(map); // this may throw BadFeaturesMap
        if (peerList.isEmpty() || peerList.front().genesisHash != storage->genesisHash())
            throw BadFeaturesMap("Incompatible genesis hash");
        const auto peerAddress = c->peerAddress();
        Debug() << "add_peer tentatively accepted for host " << peerList.front().hostName << " (" << peerList.size() << ")" << " from " << peerAddress.toString();
        emit gotRpcAddPeer(peerList, peerAddress);
    } catch (const BadFeaturesMap & e) {
        const auto hm = map.value("hosts").toMap();
        const QString hostNamePart = !hm.isEmpty() ? QString(" (%1)").arg(hm.firstKey()) : QString();
        Debug() << "Refusing add_peer" << hostNamePart << " for reason: " << e.what();
        retval = false;
    }
    emit c->sendResult(m.id, retval);

}
void Server::rpc_server_banner(Client *c, const RPC::Message &m)
{
    constexpr int MAX_BANNER_DATA = 16384;
    static const QString bannerFallback = QString("Connected to a %1 server").arg(ServerMisc::AppSubVersion);
    const QString bannerFile(c->peerAddress().isLoopback() && !options->torBannerFile.isEmpty()
                             ? options->torBannerFile : options->bannerFile);
    if (bannerFile.isEmpty() || !QFile::exists(bannerFile) || !QFileInfo(bannerFile).isReadable()) {
        // fallback -- banner file invalid/not readable/not specified
        emit c->sendResult(m.id, bannerFallback);
    } else {
        // banner file specified, now let's open it up in a worker thread to keep the server responsive and return immediately
        generic_do_async(c, m.id,
                        [bannerFile,
                         donationAddress = options->donationAddress,
                         daemonVersion = bitcoinDInfo.version,
                         subversion = bitcoinDInfo.subversion] {
                QVariant ret;
                QFile bf(bannerFile);
                if (QByteArray bannerFileData;
                        !bf.open(QIODevice::ReadOnly) || ((bannerFileData = bf.read(MAX_BANNER_DATA)).isEmpty()
                                                          && bf.error() != QFile::FileError::NoError))
                {
                    // error reading banner file, just send the fallback
                    ret = bannerFallback;
                } else {
                    // read banner file ok, perform variable substitutions
                    ret = QString::fromUtf8(bannerFileData)
                            .replace("$SERVER_VERSION", ServerMisc::AppVersion)
                            .replace("$SERVER_SUBVERSION", ServerMisc::AppSubVersion)
                            .replace("$DONATION_ADDRESS", donationAddress)
                            .replace("$DAEMON_VERSION", daemonVersion.toString(true))
                            .replace("$DAEMON_SUBVERSION", subversion)
                            .left(MAX_BANNER_DATA); ///< Note this ".left()" is really not in bytes but unicode codepoints, that's fine, the limit is a soft limit
                }
                // send result to client (either the fallback or the real deal)
                return ret;
        });
    }
}
void Server::rpc_server_donation_address(Client *c, const RPC::Message &m)
{
    emit c->sendResult(m.id, options->donationAddress);
}
/* static */
QVariantMap Server::makeFeaturesDictForConnection(AbstractConnection *c, const QByteArray &genesisHash, const Options &opts)
{
    QVariantMap r;
    if (!c) {
        // paranoia
        Error() << __func__ << ": called with a nullptr for AbstractConnection FIXME!";
        return r;
    }
    r["pruning"] = QVariant(); // null
    r["genesis_hash"] = QString(Util::ToHexFast(genesisHash));
    r["server_version"] = ServerMisc::AppSubVersion;
    r["protocol_min"] = ServerMisc::MinProtocolVersion.toString();
    r["protocol_max"] = ServerMisc::MaxProtocolVersion.toString();
    r["hash_function"] = ServerMisc::HashFunction;

    QVariantMap hmap, hmapTor;
    if (opts.publicTcp.has_value())
        hmap["tcp_port"] = unsigned(opts.publicTcp.value());
    if (opts.publicSsl.has_value())
        hmap["ssl_port"] = unsigned(opts.publicSsl.value());
    if (opts.publicWs.has_value())
        hmap["ws_port"] = unsigned(opts.publicWs.value());
    if (opts.publicWss.has_value())
        hmap["wss_port"] = unsigned(opts.publicWss.value());
    if (hmap.isEmpty()) {
        // This should not normally happen but it can if user specified public_tcp_port=0 and public_ssl_port=0.
        // In that case we have to report SOMETHING here as per Electrum Cash protocol specs, so we just use the local port
        // that the client is connected to right now.  TODO: verify if we can get away with an empty dictionary here
        // instead?
        const bool isws = c->isWebSocket(), isssl = c->isSsl();
        const QString key = isws
                            ? (isssl ? "wss_port" : "ws_port" )
                            : (isssl ? "ssl_port" : "tcp_port");
        hmap[key] = unsigned(c->localPort());
    }
    const QString hostName = opts.hostName.value_or(c->localAddress().toString());
    // next, add tor .onion identity, if any defined in config -- for tor they need to specify at least a hostname and a port
    QString torHostName;
    if (opts.torHostName.has_value()) {

        torHostName = opts.torHostName.value();
        if (opts.torTcp.has_value())
            hmapTor["tcp_port"] = unsigned(opts.torTcp.value());
        if (opts.torSsl.has_value())
            hmapTor["ssl_port"] = unsigned(opts.torSsl.value());
        if (opts.torWs.has_value())
            hmapTor["ws_port"] = unsigned(opts.torWs.value());
        if (opts.torWss.has_value())
            hmapTor["wss_port"] = unsigned(opts.torWss.value());
    }
    QVariantMap hostsMap = {{ hostName, hmap }};
    if (!hmapTor.isEmpty() && !torHostName.isEmpty())
        hostsMap[torHostName] = hmapTor;

    r["hosts"] = hostsMap;
    return r;
}
void Server::rpc_server_features(Client *c, const RPC::Message &m)
{
    emit c->sendResult(m.id, makeFeaturesDictForConnection(c, storage->genesisHash(), *options));
}
void Server::rpc_server_peers_subscribe(Client *c, const RPC::Message &m)
{
    // See: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#server-peers-subscribe
    QVariantList res;
    for (const auto & pi : std::as_const(peers)) { // as_const here ensures we keep the implicit sharing for `peers`
        if (!pi.isMinimallyValid()) // paranoia -- this should never happen as other code filtered this out already
            continue;
        QVariantList item;
        const QString addrOrHost = !pi.addr.isNull() ? pi.addr.toString() : pi.hostName;
        item.push_back(addrOrHost); // item 1, ip address (or host if .isNull() e.g. tor)
        item.push_back(pi.hostName); // item 2, hostName
        QVariantList nested;
        nested.push_back(QStringLiteral("v") + (pi.protocolMax.isValid() ? pi.protocolMax.toString() : pi.protocolVersion.toString()));
        if (pi.ssl)
            nested.push_back(QStringLiteral("s") + QString::number(pi.ssl));
        if (pi.tcp)
            nested.push_back(QStringLiteral("t") + QString::number(pi.tcp));
        item.push_back(nested);
        res.push_back(item);
    }
    emit c->sendResult(m.id, res);
}
void Server::rpc_server_ping(Client *c, const RPC::Message &m)
{
    emit c->sendResult(m.id);
}
void Server::rpc_server_version(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    if (l.size() == 0)
        // missing client useragent, default to "Unknown"
        l.push_back(c->info.userAgent);
    if (l.size() == 1)
        // missing second arg, protocolVersion, default to our minimal protocol version "1.4"
        l.push_back(ServerMisc::MinProtocolVersion.toString());
    assert(l.size() == 2);

    if (c->info.alreadySentVersion)
        throw RPCError(QString("%1 already sent").arg(m.method));

    Version pver;
    if (const auto sl = l[1].toStringList(); sl.size() == 2) {
        // Ergh. EX also supports (protocolMin, protocolMax) tuples as the second arg! :/
        Version cMin = sl[0].left(kMaxServerVersionLen);
        Version cMax = sl[1].left(kMaxServerVersionLen);
        if (!cMin.isValid() || !cMax.isValid() || cMin > cMax)
            throw RPCErrorWithDisconnect(QString("Bad version tuple: %1").arg(sl.join(", ")));

        pver = std::min(cMax, ServerMisc::MaxProtocolVersion);
        if (pver < std::max(cMin, ServerMisc::MinProtocolVersion))
            pver = Version();
    } else {
        pver = l[1].toString().left(kMaxServerVersionLen); // try and parse version, see Version.cpp, QString constructor.
    }
    if (!pver.isValid() || pver < ServerMisc::MinProtocolVersion || pver > ServerMisc::MaxProtocolVersion)
        throw RPCErrorWithDisconnect("Unsupported protocol version");

    c->info.userAgent = l[0].toString().left(kMaxServerVersionLen);
    c->info.protocolVersion = pver;
    c->info.alreadySentVersion = true;
    emit c->sendResult(m.id, QStringList({ServerMisc::AppSubVersion, pver.toString()}));
}

/// returns the 'branch' and 'root' keys ready to be put in the results dictionary
auto Server::getHeadersBranchAndRoot(unsigned height, unsigned cp_height) -> HeadersBranchAndRootPair
{
    HeadersBranchAndRootPair ret;
    if (height <= cp_height) {
        auto pair = storage->headerBranchAndRoot(height, cp_height);
        auto & [branch, root] = pair;
        std::reverse(root.begin(), root.end());
        ret.second = QString(Util::ToHexFast(root)); // we cast to QString to prevent JSON null for empty string ""
        QVariantList & branchList = ret.first;
        branchList.reserve(int(branch.size()));
        for (auto & item : branch) {
            std::reverse(item.begin(), item.end());
            branchList.push_back(Util::ToHexFast(item));
            if (branchList.back().isNull())
                // this should never happen, but it pays to be paranoid
                throw InternalError("bad data retrieved from merkle cache");
        }
    }
    return ret;
}


void Server::rpc_blockchain_block_header(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(!l.isEmpty());
    bool ok;
    const unsigned height = l.front().toUInt(&ok);
    if (!ok || height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid height");
    ok = true;
    const unsigned cp_height = l.size() > 1 ? l.back().toUInt(&ok) : 0;
    if (!ok || cp_height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid cp_height");
    if (cp_height) {
        const auto tip = storage->latestTip().first;
        if (tip < 0) throw InternalError("chain height is negative");
        if ( ! (height <= cp_height && cp_height <= unsigned(tip)) )
            throw RPCError(QString("header height %1 must be <= cp_height %2 which must be <= chain height %3")
                           .arg(height).arg(cp_height).arg(tip));
    }
    generic_do_async(c, m.id, [height, cp_height, this] {
        QString err;
        const auto optHdr = storage->headerForHeight(height, &err); // may return nothing (but will set err) if height is now beyond chain height due to reorg
        if (QByteArray hdr; err.isEmpty() && optHdr.has_value() && !(hdr = optHdr.value()).isEmpty()) {
            const auto hexHdr = Util::ToHexFast(hdr); // hexHdr definitely not empty, no need to cast to QString (avoids a copy!)
            QVariant ret;
            if (!cp_height)
                ret = hexHdr;
            else {
                const auto [branch, root] = getHeadersBranchAndRoot(height, cp_height); // may throw if chain mutated and height or cp_height are no longer legal
                ret = QVariantMap{
                    { "header" , hexHdr },
                    { "branch",  branch },
                    { "root",    root   },
                };
            }
            return ret;
        } else
            throw RPCError(err.isEmpty() ? "Unknown error" : err);
    });
}

void Server::rpc_blockchain_block_headers(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() >= 2);
    bool ok;
    const unsigned height = l.front().toUInt(&ok);
    if (!ok || height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid height");
    unsigned count = l[1].toUInt(&ok);
    if (!ok || count >= Storage::MAX_HEADERS)
        throw RPCError("Invalid count");
    const auto tip = storage->latestTip().first;
    if (tip < 0) throw InternalError("chain height is negative");
    static constexpr unsigned MAX_COUNT = 2016; ///< TODO: make this cofigurable. this is the current electrumx limit, for now.
    count = std::min(std::min(unsigned(tip+1) - height, count), MAX_COUNT);
    ok = true;
    const unsigned cp_height = l.size() > 2 ? l.back().toUInt(&ok) : 0;
    if (!ok || cp_height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid cp_height");
    if (count && cp_height) {
        if ( ! (height + (count - 1) <= cp_height && cp_height <= unsigned(tip)) )
            throw RPCError(QString("header height + (count - 1) %1 must be <= cp_height %2 which must be <= chain height %3")
                           .arg(height + (count - 1)).arg(cp_height).arg(tip));
    }
    generic_do_async(c, m.id, [height, count, cp_height, this] {
        // EX doesn't seem to return error here if invalid height/no results, so we will do same.
        const auto hdrs = storage->headersFromHeight(height, std::min(count, MAX_COUNT));
        const size_t nHdrs = hdrs.size(), hdrSz = size_t(BTC::GetBlockHeaderSize()), hdrHexSz = hdrSz*2;
        QByteArray hexHeaders(int(nHdrs * hdrHexSz), Qt::Uninitialized);
        for (size_t i = 0, offset = 0; i < nHdrs; ++i, offset += hdrHexSz) {
            const auto & hdr = hdrs[i];
            if (UNLIKELY(hdr.size() != int(hdrSz))) { // ensure header looks the right size
                // this should never happen.
                Error() << "Header size from db height " << i + height << " is not " << hdrSz << " bytes! Database corruption likely! FIXME!";
                throw RPCError("Server header store invalid", RPC::Code_InternalError);
            }
            // fast, in-place conversion to hex
            Util::ToHexFastInPlace(hdr, hexHeaders.data() + offset, hdrHexSz);
        }
        QVariantMap resp{
            {"hex" , QString(hexHeaders)},  // we cast to QString to prevent null for empty string ""
            {"count", unsigned(hdrs.size())},
            {"max", MAX_COUNT}
        };
        if (count && cp_height) {
            // Note: it's possible for a reorg to happen and the chain height to be shortened in parellel in such
            // a way that lastHeight > chainHeight or cp_height > chainHeight, thus making this merkle branch query
            // below illegal. In that case the getHeadersBranchAndRoot function will bubble up an exception about a
            // short header count, which is what we want.
            const auto lastHeight = height + count - 1;
            const auto [branch, root] = getHeadersBranchAndRoot(lastHeight, cp_height);
            resp["branch"] = branch;
            resp["root"] = root;
        }
        return resp;
    });
}
void Server::rpc_blockchain_estimatefee(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(!l.isEmpty());
    bool ok;
    int n = l.front().toInt(&ok);
    if (!ok || n < 0)
        throw RPCError(QString("%1 parameter should be a single non-negative integer").arg(m.method));

    static const auto isZeroArgEstimateFee = [](const QString &subversion, const Version &version) -> bool {
        static const QString zeroArgSubversionPrefixes[] = { "/Bitcoin ABC", "/Bitcoin Cash Node", };
        static const Version minVersion{0, 20, 2};
        if (version < minVersion)
            return false;
        for (const auto & prefix : zeroArgSubversionPrefixes)
            if (subversion.startsWith(prefix))
                return true;
        return false;
    };

    if ( isZeroArgEstimateFee(bitcoinDInfo.subversion, bitcoinDInfo.version) ) {
        // Bitcoin ABC v0.20.2 has taken out the nblocks argument (also applies to Bitcoin Cash Node)
        generic_async_to_bitcoind(c, m.id, "estimatefee", QVariantList(),[](const RPC::Message &response){
            return response.result();
        });
    } else {
        // BUcash, earlier ABC, and others support the nblocks argument
        generic_async_to_bitcoind(c, m.id, "estimatefee", QVariantList{unsigned(n)},[](const RPC::Message &response){
            return response.result();
        });
    }
}
void Server::rpc_blockchain_headers_subscribe(Client *c, const RPC::Message &m) // fully implemented
{
    // helper used both for this response and for notifications
    static const auto mkResp = [](unsigned height, const QByteArray & header) -> QVariantMap {
        return QVariantMap{
            { "height" , height },
            { "hex" , Util::ToHexFast(header) }
        };
    };
    Storage::Header hdr;
    const auto [height, hhash] = storage->latestTip(&hdr);
    // we assume everything is peachy and don't check header size, etc as we can't really get here until we have synched at least *some* headers.
    if (!c->isSubscribedToHeaders) {
        c->isSubscribedToHeaders = true;
        // connect to signal. Will be emitted directly to object until it dies.
        connect(this, &Server::newHeader, c, [c, meth=m.method](unsigned height, const QByteArray &header){
            // the notification is a list of size 1, with a dict in it. :/
            c->sendNotification(meth, QVariantList({mkResp(height, header)}));
        });
        Debug() << c->prettyName(false, false) << " is now subscribed to headers";
    } else {
        Debug() << c->prettyName(false, false) << " was already subscribed to headers, ignoring duplicate subscribe request";
    }
    emit c->sendResult(m.id, mkResp(unsigned(std::max(0, height)), hdr));
}
void Server::rpc_blockchain_relayfee(Client *c, const RPC::Message &m)
{
    // This value never changes unless bitcoind is restarted, in which case we will pick up the new value when it comes
    // back. See: refreshBitcoinDNetworkInfo()
    emit c->sendResult(m.id, bitcoinDInfo.relayFee);
}

// ---- The below two methods are used by both the blockchain.scripthash.* and blockchain.address.* sets of methods
//      below for boilerplate checking & parsing.
HashX Server::parseFirstAddrParamToShCommon(const RPC::Message &m, QString *addrStrOut) const
{
    const auto net = srvmgr->net();
    if (UNLIKELY(net == BTC::Net::Invalid))
        // This should never happen in practice, but it pays to be paranoid.
        throw RPCError("Server cannot parse addresses at this time", RPC::ErrorCodes::Code_InternalError);
    constexpr int kAddrLenLimit = 128; // no address is ever really over 64 chars, let alone 128
    QVariantList l(m.paramsList());
    assert(!l.isEmpty());
    const QString addrStr = l.front().toString().left(kAddrLenLimit).trimmed();
    const BTC::Address address(addrStr);
    if (address.net() != net || !address.isValid())
        throw RPCError(QString("Invalid address: %1").arg(addrStr));
    const auto sh = address.toHashX();
    if (UNLIKELY(sh.length() != HashLen))
        throw RPCError("Invalid scripthash", RPC::ErrorCodes::Code_InternalError); // this should never happen but we must be defensive here.
    if (addrStrOut) *addrStrOut = addrStr;
    return sh;
}
HashX Server::parseFirstShParamCommon(const RPC::Message &m) const
{
    QVariantList l(m.paramsList());
    assert(!l.isEmpty());
    const HashX sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    return sh;
}
// ---
void Server::rpc_blockchain_scripthash_get_balance(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_get_balance(c, m, sh);
}
void Server::rpc_blockchain_address_get_balance(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    impl_get_balance(c, m, sh);
}
void Server::impl_get_balance(Client *c, const RPC::Message &m, const HashX &sh)
{
    generic_do_async(c, m.id, [sh, this] {
        const auto [amt, uamt] = storage->getBalance(sh);
        /* Note: ElectrumX protocol docs are incorrect. They claim a string in coin units is returned here.
         * It is not. Instead a number in satoshis is returned!
         * Incorrect docs: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-balance */
        QVariantMap resp{
          { "confirmed" , qlonglong(amt / amt.satoshi()) },
          { "unconfirmed" , qlonglong(uamt / uamt.satoshi()) },
        };
        return resp;
    });
}

/// called from get_mempool and get_history to retrieve the mempool for a hashx synchronously.  Returns the
/// QVariantMap suitable for placing into the resulting response.
QVariantList Server::getHistoryCommon(const HashX &sh, bool mempoolOnly)
{
    QVariantList resp;
    const auto items = storage->getHistory(sh, !mempoolOnly, true); // these are already sorted
    for (const auto & item : items) {
        QVariantMap m{
            { "tx_hash" , Util::ToHexFast(item.hash) },
            { "height", int(item.height) },
        };
        if (item.fee.has_value())
            m["fee"] = qlonglong(item.fee.value() / bitcoin::Amount::satoshi());
        resp.push_back(m);
    }
    return resp;
}

void Server::rpc_blockchain_scripthash_get_history(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_get_history(c, m, sh);
}
void Server::rpc_blockchain_address_get_history(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    impl_get_history(c, m, sh);
}
void Server::impl_get_history(Client *c, const RPC::Message &m, const HashX &sh)
{
    generic_do_async(c, m.id, [sh, this] {
        return getHistoryCommon(sh, false);
    });
}

void Server::rpc_blockchain_scripthash_get_mempool(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_get_mempool(c, m, sh);
}
void Server::rpc_blockchain_address_get_mempool(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    impl_get_mempool(c, m, sh);
}
void Server::rpc_blockchain_address_get_scripthash(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    emit c->sendResult(m.id, Util::ToHexFast(sh));
}
void Server::impl_get_mempool(Client *c, const RPC::Message &m, const HashX &sh)
{
    generic_do_async(c, m.id, [sh, this] {
        return getHistoryCommon(sh, true);
    });
}
void Server::rpc_blockchain_scripthash_listunspent(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_listunspent(c, m, sh);
}
void Server::rpc_blockchain_address_listunspent(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    impl_listunspent(c, m, sh);
}
void Server::impl_listunspent(Client *c, const RPC::Message &m, const HashX &sh)
{
    generic_do_async(c, m.id, [sh, this] {
        QVariantList resp;
        const auto items = storage->listUnspent(sh); // these are already sorted
        for (const auto & item : items) {
            resp.push_back(QVariantMap{
                { "tx_hash" , Util::ToHexFast(item.hash) },
                { "tx_pos"  , item.tx_pos },
                { "height", item.height },  // confirmed height. Is 0 for mempool tx regardless of unconf. parent status. Note this differs from get_mempool or get_history where -1 is used for unconf. parent.
                { "value", qlonglong(item.value / item.value.satoshi()) }, // amount (int64) in satoshis
            });
        }
        return resp;
    });
}
void Server::rpc_blockchain_scripthash_subscribe(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_sh_subscribe(c, m, sh);
}
void Server::rpc_blockchain_address_subscribe(Client *c, const RPC::Message &m)
{
    QString addrStr;
    const auto sh = parseFirstAddrParamToShCommon(m, &addrStr);
    assert(!addrStr.isEmpty());
    impl_sh_subscribe(c, m, sh, addrStr);
}
void Server::impl_sh_subscribe(Client *c, const RPC::Message &m, const HashX &sh, const std::optional<QString> &optAlias)
{
    const auto CheckSubsLimit = [c, &sh, this](int64_t nShSubs, bool doUnsub) {
        if (UNLIKELY(nShSubs > options->maxSubsPerIP)) {
            if (c->perIPData->isWhitelisted()) {
                // White-listed, let it go, but print to debug log
                Debug() << c->prettyName(false, false) << " exceeded the per-IP subscribe limit with " << nShSubs
                        << " subs, but it is whitelisted (subnet: " << c->perIPData->whiteListedSubnet().toString() << ")";
            } else {
                // Not white-listed .. unsubscribe and throw an error.
                if (const auto now = Util::getTimeSecs(); now - c->lastWarnedAboutSubsLimit > ServerMisc::kMaxSubsPerIPWarningsRateLimitSecs /* 1.0 secs */) {
                    // message spam throttled to once per second
                    Warning() << c->prettyName(false, false) << " exceeded per-IP subscribe limit with " << nShSubs
                              << " subs, denying  subscribe request";
                    c->lastWarnedAboutSubsLimit = now;
                }
                if (doUnsub) {
                    // unsubscribe client right away
                    if (LIKELY(storage->subs()->unsubscribe(c, sh))) {
                        // decrement counters
                        --c->nShSubs;
                        --c->perIPData->nShSubs;
                    } else
                        // This should never happen but we'll print debug/warning info if it does.
                        Warning() << c->prettyName(false, false) << " failed to unsubscribe client from a scripthash we just subscribed him to! FIXME!";
                }
                throw RPCError("Subscription limit reached", RPC::Code_App_LimitExceeded); // send error to client
            }
        }
    };
    // First, check the Per-IP subs limit right away before we do anything. This has a potential race condition
    // with other clients from this IP -- but breaking the limit will be caught in the second check below.
    // The reason we check twice is we *really* want to avoid creating a zombie sub for this client if we can
    // avoid it if they are at the limit.
    CheckSubsLimit( c->perIPData->nShSubs + 1, false ); // may throw RPCError

    SubsMgr::SubscribeResult result;
    try {
        const auto MkNotifierLambda = [c, &m, &optAlias]() -> StatusCallback {
            // We return two different lambdas, based on whether there is an opAddr alias specified or not.
            // The reason for doing it this way is that were we to capture the 'alias' as an empty value in the lambda
            // always, then in the blockchain.scripthash.subscribe case we would be wasting minimally ~16 bytes of
            // memory for the empty QByteArray *for each subscription*.
            //
            // Since we only use this data for the blockchain.address.subscribe case, we will capture it only in
            // that special case, hence the existence of two different lambdas here.
            //
            // This optimization optimizes memory consumption for the common case, since we don't expect many
            // blockchain.address.subscribe calls to the server.  (EC doesn't issue these calls, and that is our
            // primary client that we serve).
            StatusCallback ret;
            if (!optAlias.has_value()) { // common case
                // regular blockchain.scripthash.subscribe callback does no aliasing/rewriting and simply echoes the sh back to client as hex.
                ret =
                    [c, method=m.method](const HashX &sh, const StatusHash &status) {
                        QVariant statusHexMaybeNull; // if empty we simply notify as 'null' (this is unlikely in practice but may happen on reorg)
                        if (!status.isEmpty())
                            statusHexMaybeNull = Util::ToHexFast(status);
                        const QByteArray shHex = Util::ToHexFast(sh);
                        emit c->sendNotification(method, QVariantList{shHex, statusHexMaybeNull});
                    };
            } else {
                // When notifying, blockchain.address.subscribe callback must rewrite the sh arg -> the original address argument given by the client.
                ret =
                    [c, method=m.method, alias=optAlias.value().toUtf8()](const HashX &, const StatusHash &status) {
                        QVariant statusHexMaybeNull; // if empty we simply notify as 'null' (this is unlikely in practice but may happen on reorg)
                        if (!status.isEmpty())
                            statusHexMaybeNull = Util::ToHexFast(status);
                        emit c->sendNotification(method, QVariantList{alias, statusHexMaybeNull});
                    };
            }
            return ret;
        };
        /// Note: potential race condition here whereby notification can arrive BEFORE the status result. In practice this
        /// is fine since clients will cope with the situation, but... ideally, fixme.
        result = storage->subs()->subscribe(c, sh, MkNotifierLambda());
    } catch (const SubsMgr::LimitReached &e) {
        if (Util::getTimeSecs() - lastSubsWarningPrintTime > ServerMisc::kMaxSubsWarningsRateLimitSecs /* ~250 ms */) {
            // rate limit printing
            Warning() << "Exception from SubsMgr: " << e.what() << " (while serving subscribe request for " << c->prettyName(false, false) << ")";
            lastSubsWarningPrintTime = Util::getTimeSecs();
        }
        emit globalSubsLimitReached(); // connected to the SrvMgr, which will loop through all IPs and kick all clients for the most-subscribed IP
        throw RPCError("Subscription limit reached", RPC::Code_App_LimitExceeded); // send error to client
    }
    const auto & [wasNew, optStatus] = result;
    if (wasNew) {
        if (++c->nShSubs == 1)
            Debug() << c->prettyName(false, false) << " is now subscribed to at least one scripthash";
        // increment per ip counter ...
        // ... and check if they hit the limit again. This catches races.  Note that if the limit is reached this will
        // throw and after unsubscribing -- but the zombie sub will be left around for a time until it is reaped
        // (in practice it won't be a huge problem).
        CheckSubsLimit( ++c->perIPData->nShSubs, true ); // may throw RPCError
    }
    if (!optStatus.has_value()) {
        // no known/cached status -- do the work ourselves asynch in the thread pool.
        generic_do_async(c, m.id, [sh, this] {
            QVariant ret;
            const auto status = storage->subs()->getFullStatus(sh);
            storage->subs()->maybeCacheStatusResult(sh, status);
            if (!status.isEmpty()) // if empty we return `null`, otherwise we return hex encoded bytes as the immediate status.
                ret = Util::ToHexFast(status);
            return ret;
        });
    } else {
        // SubsMgr reported a cached status -- immediately return that as the result!
        QVariant result;
        if (!optStatus.value().isEmpty())
            // not empty, so we return the hex-encoded string
            result = QString(Util::ToHexFast(optStatus.value()));
        // this debug statement below can get spammy and also eats cycles.
        //Debug() << "Sending cached status to client for scripthash: " << Util::ToHexFast(sh) << " status: " << result.toString();
        //
        emit c->sendResult(m.id, result); ///<  may be 'null' if status was empty (indicates no history for scripthash)
    }
}
void Server::rpc_blockchain_scripthash_unsubscribe(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstShParamCommon(m);
    impl_sh_unsubscribe(c, m, sh);
}
void Server::rpc_blockchain_address_unsubscribe(Client *c, const RPC::Message &m)
{
    const auto sh = parseFirstAddrParamToShCommon(m);
    impl_sh_unsubscribe(c, m, sh);
}
void Server::impl_sh_unsubscribe(Client *c, const RPC::Message &m, const HashX &sh)
{
    const bool result = storage->subs()->unsubscribe(c, sh);
    if (result) {
        if (--c->nShSubs == 0)
            Debug() << c->prettyName(false, false) << " is no longer subscribed to any scripthashes";
        if (--c->perIPData->nShSubs == 0)
            Debug() << "PerIP: " << c->peerAddress().toString() << " is no longer subscribed to any scripthashes";
    }
    emit c->sendResult(m.id, QVariant(result));
}

void Server::rpc_blockchain_transaction_broadcast(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 1);
    QByteArray rawtxhex = l.front().toString().left(kMaxTxHex).toUtf8(); // limit raw hex to sane length.
    // no need to validate hex here -- bitcoind does validation for us!
    generic_async_to_bitcoind(c, m.id, "sendrawtransaction", QVariantList{ rawtxhex },
        // print to log, echo bitcoind's reply to client
        [size=rawtxhex.length()/2, c, this](const RPC::Message & reply){
            QVariant ret = reply.result();
            ++c->info.nTxSent;
            c->info.nTxBytesSent += unsigned(size);
            emit broadcastTxSuccess(unsigned(size));
            Log() << "Broadcast tx for client " << c->id << ", size: " << size << " bytes, response: " << ret.toString();
            static const Version FirstNonVulberableECVersion(3,3,4);
            if (const auto uaVersion = c->info.uaVersion(); uaVersion.isValid() && uaVersion < FirstNonVulberableECVersion) {
                // The below is to warn old clients that they are vulnerable to a phishing attack.
                // This logic is also used by the ElectronX implementations here:
                // https://github.com/Electron-Cash/electrumx/blob/fbd00416d804c286eb7de856e9399efb07a2ceaf/electrumx/server/session.py#L1526
                // https://github.com/Electron-Cash/electrumx/blob/fbd00416d804c286eb7de856e9399efb07a2ceaf/electrumx/lib/coins.py#L397
                ret = "<br/><br/>"
                      "Your transaction was successfully broadcast.<br/><br/>"
                      "However, you are using a VULNERABLE version of Electron Cash.<br/>"
                      "Download the latest version from this web site ONLY:<br/>"
                      "https://electroncash.org/"
                      "<br/><br/>";
                Log() << "Client " << c->id << " has a vulnerable Electron Cash (" << uaVersion.toString()
                      << "); upgrade warning HTML sent to client";
            }
            return ret;
        },
        // error func, throw an RPCError that's formatted in a particular way
        [c](const RPC::Message & errResponse) {
            ++c->info.nTxBroadcastErrors;
            const auto errorMessage = errResponse.errorMessage();
            Log() << "Broadcast fail for client " << c->id << ": " << errorMessage.left(120);
            throw RPCError(QString("the transaction was rejected by network rules.\n\n"
                                   // Note: ElectrumX here would also spit back the [txhex] after the final newline.
                                   // We do not do that, since it's a waste of bandwidth and also Electron Cash
                                   // ignores that information anyway.
                                   "%1\n").arg(errorMessage),
                            RPC::Code_App_BadRequest /**< ex does this here.. inconsistent with transaction.get,
                                                      * so for now we emulate that until we verify that EC
                                                      * will be ok with us changing it to Code_App_DaemonError */
                           );
        }
    );
    // <-- do nothing right now, return without replying. Will respond when daemon calls us back in callbacks above.
}
void Server::rpc_blockchain_transaction_get(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() <= 2);
    QByteArray txHash = validateHashHex( l.front().toString() );
    if (txHash.length() != HashLen)
        throw RPCError("Invalid tx hash");
    bool verbose = false;
    if (l.size() == 2) {
        const auto [verbArg, verbArgOk] = parseBoolSemiLooselyButNotTooLoosely( l.back() );
        if (!verbArgOk)
            throw RPCError("Invalid verbose argument; expected boolean");
        verbose = verbArg;
    }
    generic_async_to_bitcoind(c, m.id, "getrawtransaction", QVariantList{ Util::ToHexFast(txHash), verbose },
        // use the default success func, which just echoes the bitcoind reply to the client
        BitcoinDSuccessFunc(),
        // error func, throw an RPCError
        [](const RPC::Message & errResponse) {
            // EX does this weird thing.. we do it too for now until we can verify not doing it won't break old EC
            // clients... TODO: see if this can be removed in favor of a more canonical error message.
            throw RPCError(formatBitcoinDErrorResponseToLookLikeDumbElectrumXPythonRepr(errResponse),
                           RPC::Code_App_DaemonError);
        }
    );
    // <-- do nothing right now, return without replying. Will respond when daemon calls us back in callbacks above.
}

namespace {
    /// Note: pos must be within the txHashes array, otherwise a BadArgs exception will be thrown.
    /// Input txHashes should be in bitcoind memory order.
    /// Output is a QVariantList already reversed and hex encoded, suitable for putting into the results map as 'merkle'.
    /// Used by the below two _id_from_pos and _get_merkle rpc methods.
    QVariantList getMerkleForTxHashes(const std::vector<QByteArray> & txHashes, unsigned pos) {
        QVariantList branchList;

        // next, compute the branch and root for the tx hashes which are now in bitcoind memory order
        auto pair = Merkle::branchAndRoot(txHashes, pos);
        auto & [branch, root] = pair;

        // now, build our results for json as a QVariantList, reversing the memory back to hex memory order, and hex encoding it.
        branchList.reserve(int(branch.size()));
        for (auto & h : branch) {
            // reverse each hash in place and then hex encode it, and pust it to branchList
            std::reverse(h.begin(), h.end());
            h = Util::ToHexFast(h);
            branchList.push_back(h);
        }
        return branchList;
    }
}

void Server::rpc_blockchain_transaction_get_merkle(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 2);
    QByteArray txHash = validateHashHex( l.front().toString() );
    if (txHash.length() != HashLen)
        throw RPCError("Invalid tx hash");
    bool ok = false;
    unsigned height = l.back().toUInt(&ok);
    if (!ok || height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid height argument; expected non-negative numeric value");
    generic_do_async(c, m.id, [txHash, height, this] () mutable {
        auto txHashes = storage->txHashesForBlockInBitcoindMemoryOrder(height);
        std::reverse(txHash.begin(), txHash.end()); // we need to compare to bitcoind memory order so reverse specified hash
        constexpr unsigned NO_POS = ~0U;
        unsigned pos = NO_POS;
        for (unsigned i = 0; i < txHashes.size(); ++i) {
            if (txHashes[i] == txHash) {
                pos = i;
                break;
            }
        }
        if (pos == NO_POS)
            throw RPCError(QString("No transaction matching the requested hash found at height %1").arg(height));

        const auto branchList = getMerkleForTxHashes(txHashes, pos);

        QVariantMap resp = {
            { "block_height" , height },
            { "pos" , pos },
            { "merkle" , branchList }
        };

        return resp;
    });
}

void Server::rpc_blockchain_transaction_id_from_pos(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(!l.isEmpty());

    bool ok = false;
    unsigned height = l.front().toUInt(&ok); // arg0
    if (!ok || height >= Storage::MAX_HEADERS)
        throw RPCError("Invalid height argument; expected non-negative numeric value");
    unsigned pos = l.at(1).toUInt(&ok); // arg1
    constexpr unsigned MAX_POS = Storage::MAX_HEADERS;
    if (!ok || pos >= MAX_POS)
        throw RPCError("Invalid tx_pos argument; expected non-negative numeric value");
    bool merkle = false;
    if (l.size() == 3) { //optional arg2
        const auto [arg, argOk] = parseBoolSemiLooselyButNotTooLoosely( l.back() );
        if (!argOk)
            throw RPCError("Invalid merkle argument; expected boolean");
        merkle = arg;
    }
    generic_do_async(c, m.id, [height, pos, merkle, this] {
        static const QString missingErr("No transaction at position %1 for height %2");
        if (merkle) {
            // merkle=true is a dict, see: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-transaction-id-from-pos
            // get all hashes for the block (we need them for merkle)
            auto txHashes = storage->txHashesForBlockInBitcoindMemoryOrder(height);
            if (pos >= txHashes.size()) {
                // out of range, or block not found
                throw RPCError(missingErr.arg(pos).arg(height));
            }
            // save the requested tx_hash now, which we will return as tx_hash of the response dictionary
            // (we need to reverse it for outputting to hex since we received it in bitcoind internal memory order).
            const QByteArray txHashHex = Util::ToHexFast(Util::reversedCopy(txHashes[pos]));

            const auto branchList = getMerkleForTxHashes(txHashes, pos);

            QVariantMap res = {
                { "tx_hash" , txHashHex },
                { "merkle" , branchList },
            };

            return QVariant(res);
        } else {
            // no merkle, just return the tx_hash immediately without going async
            const auto opt = storage->hashForHeightAndPos(height, pos);
            if (!opt.has_value() || opt.value().length() != HashLen)
                throw RPCError(missingErr.arg(pos).arg(height));
            const auto txHashHex = Util::ToHexFast(opt.value());
            return QVariant(txHashHex);
        }
    });
}
void Server::rpc_mempool_get_fee_histogram(Client *c, const RPC::Message &m)
{
    const auto hist = storage->mempoolHistogram();
    QVariantList result;
    for  (const auto & [feeRate, cumSize] : hist) {
        result.push_back(QVariantList{feeRate, cumSize});
    }
    emit c->sendResult(m.id, result);
}
// --- Server::StaticData Definitions ---
#define HEY_COMPILER_PUT_STATIC_HERE(x) decltype(x) x
#define PR RPC::Method::PosParamRange
#define MP(x) static_cast<ServerBase::Member_t>(&Server :: x) // wrapper to cast from narrow method pointer to ServerBase::Member_t
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::dispatchTable);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::methodMap);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::registry){
/*  ==> Note: Add stuff to this table when adding new RPC methods.
    { {"rpc.name",                allow_requests, allow_notifications, PosParamRange, (QSet<QString> note: {} means undefined optional)}, &method_to_call }     */
    { {"server.add_peer",                   true,               false,    PR{1,1},      RPC::KeySet{} },          MP(rpc_server_add_peer) },
    { {"server.banner",                     true,               false,    PR{0,0},                    },          MP(rpc_server_banner) },
    { {"server.donation_address",           true,               false,    PR{0,0},                    },          MP(rpc_server_donation_address) },
    { {"server.features",                   true,               false,    PR{0,0},                    },          MP(rpc_server_features) },
    { {"server.peers.subscribe",            true,               false,    PR{0,0},                    },          MP(rpc_server_peers_subscribe) },
    { {"server.ping",                       true,               false,    PR{0,0},                    },          MP(rpc_server_ping) },
    { {"server.version",                    true,               false,    PR{0,2},                    },          MP(rpc_server_version) },

    { {"blockchain.address.get_balance",    true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_get_balance) },
    { {"blockchain.address.get_history",    true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_get_history) },
    { {"blockchain.address.get_mempool",    true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_get_mempool) },
    { {"blockchain.address.get_scripthash", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_get_scripthash) },
    { {"blockchain.address.listunspent",    true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_listunspent) },
    { {"blockchain.address.subscribe",      true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_subscribe) },
    { {"blockchain.address.unsubscribe",    true,               false,    PR{1,1},                    },          MP(rpc_blockchain_address_unsubscribe) },

    { {"blockchain.block.header",           true,               false,    PR{1,2},                    },          MP(rpc_blockchain_block_header) },
    { {"blockchain.block.headers",          true,               false,    PR{2,3},                    },          MP(rpc_blockchain_block_headers) },
    { {"blockchain.estimatefee",            true,               false,    PR{1,1},                    },          MP(rpc_blockchain_estimatefee) },
    { {"blockchain.headers.subscribe",      true,               false,    PR{0,0},                    },          MP(rpc_blockchain_headers_subscribe) },
    { {"blockchain.relayfee",               true,               false,    PR{0,0},                    },          MP(rpc_blockchain_relayfee) },

    { {"blockchain.scripthash.get_balance", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_get_balance) },
    { {"blockchain.scripthash.get_history", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_get_history) },
    { {"blockchain.scripthash.get_mempool", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_get_mempool) },
    { {"blockchain.scripthash.listunspent", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_listunspent) },
    { {"blockchain.scripthash.subscribe",   true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_subscribe) },
    { {"blockchain.scripthash.unsubscribe", true,               false,    PR{1,1},                    },          MP(rpc_blockchain_scripthash_unsubscribe) },

    { {"blockchain.transaction.broadcast",  true,               false,    PR{1,1},                    },          MP(rpc_blockchain_transaction_broadcast) },
    { {"blockchain.transaction.get",        true,               false,    PR{1,2},                    },          MP(rpc_blockchain_transaction_get) },
    { {"blockchain.transaction.get_merkle", true,               false,    PR{2,2},                    },          MP(rpc_blockchain_transaction_get_merkle) },
    { {"blockchain.transaction.id_from_pos",true,               false,    PR{2,3},                    },          MP(rpc_blockchain_transaction_id_from_pos) },

    { {"mempool.get_fee_histogram",         true,               false,    PR{0,0},                    },          MP(rpc_mempool_get_fee_histogram) },
};
#undef MP
#undef PR
#undef HEY_COMPILER_PUT_STATIC_HERE
namespace {
    template <typename DTable, typename MMap, typename Registry>
    void InitStaticDataCommon(DTable & dispatchTable, MMap & methodMap, const Registry & registry) {
        if (!dispatchTable.empty())
            return;
        dispatchTable.reserve(registry.size());
        methodMap.reserve(registry.size());
        for (const auto & r : registry) {
            if (!r.member) {
                std::cerr << "Runtime check failed: RPC Method " << r.method.toUtf8().constData()
                          << " has a nullptr for its .member! FIXME!" << std::endl << std::flush;
                std::_Exit(EXIT_FAILURE);
            }
            methodMap[r.method] = r;
            dispatchTable[r.method] = r.member;
        }

    }
}
/*static*/
void Server::StaticData::init() { InitStaticDataCommon(dispatchTable, methodMap, registry); }
// --- /Server::StaticData Definitions ---
// --- /RPC METHODS ---

// --- SSL Server support ---
ServerSSL::ServerSSL(SrvMgr *sm, const QHostAddress & address_, quint16 port_, const std::shared_ptr<const Options> & opts,
                     const std::shared_ptr<Storage> & storage_, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr_)
    : Server(sm, address_, port_, opts, storage_, bitcoindmgr_), cert(opts->sslCert), key(opts->sslKey)
{
    if (cert.isNull() || key.isNull())
        throw BadArgs("ServerSSL cannot be instantiated: Key or cert are null!");
    if (!QSslSocket::supportsSsl())
        throw BadArgs("ServerSSL cannot be instantiated: Missing SSL support!");
    resetName();
}
ServerSSL::~ServerSSL() { stop(); }
QString ServerSSL::prettyName() const
{
    return (usesWS ? QStringLiteral("Wss%1") : QStringLiteral("Ssl%1")).arg(AbstractTcpServer::prettyName());
}
void ServerSSL::incomingConnection(qintptr socketDescriptor)
{
    auto socket = createSocketFromDescriptorAndCheckLimits<QSslSocket>(socketDescriptor);
    if (!socket)
        // low-level error. Fail. Error message was already logged.
        return;
    socket->setLocalCertificate(cert);
    socket->setPrivateKey(key);
    socket->setProtocol(QSsl::SslProtocol::AnyProtocol);
    const auto peerName = QStringLiteral("%1:%2").arg(socket->peerAddress().toString()).arg(socket->peerPort());
    if (socket->state() != QAbstractSocket::SocketState::ConnectedState || socket->isEncrypted()) {
        Warning() << peerName << " socket had unexpected state (must be both connected and unencrypted), deleting socket";
        delete socket;
        return;
    }
    QTimer *timer = new QTimer(socket);
    timer->setObjectName(QStringLiteral("TLS handshake timer"));
    timer->setSingleShot(true);
    static const auto kTimedOutPropertyName = "ServerSSL_Handshake_Timed_Out";
    connect(timer, &QTimer::timeout, this, [socket, timer, peerName]{
        Warning() << peerName << " SSL handshake timed out after " << QString::number(timer->interval()/1e3, 'f', 1) << " secs, deleting socket";
        socket->setProperty(kTimedOutPropertyName, true);
        socket->abort();
        socket->deleteLater();
    });
    auto tmpConnections = std::make_shared<QList<QMetaObject::Connection>>();
    *tmpConnections += connect(socket, &QSslSocket::disconnected, this, [socket, peerName]{
        if (!socket->property(kTimedOutPropertyName).toBool())
            Debug() << peerName << " SSL handshake failed due to disconnect before completion, deleting socket";
        socket->deleteLater();
    });
    *tmpConnections += connect(socket, &QSslSocket::encrypted, this, [this, timer, tmpConnections, socket, peerName] {
        Trace() << peerName << " SSL ready";
        timer->stop();
        timer->deleteLater();
        if (tmpConnections) {
            // tmpConnections will get auto-deleted after this lambda returns because the QObject connection holding
            // it alive will be disconnected.
            for (const auto & conn : *tmpConnections)
                disconnect(conn);
        }
        if (!usesWS) {
            // Classic non-WebSocket mode.  We are done; enqueue the connection and emit the signal.
            addPendingConnection(socket);
            emit newConnection();
            return;
        }

        // WebSockets mode -- create the wrapper object and further negotiate the handshake.  Later on newConnection()
        // will be emitted again on success, or the socket will be auto-deleted on failure.
        startWebSocketHandshake(socket);
    });
    *tmpConnections +=
    connect(socket, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), this, [socket, peerName](const QList<QSslError> & errors) {
        for (const auto & e : errors)
            Warning() << peerName << " SSL error: " << e.errorString();
        Debug() << peerName << " Aborting connection due to SSL errors";
        socket->deleteLater();
    });
    timer->start(10'000); // give the TLS handshake 10 seconds to complete
    socket->startServerEncryption();
}
// --- /SSL Server support ---

// --- Admin RPC Serer ---
AdminServer::AdminServer(SrvMgr *sm, const QHostAddress & a, quint16 p, const std::shared_ptr<const Options> & o,
                         const std::shared_ptr<Storage> & s, const std::shared_ptr<BitcoinDMgr> & bdm,
                         const std::weak_ptr<PeerMgr> & pm)
    : ServerBase(sm, StaticData::methodMap, StaticData::dispatchTable, a, p, o, s, bdm), peerMgr(pm)
{
    StaticData::init(); // noop after first time it's called
    resetName();
    threadPool = std::make_unique<ThreadPool>(this);
    asyncThreadPool = threadPool.get();
    threadPool->setExtantJobLimit(100); // be very conservative here.
    threadPool->setMaxThreadCount(std::min(QThread::idealThreadCount(), 2)); // limit to max 2 threads for admin rpc. we want to limit interference with SPV clients.
}

AdminServer::~AdminServer() { stop(); asyncThreadPool = nullptr; }

QString AdminServer::prettyName() const { return QStringLiteral("Admin%1").arg(AbstractTcpServer::prettyName()); }

auto AdminServer::stats() const -> Stats
{
    QVariantMap m = ServerBase::stats().toMap();
    if (!m.isEmpty()) {
        // this is a bit awkward...
        const auto fkey = m.firstKey();
        auto m2 = m[fkey].toMap();
        m2["threadPool"] = threadPool->stats();
        m[fkey] = m2;
    }
    return m;
}


void AdminServer::kickBanBoilerPlate(const RPC::Message &m, BanOp banOp)
{
    const auto list = m.paramsList();
    std::list<IdMixin::Id> ids;
    std::list<QHostAddress> addrs;
    int argNum = 0;
    for (const auto & var : list) {
        ++argNum;
        QString s = var.toString();
        bool ok;
        std::uint64_t cid = s.toULongLong(&ok);
        constexpr auto UnbanMsg = "Argument %1 is not an IP address: '%2'",
                       OtherMsg = "Argument %1 is not a ClientID or an IP address: '%2'";
        if (ok && cid) {
            if (banOp == BanOp::Unban)
                // cannot unban by ID since the actual ban table only stores IP addresses
                throw RPCError(QString(UnbanMsg).arg(argNum).arg(s));
            ids.push_back(cid);
        } else if (auto addr = QHostAddress(s); !addr.isNull() ) {
            addrs.emplace_back(std::move(addr));
        } else {
            const char * msg = banOp == BanOp::Unban ? UnbanMsg : OtherMsg;
            throw RPCError(QString(msg).arg(argNum).arg(s));
        }
    }
    for (const auto & cid : ids) {
        switch (banOp) {
        case BanOp::Ban:  emit srvmgr->banID(cid); break;
        case BanOp::Kick: emit srvmgr->kickById(cid); break;
        case BanOp::Unban: break; ///< this is never reached because we throw above if we encounter cid's in an Unban.
        }
    }
    for (const auto & addr : addrs) {
        switch (banOp) {
        case BanOp::Ban:  emit srvmgr->banIP(addr); break;
        case BanOp::Kick: emit srvmgr->kickByAddress(addr); break;
        case BanOp::Unban: emit srvmgr->liftIPBan(addr); break;
        }
    }
}
void AdminServer::rpc_addpeer(Client *c, const RPC::Message &m)
{
    if (peerMgr.expired())
        throw RPCError("This server has peering disabled");
    const auto kwargs = m.paramsMap(); // this is guaranteed to not be empty by calling code
    PeerInfo pi;
    pi.hostName = kwargs.value("host").toString().trimmed().toLower();
    if (pi.hostName.isEmpty())
        throw RPCError("Invalid host specified");

    // the below parses kwargs["tcp"] and kwargs["ssl"] if not null, and puts the result (if any) in pi.tcp and pi.ssl
    using Tup = std::tuple<QString, quint16 &>;
    for (const auto & [key, valDest] : {Tup{"tcp", pi.tcp}, Tup{"ssl", pi.ssl}}) {
        bool ok;
        unsigned val = 0;
        if (!kwargs.value(key).isNull()) {
            val = kwargs.value(key).toUInt(&ok);
            if (!ok || val > USHRT_MAX)
                throw RPCError(QString("Invalid %1 port specified").arg(key));
            valDest = quint16(val);
        }
    }
    // -

    if (!pi.ssl && !pi.tcp)
        throw RPCError("Must specify at least one TCP or SSL port");
    emit gotRpcAddPeer(PeerInfoList{pi}, QHostAddress());
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_ban(Client *c, const RPC::Message &m)
{
    kickBanBoilerPlate(m, BanOp::Ban);
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_banpeer(Client *c, const RPC::Message &m)
{
    if (peerMgr.expired())
        throw RPCError("This server has peering disabled");
    const auto strs = m.params().toStringList();
    int ctr = 0;
    for (auto suf : strs) {
        if ((suf=suf.trimmed()).isEmpty())
            continue;
        ++ctr;
        emit srvmgr->banPeersWithSuffix(suf);
    }
    emit c->sendResult(m.id, bool(ctr));
}
void AdminServer::rpc_bitcoind_throttle(Client *c, const RPC::Message &m)
{
    const QVariantList l = m.paramsList();
    if (!l.isEmpty()) {
        // set
        if (l.size() != 3)
err:
            throw RPCError("Bad params: please pass a list of 3 positive integers");
        Options::BdReqThrottleParams p;
        bool ok;
        p.hi = l[0].toInt(&ok);
        if (!ok) goto err;
        p.lo = l[1].toInt(&ok);
        if (!ok) goto err;
        p.decay = l[2].toInt(&ok);
        if (!ok) goto err;
        if (!p.isValid())
            throw RPCError(QString("Bad params: specify [hi, lo, decay], where hi > lo (both must be under %1)").arg(Options::maxBDReqHi));

        emit srvmgr->requestBitcoindThrottleParamsChange(p.hi, p.lo, p.decay); // direct connection to App object, takes effect immediately
    }
    // get
    const auto [hi, lo, decay] = options->bdReqThrottleParams.load();
    emit c->sendResult(m.id, QVariantList{hi, lo, decay});
}
void AdminServer::rpc_clients(Client *c, const RPC::Message &m)
{
    generic_do_async(c, m.id, [srvmgr = QPointer(this->srvmgr)]{
        if (!srvmgr) throw InternalError("SrvMgr pointer is null"); // this should never happen but it pays to be paranoid
        // this blocks, but it will block in this worker thread. It may throw, but that's ok as the generic_do_async() wrapper
        // in ServerBase handles catching any and all exceptions and will just send an error response to the client.
        return srvmgr->adminRPC_getClients_blocking(kBlockingCallTimeoutMS);
    });
}
void AdminServer::rpc_getinfo(Client *c, const RPC::Message &m)
{
    QVariantMap res;
    res["bitcoind"] = QString("%1:%2").arg(options->bitcoind.first).arg(options->bitcoind.second);
    res["bitcoind_warnings"] = bitcoinDInfo.warnings;
    {
        const auto opt = storage->latestHeight();
        res["height"] = opt.has_value() ? opt.value() : QVariant();
    }
    res["chain"] = storage->getChain();
    res["genesis_hash"] = Util::ToHexFast(storage->genesisHash());
    res["pid"] = QCoreApplication::applicationPid();
    res["clients_connected"] = qulonglong(Client::numClients.load());
    res["clients_connected_max_lifetime"] = qulonglong(Client::numClientsMax.load());
    res["clients_connected_total_lifetime"] = qulonglong(Client::numClientsCtr.load());
    res["version"] = ServerMisc::AppSubVersion;
    res["txs_sent"] = qulonglong(srvmgr->txBroadcasts());
    res["txs_sent_bytes"] = qulonglong(srvmgr->txBroadcastBytes());
    res["uptime"] = QString::number(Util::getTimeSecs(), 'f', 1) + " secs";
    res["subscriptions"] = qlonglong(storage->subs()->numActiveClientSubscriptions());
    res["peers"] = peers.size();
    res["config"] = options->toMap();
    { // mempool
        QVariantMap mp;
        auto [mempool, lock] = storage->mempool();
        mp["txs"] = qulonglong(mempool.txs.size());
        mp["addresses"] = qulonglong(mempool.hashXTxs.size());
        std::size_t sizeTotal = 0;
        std::int64_t feeTotal = 0;
        std::for_each(mempool.txs.begin(), mempool.txs.end(), [&sizeTotal, &feeTotal](const auto &pair){
            sizeTotal += pair.second->sizeBytes;
            feeTotal += pair.second->fee / bitcoin::Amount::satoshi();
        });
        mp["size_bytes"] = qulonglong(sizeTotal);
        mp["avg_fee_sats_B"] = long(std::round(double(feeTotal) / double(sizeTotal) * 100.)) / 100.;
        res["mempool"] = mp;
    }
    { // utxoset
        QVariantMap us;
        us["size"] = qulonglong(storage->utxoSetSize());
        us["size_MiB"] = long(std::round(storage->utxoSetSizeMiB() * 100.0)) / 100.;
        res["utxoset"] = us;
    }
    // ThreadPool - this is thread-safe.. despite the name here it doesn't follow the StatsMixin API and returns data
    // in a thread-safe way without blocking.
    res["thread_pool"] = ::AppThreadPool()->stats();

    // storage stats -- for this we need to go asynch because we need to block to grab them using the StatsMixin API
    generic_do_async(c, m.id, [storage = this->storage, res]() mutable {
        QVariant v = storage->statsSafe(kBlockingCallTimeoutMS);
        // Here we do this contorted thing to delete the "table factory options" dict for each of the db's, to make
        // the `getinfo` call not be as verbose. (We also delete "keep_log_file_num" and "max_open_files" since they
        // are redundant).
        if (QVariantMap m, m2; !(m = v.toMap()).isEmpty() && !(m2 = m.value("DB Stats").toMap()).isEmpty()) {
            QVariantMap m2_new;
            for (auto it = m2.begin(); it != m2.end(); ++it) {
                QVariant v2 = it.value();
                if (QVariantMap m3; !(m3 = v2.toMap()).isEmpty()) {
                    m3.remove("table factory options"); // delete this very verbose dict
                    m3.remove("keep_log_file_num"); // redundant with config value
                    m3.remove("max_open_files"); // redundant with config value
                    v2 = m3;
                }
                m2_new[it.key()] = v2;
            }
            m["DB Stats"] = m2_new;
            v = m;
        }
        res["storage_stats"] = v;
        return res; // returns result to client
    });
}
void AdminServer::rpc_kick(Client *c, const RPC::Message &m)
{
    kickBanBoilerPlate(m, BanOp::Kick);
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_listbanned(Client *c, const RPC::Message &m)
{
    emit c->sendResult(m.id, srvmgr->adminRPC_banInfo_threadSafe());
}
void AdminServer::rpc_loglevel(Client *c, const RPC::Message &m)
{
    bool ok;
    const int level = m.paramsList().front().toInt(&ok);
    if (!ok || level < 0 || level > 2)
        throw RPCError("Invalid log level, please specify an integer from 0 to 2");
    App *app = ::app();
    if (!app) throw InternalError("The impossible has happened. The App pointer is null. FIXME!");
    switch (level) {
    case 0:
        emit app->setVerboseTrace(false);
        emit app->setVerboseDebug(false);
        break;
    case 1:
        emit app->setVerboseTrace(false);
        emit app->setVerboseDebug(true);
        break;
    case 2:
        emit app->setVerboseDebug(true);
        emit app->setVerboseTrace(true);
        break;
    }
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_maxbuffer(Client *c, const RPC::Message &m)
{

    if (const auto l = m.paramsList(); !l.empty()) {
        bool ok;
        const int arg = m.paramsList().front().toInt(&ok);
        if (!ok || !Options::isMaxBufferSettingInBounds(arg))
            throw RPCError(QString("Invalid maxbuffer, please specify an integer in the range [%1, %2]").arg(Options::maxBufferMin).arg(Options::maxBufferMax));
        emit srvmgr->requestMaxBufferChange(Options::clampMaxBufferSetting(arg)); // has a slot connected via DirectConnection so takes effect immediately
    }
    // return the current setting
    emit c->sendResult(m.id, options->maxBuffer.load());
}
void AdminServer::rpc_peers(Client *c, const RPC::Message &m)
{
    auto strongPeerMgr = peerMgr.lock();
    if (!strongPeerMgr)
        throw RPCError("This server has peering disabled");
    // We do this async in our worker thread since it blocks (briefly)
    generic_do_async(c, m.id, [peerMgr = strongPeerMgr]{
        return peerMgr->statsSafe(kBlockingCallTimeoutMS);
    });
}
void AdminServer::rpc_rmpeer(Client *c, const RPC::Message &m)
{
    if (peerMgr.expired())
        throw RPCError("This server has peering disabled");
    const auto strs = m.params().toStringList();
    int ctr = 0;
    for (auto suffix : strs) {
        if ((suffix=suffix.trimmed()).isEmpty())
            continue;
        ++ctr;
        emit srvmgr->kickPeersWithSuffix(suffix);
    }
    emit c->sendResult(m.id, bool(ctr));
}
void AdminServer::rpc_shutdown(Client *c, const RPC::Message &m)
{
    auto app = qApp;
    // send the signal after 100ms to the QCoreApplication instance to quit.  this allows time for the result to be sent to the client, hopefully.
    Util::AsyncOnObject(app, [app] {
        Log() << "Received 'stop' command from admin RPC, shutting down ...";
        app->quit();
    }, 100);
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_unban(Client *c, const RPC::Message &m)
{
    kickBanBoilerPlate(m, BanOp::Unban);
    emit c->sendResult(m.id, true);
}
void AdminServer::rpc_unbanpeer(Client *c, const RPC::Message &m)
{
    if (peerMgr.expired())
        throw RPCError("This server has peering disabled");
    const auto strs = m.params().toStringList();
    int ctr = 0;
    for (auto suf : strs) {
        if ((suf=suf.trimmed()).isEmpty())
            continue;
        ++ctr;
        emit srvmgr->liftPeerSuffixBan(suf);
    }
    emit c->sendResult(m.id, bool(ctr));
}

// --- AdminServer::StaticData Definitions ---
#define HEY_COMPILER_PUT_STATIC_HERE(x) decltype(x) x
#define PR RPC::Method::PosParamRange
#define KS  RPC::KeySet
#define MP(x) static_cast<ServerBase::Member_t>(&AdminServer :: x) // wrapper to cast from narrow method pointer to ServerBase::Member_t
#define UNLIMITED (RPC::Method::NO_POS_PARAM_LIMIT)
HEY_COMPILER_PUT_STATIC_HERE(AdminServer::StaticData::dispatchTable);
HEY_COMPILER_PUT_STATIC_HERE(AdminServer::StaticData::methodMap);
HEY_COMPILER_PUT_STATIC_HERE(AdminServer::StaticData::registry){
/*  ==> Note: Add stuff to this table when adding new RPC methods.
    { {"rpc.name",                allow_requests, allow_notifications, PosParamRange, (QSet<QString> note: {} means undefined optional)}, &method_to_call }     */
    { {"addpeer",                           true,               false,    PR{0,0},      KS{"host","tcp","ssl"} }, MP(rpc_addpeer) },
    { {"ban",                               true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_ban) },
    { {"banpeer",                           true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_banpeer) },
    { {"bitcoind_throttle",                 true,               false,    PR{0,3},                 {} },          MP(rpc_bitcoind_throttle) },
    { {"clients",                           true,               false,    PR{0,0},                 {} },          MP(rpc_clients) },
    { {"getinfo",                           true,               false,    PR{0,0},                 {} },          MP(rpc_getinfo) },
    { {"kick",                              true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_kick) },
    { {"listbanned",                        true,               false,    PR{0,0},                 {} },          MP(rpc_listbanned) },
    { {"loglevel",                          true,               false,    PR{1,1},                 {} },          MP(rpc_loglevel) },
    { {"maxbuffer",                         true,               false,    PR{0,1},                 {} },          MP(rpc_maxbuffer) },
    { {"peers",                             true,               false,    PR{0,0},                 {} },          MP(rpc_peers) },
    { {"rmpeer",                            true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_rmpeer) },
    { {"shutdown",                          true,               false,    PR{0,0},                 {} },          MP(rpc_shutdown) },
    { {"stop",                              true,               false,    PR{0,0},                 {} },          MP(rpc_shutdown) }, // alias for 'shutdown'
    { {"unban",                             true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_unban) },
    { {"unbanpeer",                         true,               false,    PR{1,UNLIMITED},         {} },          MP(rpc_unbanpeer) },
};
#undef UNLIMITED
#undef MP
#undef KS
#undef PR
#undef HEY_COMPILER_PUT_STATIC_HERE
/*static*/
void AdminServer::StaticData::init() { InitStaticDataCommon(dispatchTable, methodMap, registry); }
// ---- /Admin RPC Server ---

/*static*/ std::atomic_size_t Client::numClients{0}, Client::numClientsMax{0}, Client::numClientsCtr{0};

Client::Client(const RPC::MethodMap & mm, IdMixin::Id id_in, QTcpSocket *sock, int maxBuffer)
    : RPC::ElectrumConnection(mm, id_in, sock, /* ensure sane --> */ qMax(maxBuffer, Options::maxBufferMin))
{
    ++numClientsCtr;
    const auto N = ++numClients;
    {
        size_t expected = numClientsMax.load(std::memory_order_relaxed);
        // This loop atomically updates the maximum only if it's less than the current counter.
        // It will only actually loop if there is contention on the atomic variable numClientsMax
        // otherwise it will atomically update it so long as it is the true maximum. Don't worry, it will generally
        // only loop if there is contention and even so the number of iterations won't exceed the number of contending
        // threads (typically 2 iterations max worst case on a server listening to 2 ports).
        while (expected < N && !numClientsMax.compare_exchange_weak(expected, N, std::memory_order_release, std::memory_order_relaxed))
        { /* nothing */ }
    }
    socket = sock;
    stale_threshold = 10 * 60 * 1000; // 10 mins stale threshold; after which clients get disconnected for being idle (for now... TODO: make this configurable)
    pingtime_ms = int(stale_threshold); // this determines how often the pingtimer fires
    status = Connected ; // we are always connected at construction time.
    errorPolicy = ErrorPolicySendErrorMessage;
    setObjectName(QStringLiteral("Client.%1").arg(id_in));
    on_connected();
    Log() << "New " << prettyName(false, false) << ", " << N << Util::Pluralize(QStringLiteral(" client"), N) << " total";
}

Client::~Client()
{
    --numClients;
    if constexpr (!isReleaseBuild())
        Debug() << __func__ << " " << id;
    socket = nullptr; // NB: we are a child of socket, so socket is alread invalid here. This line here is added in case some day I make AbstractClient delete socket on destruct.
    emit clientDestructing(this); // This is currently connected to a lambda in ServerBase::newClient
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
        Debug() << __func__ << " " << id << " (graceful); delayed socket delete (wait for disconnect) ...";

    // tell ConnectionBase to not send us any new messages from this client
    ignoreNewIncomingMessages = true;
}

void Client::do_ping()
{
    // Don't send clients pings.
    // Instead, rely on them to ping us else disconnect them if idle for too long.
    // The below just checks idle.
    if (Util::getTime() - lastGood >= stale_threshold) {
        Debug() << prettyName() << ": idle timeout after " << ((stale_threshold)/1e3) << " sec., will close connection";
        do_disconnect();
        return;
    }
}
