#include "Servers.h"

#include "BitcoinD.h"
#include "Merkle.h"
#include "Storage.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QtNetwork>
#include <QString>
#include <QTextCodec>
#include <QTextStream>
#include <QTimer>

#include <cstdlib>
#include <utility>

TcpServerError::~TcpServerError() {} // for vtable

AbstractTcpServer::AbstractTcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), IdMixin(newId()), addr(a), port(p)
{
    assert(qobj()); // Runtime check that derived class followed the rules outlined at the top of Mixins.h

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


// ---- Classes Server & Client ----

// class Server constants
namespace {
    // TODO: maybe move these to a more global place? For now here is fine.
    namespace Constants {
        constexpr int kMaxServerVersion = 80,  ///< the maximum server version length we accept to prevent memory exhaustion attacks
                      kMaxBuffer = 4*1000*1000, ///< =4MB. The max buffer we use in Client (ElectronX client). TODO: Make this tune-able and configurable!
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
        return QString("daemon error: DaemonError({'code': %1, 'message': '%2'})")
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

Server::Server(const QHostAddress &a, quint16 p, std::shared_ptr<Storage> s, std::shared_ptr<BitcoinDMgr> bdm)
    : AbstractTcpServer(a, p), storage(std::move(s)), bitcoindmgr(std::move(bdm))
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
    ret["numClients"] = clientsById.count();
    QVariantList clientList;
    for (const auto & client : clientsById) {
        // note we call this thread-unsafe function stats() here because client lives in our thread. but if that design
        // changes, update this to call client->statsSafe(100) instead
        auto map = client->stats().toMap();
        auto name = map.take("name").toString();
        map["version"] = QVariantList({client->info.userAgent, client->info.protocolVersion});
        map["errCt"] = client->info.errCt;
        map["nRequestsRcv"] = client->info.nRequestsRcv;
        map["isSubscribedToHeaders"] = client->isSubscribedToHeaders;
        // the below don't really make much sense for this class (they are always 0 or empty)
        map.remove("nDisconnects");
        map.remove("nSocketErrors");
        map.remove("lastSocketError");
        map.remove("nUnansweredRequests");
        map.remove("nRequestsSent");
        clientList.append(QVariantMap({{name, map}}));
    }
    ret["clients"] = clientList;
    return ret;
}

void Server::on_started()
{
    AbstractTcpServer::on_started();
    // add more conns here, etc, if needed
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
void Server::killClient(quint64 clientId)
{
    killClient(clientsById.take(clientId));
}
void Server::onMessage(quint64 clientId, const RPC::Message &m)
{
    Trace() << "onMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        auto member = StaticData::dispatchTable.value(m.method);
        if (!member)
            Error() << "Unknown method: \"" << m.method << "\". This shouldn't happen. FIXME! Json: " << m.toJsonString();
        else {
            // indicate a good request, accepted request
            ++c->info.nRequestsRcv;
            try {
                // call ptr to member -- note member is free to throw if it wants to send an error immediately
                (this->*member)(c, m);
            } catch (const RPCError & e) {
                emit c->sendError(false, e.code, e.what(), m.id);
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
void Server::onErrorMessage(quint64 clientId, const RPC::Message &m)
{
    Trace() << "onErrorMessage: " << clientId << " json: " << m.toJsonString();
    if (Client *c = getClient(clientId); c) {
        // we never expect client to send us errors. Always return invalid request, disconnect client.
        emit c->sendError(true, RPC::Code_InvalidRequest, "Not a valid request object");
    }
}
void Server::onPeerError(quint64 clientId, const QString &what)
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

// --- RPC METHODS ---
namespace {
    Util::ThreadPool::FailFunc defaultTPFailFunc(Client *c, const RPC::Message::Id &id) {
        return [c, id](const QString &what) {
            emit c->sendError(false, RPC::Code_InternalError, QString("internal error: %1").arg(what), id);
        };
    }
    BitcoinDMgr::FailF defaultBDFailFunc(Client *c, const RPC::Message::Id &id) {
        return [c, id](const RPC::Message::Id &, const QString &what) {
            emit c->sendError(false, RPC::Code_InternalError, QString("internal error: %1").arg(what), id);
        };
    }
}

Server::RPCError::~RPCError() {}

void Server::generic_do_async(Client *c, const RPC::Message::Id &reqId, const std::function<QVariant ()> &work)
{
    if (LIKELY(work)) {
        struct ResErr {
            QVariant results;
            bool error = false;
            QString errMsg;
            int errCode = 0;
        };

        auto reserr = std::make_shared<ResErr>(); ///< shared with lambda for both work and completion. this is how they communicate.

        Util::ThreadPool::SubmitWork(
            c, // <--- all work done in client context, so if client is deleted, completion not called
            // runs in worker thread, must not access anything other than reserr and work
            [reserr,work]{
                try {
                    QVariant result = work();
                    reserr->results.swap( result ); // constant-time copy
                } catch (const RPCError & e) {
                    reserr->error = true;
                    reserr->errMsg = e.what();
                    reserr->errCode = e.code;
                }
            },
            // completion: runs in client thread (only called if client not already deleted)
            [c, reqId, reserr] {
                if (reserr->error) {
                    emit c->sendError(false, reserr->errCode, reserr->errMsg, reqId);
                    return;
                }
                // no error, send results to client
                emit c->sendResult(reqId, reserr->results);
            },
            // default fail function just sends json rpc error "internal error: <message>"
            defaultTPFailFunc(c, reqId)
        );
    } else
        Error() << "INTERNAL ERROR: work must be valid! FIXME!";
}

void Server::generic_async_to_bitcoind(Client *c, const RPC::Message::Id & reqId, const QString &method,
                                       const QVariantList & params,
                                       const BitcoinDSuccessFunc & successFunc,
                                       const BitcoinDErrorFunc & errorFunc)
{
    if (UNLIKELY(QThread::currentThread() != c->thread())) {
        // Paranoia, in case I or a future programmer forgets this rule.
        Warning() << __FUNCTION__ << " is meant to be called from the Client thread only. The current thread is not the"
                  << " Client thread. This may cause problems if the Client is deleted while submitting the request. FIXME!";
    }
    bitcoindmgr->submitRequest(c, newId(), method, params,
        // success
        [c, reqId, successFunc](const RPC::Message & reply) {
            try {
                const QVariant result = successFunc ? successFunc(reply) : reply.result(); // if no successFunc specified, use default which just copies the result to the client.
                emit c->sendResult(reqId, result);
            } catch (const RPCError &e) {
                emit c->sendError(false, e.code, e.what(), reqId);
            } catch (const std::exception &e) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError, e.what(), reqId);
            }
        },
        // error
        [c, reqId, errorFunc](const RPC::Message & errorReply) {
            try {
                if (errorFunc)
                    errorFunc(errorReply); // this should throw RPCError
                throw RPCError(errorReply.errorMessage(), RPC::Code_App_DaemonError);
            } catch (const RPCError &e) {
                emit c->sendError(false, e.code, e.what(), reqId);
            } catch (const std::exception &e) {
                emit c->sendError(false, RPC::ErrorCodes::Code_InternalError, QString("internal error: %1").arg(e.what()),
                                  reqId);
            }
        },
        // use default function on failure, sends json rpc error "internal error: <message>"
        defaultBDFailFunc(c, reqId)
    );
}

void Server::rpc_server_banner(Client *c, const RPC::Message &m)
{
    // TODO: have this come from a configurable text file, etc
    emit c->sendResult(m.id, QString("Connected to a %1 %2 server").arg(APPNAME).arg(VERSION));
}
void Server::rpc_server_donation_address(Client *c, const RPC::Message &m)
{
    // TODO: have this come from a configuration param, etc
    emit c->sendResult(m.id, QString("bitcoincash:qplw0d304x9fshz420lkvys2jxup38m9symky6k028"));
}
void Server::rpc_server_features(Client *c, const RPC::Message &m)
{
    // TODO: this is an incomplete impl. ("hosts", etc need love, see comments below)
    QVariantMap r;
    r["pruning"] = QVariant(); // null
    r["genesis_hash"] = QString(Util::ToHexFast(storage->genesisHash()));
    r["server_version"] = QString("%1 %2").arg(APPNAME).arg(VERSION);
    r["protocol_min"] = "1.4"; // TODO: have this come from a global constant
    r["protocol_max"] = "1.4.2"; // TODO: have this come from a global constant
    r["hash_function"] = "sha256";
    // TODO: this "hosts" key is a stub.  Its info needs to come from global config announce settings since public
    // host/port is what we should return, not local bind ip, local bind port.
    r["hosts"] = QVariantMap{
        { c->localAddress().toString(), /* TODO: have this NOT be the bind ip but rather come from config "announce" setting */
          QVariantMap{
              { "tcp_port", c->localPort() /* TODO: have this NOT be the bind ip but rather come from config "announce" setting */ }
          }
          // TODO: support SSL
        },
    };
    emit c->sendResult(m.id, r);
}
void Server::rpc_server_peers_subscribe(Client *c, const RPC::Message &m)
{
    // TODO: Implement. See: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#server-peers-subscribe
    emit c->sendResult(m.id, QVariantList());
}
void Server::rpc_server_ping(Client *c, const RPC::Message &m)
{
    emit c->sendResult(m.id);
}
void Server::rpc_server_version(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 2);
    c->info.userAgent = l[0].toString().left(kMaxServerVersion);
    c->info.protocolVersion = l[1].toString().left(kMaxServerVersion);
    emit c->sendResult(m.id, QStringList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
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
    constexpr double dummyReply = 0.00001000;
    emit c->sendResult(m.id, dummyReply);
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
        Debug() << c->prettyName() << " is now subscribed to headers";
    } else {
        Debug() << c->prettyName() << " was already subscribed to headers, ignoring duplicate subscribe request";
    }
    emit c->sendResult(m.id, mkResp(unsigned(std::max(0, height)), hdr));
}
void Server::rpc_blockchain_relayfee(Client *c, const RPC::Message &m)
{
    // TODO: Implement this
    constexpr double dummyReply = 0.00001000;
    emit c->sendResult(m.id, dummyReply);
}
void Server::rpc_blockchain_scripthash_get_balance(Client *c, const RPC::Message &m)
{
    QVariantList l(m.paramsList());
    assert(!l.isEmpty());
    const QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    generic_do_async(c, m.id, [sh, this] {
        const bitcoin::Amount amt = storage->getBalance(sh);
        /* Note: ElectrumX protocol docs are incorrect. They claim a string in coin units is returned here.
         * It is not. Instead a number in satoshis is returned!
         * Incorrect docs: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-balance */
        QVariantMap resp{
          { "confirmed" , qlonglong(amt / amt.satoshi()) },
          { "unconfirmed" , 0 }, /* TODO: unconfirmed */
        };
        return resp;
    });
}
void Server::rpc_blockchain_scripthash_get_history(Client *c, const RPC::Message &m)
{
    QVariantList l(m.paramsList());
    assert(!l.isEmpty());
    const QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    generic_do_async(c, m.id, [sh, this] {
        QVariantList resp;
        const auto items = storage->getHistory(sh); // these are already sorted
        for (const auto & item : items) {
            resp.push_back(QVariantMap{
                { "tx_hash" , Util::ToHexFast(item.hash) },
                { "height", item.height },
                // mempool tx's here would also have "fee"!  (basically the contents of get_mempool concatenated) <--- TODO
            });
        }
        return resp;
    });
}
void Server::rpc_blockchain_scripthash_get_mempool(Client *c, const RPC::Message &m)
{
    QVariantList l(m.paramsList());
    assert(!l.isEmpty());
    const QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    emit c->sendResult(m.id, QVariantList()); // always return empty mempool for now in this stub
    // NOT YET IMPLEMENTED. TODO: Implement!
    //throw RPCError("not yet implemented", RPC::Code_InternalError);
    /* Not yet implemented.. this is what the possible implementation would look like
    generic_do_async(c, m.id, [sh, this] {
        QVariantList resp;
        const auto items = storage->getMempool(sh); // these are already sorted
        for (const auto & item : items) {
            resp.push_back(QVariantMap{
                { "tx_hash" , Util::ToHexFast(item.hash) },
                { "height", item.height },  // should be 0 for "no unconfirmed parent", -1 for "has unconfirmed parent"
                { "fee", item.fee }, // fee (int64) in satoshis
            });
        }
        return QVariant(resp);
    });
    */
}
void Server::rpc_blockchain_scripthash_listunspent(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(!l.isEmpty());
    const QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    generic_do_async(c, m.id, [sh, this] {
        QVariantList resp;
        const auto items = storage->listUnspent(sh); // these are already sorted
        for (const auto & item : items) {
            resp.push_back(QVariantMap{
                { "tx_hash" , Util::ToHexFast(item.hash) },
                { "tx_pos"  , item.tx_pos },
                { "height", item.height },  // confirmed height. TODO: should be 0 for mempool regardless of unconf. parent status. Note this differs from get_mempool or get_history
                { "value", qlonglong(item.value / item.value.satoshi()) }, // amount (int64) in satoshis
            });
        }
        return resp;
    });
}
void Server::rpc_blockchain_scripthash_subscribe(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 1);
    // this isn't really implemented. this is a stub that just returns the immediate status, but doesn't actually
    // subscribe for notifications.
    QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    generic_do_async(c, m.id, [sh, this] {
        QVariant ret;
        // note: this returns just the status hex as a string. The notification will be: [scriptHash, statusHex]
        const auto hist = storage->getHistory(sh);
        if (hist.empty())
            // no history, always return 'null'
            return ret;
        QString historyString;
        {
            QTextStream ts(&historyString, QIODevice::WriteOnly);
            for (const auto & item : hist) {
                ts << Util::ToHexFast(item.hash) << ":" << item.height << ":";
            }
        }
        // scritphash status is non-reversed, single sha256
        const QByteArray historyHex = Util::ToHexFast(BTC::HashOnce(historyString.toUtf8()));
        return QVariant(QString::fromUtf8(historyHex));
    });
}
void Server::rpc_blockchain_scripthash_unsubscribe(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 1);
    // this isn't really implemented. this is a stub.
    QByteArray sh = validateHashHex( l.front().toString() );
    if (sh.length() != HashLen)
        throw RPCError("Invalid scripthash");
    emit c->sendResult(m.id, QVariant(true)); // dummy response. in future returns true if unsub'd (was sub'd), false otherwise.
}
void Server::rpc_blockchain_transaction_broadcast(Client *c, const RPC::Message &m)
{
    QVariantList l = m.paramsList();
    assert(l.size() == 1);
    QByteArray rawtxhex = l.front().toString().left(kMaxTxHex).toUtf8(); // limit raw hex to sane length.
    // no need to validate hex here -- bitcoind does validation for us!
    generic_async_to_bitcoind(c, m.id, "sendrawtransaction", QVariantList{ rawtxhex },
        // use the default success func, which just echoes the bitcoind reply to the client
        BitcoinDSuccessFunc(),
        // error func, throw an RPCError that's formatted in a particular way
        [](const RPC::Message & errResponse) {
            throw RPCError(QString("the transaction was rejected by network rules.\n\n"
                                   // Note: ElectrumX here would also spit back the [txhex] after the final newline.
                                   // We do not do that, since it's a waste of bandwidth and also Electron Cash
                                   // ignores that information anyway.
                                   "%1\n").arg(errResponse.errorMessage()),
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
    // this is a stub
    emit c->sendResult(m.id, QVariantList());
}
// --- Server::StaticData Definitions ---
#define HEY_COMPILER_PUT_STATIC_HERE(x) decltype(x) x
#define PR RPC::Method::PosParamRange
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::dispatchTable);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::methodMap);
HEY_COMPILER_PUT_STATIC_HERE(Server::StaticData::registry){
/*  ==> Note: Add stuff to this table when adding new RPC methods.
    { {"rpc.name",                allow_requests, allow_notifications, PosParamRange, (QSet<QString> note: {} means undefined optional)}, &method_to_call }     */
    { {"server.banner",                     true,               false,    PR{0,0},      RPC::KeySet{} },          &Server::rpc_server_banner },
    { {"server.donation_address",           true,               false,    PR{0,0},                    },          &Server::rpc_server_donation_address },
    { {"server.features",                   true,               false,    PR{0,0},                    },          &Server::rpc_server_features },
    { {"server.peers.subscribe",            true,               false,    PR{0,0},                    },          &Server::rpc_server_peers_subscribe },
    { {"server.ping",                       true,               false,    PR{0,0},                    },          &Server::rpc_server_ping },
    { {"server.version",                    true,               false,    PR{2,2},                    },          &Server::rpc_server_version },

    { {"blockchain.block.header",           true,               false,    PR{1,2},                    },          &Server::rpc_blockchain_block_header },
    { {"blockchain.block.headers",          true,               false,    PR{2,3},                    },          &Server::rpc_blockchain_block_headers },
    { {"blockchain.estimatefee",            true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_estimatefee },
    { {"blockchain.headers.subscribe",      true,               false,    PR{0,0},                    },          &Server::rpc_blockchain_headers_subscribe },
    { {"blockchain.relayfee",               true,               false,    PR{0,0},                    },          &Server::rpc_blockchain_relayfee },

    { {"blockchain.scripthash.get_balance", true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_get_balance },
    { {"blockchain.scripthash.get_history", true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_get_history },
    { {"blockchain.scripthash.get_mempool", true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_get_mempool },
    { {"blockchain.scripthash.listunspent", true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_listunspent },
    { {"blockchain.scripthash.subscribe",   true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_subscribe },
    { {"blockchain.scripthash.unsubscribe", true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_scripthash_unsubscribe },

    { {"blockchain.transaction.broadcast",  true,               false,    PR{1,1},                    },          &Server::rpc_blockchain_transaction_broadcast },
    { {"blockchain.transaction.get",        true,               false,    PR{1,2},                    },          &Server::rpc_blockchain_transaction_get },
    { {"blockchain.transaction.get_merkle", true,               false,    PR{2,2},                    },          &Server::rpc_blockchain_transaction_get_merkle },
    { {"blockchain.transaction.id_from_pos",true,               false,    PR{2,3},                    },          &Server::rpc_blockchain_transaction_id_from_pos },

    { {"mempool.get_fee_histogram",         true,               false,    PR{0,0},                    },          &Server::rpc_mempool_get_fee_histogram },
};
#undef PR
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

// --- SSL Server support ---
ServerSSL::ServerSSL(const QSslCertificate & cert, const QSslKey & key, const QHostAddress & address, quint16 port_,
                     std::shared_ptr<Storage> storage, std::shared_ptr<BitcoinDMgr> bitcoindmgr)
    : Server(address, port_, storage, bitcoindmgr), cert(cert), key(key)
{
    if (cert.isNull() || key.isNull())
        throw BadArgs("ServerSSL cannot be instantiated: Key or cert are null!");
    if (!QSslSocket::supportsSsl())
        throw BadArgs("ServerSSL cannot be instantiated: Missing SSL support!");
    connect(this, &ServerSSL::ready, this, []{
        Debug() << "SSL ready emitted";
    });
    setObjectName(prettyName());
    _thread.setObjectName(prettyName());
}
ServerSSL::~ServerSSL() {}
QString ServerSSL::prettyName() const
{
    return QString("Ssl%1").arg(AbstractTcpServer::prettyName());
}
void ServerSSL::incomingConnection(qintptr socketDescriptor)
{
    QSslSocket *socket = new QSslSocket(this);
    if (socket->setSocketDescriptor(socketDescriptor)) {
        socket->setLocalCertificate(cert);
        socket->setPrivateKey(key);
        socket->setProtocol(QSsl::SslProtocol::AnyProtocol);
        connect(socket, &QSslSocket::encrypted, this, &ServerSSL::ready);
        connect(socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors),
                this, [](const QList<QSslError> & errors) {
                    for (auto e : errors)
                        Warning() << "SSL error: " << e.errorString();
        });
        addPendingConnection(socket);
        socket->startServerEncryption();
    } else {
        Warning() << "setSocketDescriptor returned false -- unable to initiate SSL for client: " << socket->errorString();
        delete socket;
    }
}

// --- /SSL Server support ---

Client::Client(const RPC::MethodMap & mm, quint64 id_in, Server *srv, QTcpSocket *sock)
    : RPC::LinefeedConnection(mm, id_in, sock, kMaxBuffer), srv(srv)
{
    socket = sock;
    stale_threshold = 10 * 60 * 1000; // 10 mins stale threshold; after which clients get disconnected for being idle (for now... TODO: make this configurable)
    pingtime_ms = int(stale_threshold); // this determines how often the pingtimer fires
    Q_ASSERT(socket->state() == QAbstractSocket::ConnectedState);
    status = Connected ; // we are always connected at construction time.
    errorPolicy = ErrorPolicySendErrorMessage;
    setObjectName(QString("Client.%1").arg(id_in));
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
