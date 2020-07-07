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
#include "RPC.h"
#include "WebSocket.h"
#include <QtCore>

#include <QHostAddress>
#include <QSslSocket>

#include <type_traits>

namespace RPC {

    const QString jsonRpcVersion("2.0");
    namespace { const QString rpcDot("rpc."); } // "static"

    /*static*/ const QString Message::s_code("code");
    /*static*/ const QString Message::s_data("data");
    /*static*/ const QString Message::s_error("error");
    /*static*/ const QString Message::s_id("id");
    /*static*/ const QString Message::s_jsonrpc("jsonrpc");
    /*static*/ const QString Message::s_message("message");
    /*static*/ const QString Message::s_method("method");
    /*static*/ const QString Message::s_params("params");
    /*static*/ const QString Message::s_result("result");


    /* static */
    Message Message::fromUtf8(const QByteArray &ba, Id *id_out, bool v1)
    {
        return fromJsonData(Json::parseUtf8(ba, Json::ParseOption::RequireObject).toMap(), id_out, v1); // may throw
    }

    /* static */
    Message Message::fromJsonData(const QVariantMap & map, Id * id_out, bool v1)
    {
        Message ret;
        ret.v1 = v1;
        ret.data = map;

        if (id_out)
            id_out->clear();

        try {
            ret.id = Id::fromVariant(map.value(s_id));
            if (id_out)
                *id_out = ret.id;
        } catch (const BadArgs & e) {
            throw InvalidError(QString("Error parsing JSON key \"%1\": %2").arg(s_id).arg(e.what()));
        }

        if (QString ver; !v1 && (ver=ret.jsonRpcVersion()) != RPC::jsonRpcVersion) {// we ignore this key in v1
            if (!ver.isEmpty())
                throw InvalidError(QString("Expected jsonrpc version %1").arg(RPC::jsonRpcVersion));
            // It turns out Electron Cash doesn't even send this key, even though JSON 2.0 spec specifies it. We accept
            // requests without it if the key is missing entirely, and "fake" it so below code works (what follows is
            // code that was originally written assuming the key is there).
            ret.data[s_jsonrpc] = RPC::jsonRpcVersion;
        }

        if (auto var = map.value(s_method);
                map.contains(s_method) && (QMetaType::Type(var.type()) != QMetaType::QString
                                           || (ret.method = var.toString()).isEmpty()
                                           || ret.method.startsWith(rpcDot/*="rpc."*/)))
            throw InvalidError("Invalid method");

        // TODO: see if the below validation needs optimization

        // validate error as per JSON RPC 2.0 (or 1.0 if v1 is true)
        if (ret.isError()) {
            auto errmap = ret.data.value(s_error).toMap();
            if (!errmap.contains(s_code) || !errmap.contains(s_message))
                throw InvalidError("Expected error object to contain code and message");
            if (!v1) { // we are more lax for v1
                int n_req = errmap.contains(s_data) ? 3 : 2;
                if (errmap.count() != n_req)
                    throw InvalidError("Unexpected keys in error object");
                bool ok;
                if (int code = errmap.value(s_code).toInt(&ok); !ok || errmap.value(s_code).toString() != QString::number(code))
                    throw InvalidError("Expected error code to be an integer");
                static const KeySet required{ s_id, s_error, s_jsonrpc };
                if (required !=
#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
                        KeySet::fromList(ret.data.keys())
#else
                        Util::toCont<KeySet>(ret.data.keys())
#endif
                    )
                    throw InvalidError("Error response not valid");
            }
        }
        // validate request as per JSON RPC 2.0 (or 1.0 if v1 is true)
        else if (ret.isRequest()) {
            const bool hasParams = ret.hasParams();
            if (!v1) {
                const int n_ok = hasParams ? 4 : 3;
                if (ret.data.count() != n_ok)
                    throw InvalidError("Invalid request");
            }
            if (hasParams && !ret.isParamsMap() && !ret.isParamsList())
                throw InvalidError("Invalid params");
        }
        else if (ret.isNotif()) {
            const bool hasParams = ret.hasParams();
            if (!v1) {
                const int n_ok = hasParams ? 3 : 2;
                if (ret.data.count() != n_ok)
                    throw InvalidError("Invalid notification");
            }
            if (hasParams && !ret.isParamsMap() && !ret.isParamsList())
                throw InvalidError("Invalid params");
        }
        else if (ret.isResponse()) {
            if (!v1) {
                const int n_ok = 3;
                if (ret.data.count() != n_ok)
                    throw InvalidError("Invalid response");
            }
        }
        else {
            throw InvalidError("Invalid JSON RPC object");
        }

        // if we get to this point, the json meets minimal JSON RPC specs.

        return ret;
    }

    /* static */
    Message Message::makeError(int code, const QString &message, const Id & id, bool v1)
    {
        Message ret;
        auto & map = ret.data;
        if (!v1)
            map[s_jsonrpc] = RPC::jsonRpcVersion;
        ret.v1 = v1;
        ret.id = id;
        map[s_id] = id.toVariant(); // may be "null"
        QVariantMap errMap;
        errMap[s_code] = code;
        errMap[s_message] = message;
        map[s_error] = errMap;
        return ret;
    }

    /// uses provided schema -- will not throw exception
    /*static*/
    Message Message::makeResponse(const Id & reqId, const QVariant & result, bool v1)
    {
        Message ret;
        ret.v1 = v1;
        auto & map = ret.data;
        if (!v1)
            map[s_jsonrpc] = RPC::jsonRpcVersion;
        else
            map[s_error] = QVariant(); // v1: always set the "error" key to null
        map[s_id] = reqId.toVariant();
        map[s_result] = result;
        ret.id = reqId;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantList & params, bool v1)
    {
        Message ret = makeNotification(methodName, params, v1);
        auto & map = ret.data;
        map[s_id] = id.toVariant();
        ret.id = id;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantMap & params, bool v1)
    {
        Message ret = makeNotification(methodName, params, v1);
        auto & map = ret.data;
        map[s_id] = id.toVariant();
        ret.id = id;
        return ret;
    }

    /* static */
    Message Message::makeNotification(const QString &methodName, const QVariantList & params, bool v1)
    {
        Message ret;
        ret.v1 = v1;
        auto & map = ret.data;
        if (!v1)
            map[s_jsonrpc] = RPC::jsonRpcVersion;
        else
            map[s_id] = QVariant(); // v1: always has the "id" key as null for a notif
        map[s_method] = methodName;
        map[s_params] = params;
        ret.method = methodName;
        return ret;
    }

    /* static */
    Message Message::makeNotification(const QString &methodName, const QVariantMap & params, bool v1)
    {
        Message ret;
        ret.v1 = v1;
        auto & map = ret.data;
        if (!v1)
            map[s_jsonrpc] = RPC::jsonRpcVersion;
        else
            map[s_id] = QVariant(); // v1: always has the "id" key as null for a notif
        map[s_method] = methodName;
        map[s_params] = params;
        ret.method = methodName;
        return ret;
    }

    ConnectionBase::ConnectionBase(const MethodMap & methods, IdMixin::Id id_in, QObject *parent, qint64 maxBuffer_)
        : AbstractConnection(id_in, parent, maxBuffer_), methods(methods)
    {
    }

    ConnectionBase::~ConnectionBase() {}

    void ConnectionBase::on_connected()
    {
        AbstractConnection::on_connected();
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &ConnectionBase::sendRequest, this, &ConnectionBase::_sendRequest));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &ConnectionBase::sendNotification, this, &ConnectionBase::_sendNotification));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &ConnectionBase::sendError, this, &ConnectionBase::_sendError));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &ConnectionBase::sendResult, this, &ConnectionBase::_sendResult));
    }

    void ConnectionBase::on_disconnected()
    {
        AbstractConnection::on_disconnected(); // will auto-disconnect all QMetaObject::Connections appearing in connectedConns
        nUnansweredLifetime += quint64(idMethodMap.size());
        idMethodMap.clear();
    }

    auto ConnectionBase::stats() const -> Stats
    {
        auto m = AbstractConnection::stats().toMap();
        m["nRequestsSent"] = nRequestsSent;
        m["nResultsSent"] = nResultsSent;
        m["nErrorsSent"] = nErrorsSent;
        m["nNotificationsSent"] = nNotificationsSent;
        m["nUnansweredRequests"] = nUnansweredLifetime + quint64(idMethodMap.size()); // we may care about this
        m["nErrorReplies"] = nErrorReplies;
        return m;
    }

    void ConnectionBase::_sendRequest(const Message::Id & reqid, const QString &method, const QVariantList & params)
    {
        if (status != Connected || !socket) {
            DebugM(__func__, " method: ", method, "; Not connected! ", "(id: ", this->id, "), forcing on_disconnect ...");
            // the below ensures socket cleanup code runs.  This guarantees a disconnect & cleanup on bad socket state.
            do_disconnect();
            return;
        }
        const QByteArray jsonData = Message::makeRequest(reqid, method, params, v1).toJsonUtf8();
        if (jsonData.isEmpty()) {
            Error() << __func__ << " method: " << method << "; Unable to generate request JSON! FIXME!";
            return;
        }
        if (idMethodMap.size() >= MAX_UNANSWERED_REQUESTS) {  // prevent memory leaks in case of misbehaving peer
            Warning() << "Closing connection because too many unanswered requests for: " << prettyName();
            do_disconnect();
            return;
        }
        idMethodMap[reqid] = method; // remember method sent out to associate it back.

        TraceM("Sending json: ", Util::Ellipsify(jsonData));
        ++nRequestsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(jsonData) );
    }
    void ConnectionBase::_sendNotification(const QString &method, const QVariant & params)
    {
        if (status != Connected || !socket) {
            DebugM(__func__, " method: ", method, "; Not connected! ", "(id: ", this->id, "), forcing on_disconnect ...");
            // the below ensures socket cleanup code runs.  This guarantees a disconnect & cleanup on bad socket state.
            do_disconnect();
            return;
        }
        QByteArray json;
        if (params.canConvert<QVariantMap>()) {
            json = Message::makeNotification(method, params.toMap(), v1).toJsonUtf8();
        } else if (params.canConvert<QVariantList>()) {
            json = Message::makeNotification(method, params.toList(), v1).toJsonUtf8();
        } else {
            Error() << __func__ << " method: " << method << "; Notification requires either a QVarantList or a QVariantMap as its argument! FIXME!";
            return;
        }
        if (json.isEmpty()) {
            Error() << __func__ << " method: " << method << "; Unable to generate notification JSON! FIXME!";
            return;
        }
        TraceM("Sending json: ", Util::Ellipsify(json));
        ++nNotificationsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(json) );
    }
    void ConnectionBase::_sendError(bool disc, int code, const QString &msg, const Message::Id & reqId)
    {
        if (status != Connected || !socket) {
            DebugM(__func__, "; Not connected! ", "(id: ", this->id, "), forcing on_disconnect ...");
            // the below ensures socket cleanup code runs.  This guarantees a disconnect & cleanup on bad socket state.
            do_disconnect();
            return;
        }
        const QByteArray json = Message::makeError(code, msg, reqId, v1).toJsonUtf8();
        TraceM("Sending json: ", Util::Ellipsify(json));
        ++nErrorsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(json) );
        if (disc) {
            do_disconnect(true); // graceful disconnect
        }
    }
    void ConnectionBase::_sendResult(const Message::Id & reqid, const QVariant & result)
    {
        if (status != Connected || !socket) {
            DebugM(__func__, ":  Not connected! ", "(id: ", this->id, "), forcing on_disconnect ...");
            // the below ensures socket cleanup code runs.  This guarantees a disconnect & cleanup on bad socket state.
            do_disconnect();
            return;
        }
        const QByteArray json = Message::makeResponse(reqid, result, v1).toJsonUtf8();
        if (json.isEmpty()) {
            Error() << __func__ << ": Unable to generate result JSON! FIXME!";
            return;
        }
        TraceM("Sending result json: ", Util::Ellipsify(json));
        ++nResultsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(json) );
    }

    void ConnectionBase::processJson(const QByteArray &json)
    {
        if (ignoreNewIncomingMessages) {
            // This is only ever latched to true in the "Client" subclass and it signifies that the client is being
            // dropped and so we have this short-circuit conditional to save on cycles in that situation and not
            // bother processing further messages.
            DebugM("ignoring ", json.length(), " byte incoming message from ", id);
            return;
        }
        Message::Id msgId;
        try {
            Message message = Message::fromUtf8(json, &msgId, v1); // may throw

            static const auto ValidateParams = [](const Message &msg, const Method &m) {
                if (!msg.hasParams()) {
                    if ( (m.opt_kwParams.has_value() && !m.opt_kwParams->isEmpty())
                         || (m.opt_nPosParams.has_value() && m.opt_nPosParams->first != 0) )
                        throw InvalidParameters("Missing required params");
                } else if (msg.isParamsList()) {
                    // positional args specified
                    if (!m.opt_nPosParams.has_value())
                        throw InvalidParameters("Postional params are not supported for this method");
                    const unsigned num = unsigned(msg.paramsList().count());
                    auto [minParams, maxParams] = *m.opt_nPosParams;
                    if (maxParams < minParams) maxParams = minParams;
                    if (num < minParams)
                        throw InvalidParameters(QString("Expected at least %1 %2 for %3, got %4 instead")
                                                .arg(minParams).arg(Util::Pluralize("parameter", minParams))
                                                .arg(m.method).arg(num));
                    if (num > maxParams)
                        throw InvalidParameters(QString("Expected at most %1 %2 for %3, got %4 instead")
                                                .arg(maxParams).arg(Util::Pluralize("parameter", maxParams))
                                                .arg(m.method).arg(num));
                } else if (msg.isParamsMap()) {
                    // named args specified
                    if (!m.opt_kwParams.has_value())
                        throw InvalidParameters("Named params are not supported for this method");
                    const auto nameset =
 #if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
                            KeySet::fromList(msg.paramsMap().keys()); // TODO: this is not the most efficient -- for now this isn't used except for AdminServer, so it's fine.
 #else
                            Util::toCont<KeySet>(msg.paramsMap().keys());
 #endif
                    const auto & kwSet = *m.opt_kwParams;
                    if (m.allowUnknownNamedParams) {
                        if (!(kwSet - nameset).isEmpty())
                            throw InvalidParameters("Required parameters missing");
                    } else {
                        if (nameset != kwSet)
                            throw InvalidParameters("Unknown or missing parameters");
                    }
                }
            };

            if (message.isError()) {
                // error message
                ++nErrorReplies;
                idMethodMap.remove(message.id); // don't leak the request -- an error response is an answer! Remove from map.
                emit gotErrorMessage(id, message);
            } else if (message.isNotif()) {
                try {
                    const auto it = methods.find(message.method);
                    if (it == methods.end())
                        throw UnknownMethod("Unknown method");
                    const Method & m = it.value();
                    if (m.allowsNotifications) {
                        ValidateParams(message, m);
                        emit gotMessage(id, message);
                    } else {
                        throw Exception(QString("Ignoring unexpected notification"));
                    }
                } catch (const Exception & e) {
                    // Note: we emit peerError here so that the tally of number of errors goes up and we eventually disconnect the offending peer.
                    // This should not cause an error message to be sent to the peer.
                    emit peerError(this->id, lastPeerError=QString("Error processing notification '%1' from %2: %3").arg(message.method, prettyName(), e.what()));
                }
            } else if (message.isRequest()) {
                const auto it = methods.find(message.method);
                const Method *m = it != methods.end() ? &it.value() : nullptr;
                if (!m || !m->allowsRequests)
                    throw UnknownMethod(QString("Unsupported request: %1").arg(message.method));
                ValidateParams(message, *m);
                emit gotMessage(id, message);
            } else if (message.isResponse()) {
                QString meth = idMethodMap.take(message.id);
                if (meth.isEmpty()) {
                    throw BadPeer(QString("Unexpected response (id: %1)").arg(message.id.toString()));
                }
                message.method = meth;
                emit gotMessage(id, message);
            } else {
                // Not a Request and not a Response or Notification or Error. Not JSON-RPC 2.0.
                throw InvalidRequest("Invalid JSON");
            }
            lastGood = Util::getTime(); // update "lastGood" as this is used to determine if stale or not.
        } catch (const Exception &e) {
            // TODO: clean this up. It's rather inelegant. :/
            const bool wasJsonParse = dynamic_cast<const Json::ParseError *>(&e);
            const bool wasUnk = dynamic_cast<const UnknownMethod *>(&e);
            const bool wasInv = dynamic_cast<const InvalidRequest *>(&e) || dynamic_cast<const InvalidError *>(&e);
            const bool wasInvParms = dynamic_cast<const InvalidParameters *>(&e);
            int code = Code_Custom;
            if (wasJsonParse) code = Code_ParseError;
            else if (wasInvParms) code = Code_InvalidParams;
            else if (wasUnk) code = Code_MethodNotFound;
            else if (wasInv) code = Code_InvalidRequest;
            bool doDisconnect = errorPolicy & ErrorPolicyDisconnect;
            if (errorPolicy & ErrorPolicySendErrorMessage) {
                emit sendError(doDisconnect, code, QString(e.what()).left(120), msgId);
                if (!doDisconnect)
                    emit peerError(id, lastPeerError=e.what());
                doDisconnect = false; // if was true, already enqueued graceful disconnect after error reply, if was false, no-op here
            }
            if (doDisconnect) {
                Error() << "Error reading/parsing data coming in: " << (lastPeerError=e.what());
                do_disconnect();
                status = Bad;
            }
        } catch (const std::exception &e) {
            // Other low-level error such as bad_alloc, etc. This is very unlikely. We simply disconnect and give up.
            Error() << prettyName(false, true) << ": Low-level error reading/parsing data coming in: " << (lastPeerError=e.what());
            do_disconnect();
            status = Bad;
        } // end try/catch
    }

    /* --- LinefeedConnection --- */
    ElectrumConnection::~ElectrumConnection() {} ///< for vtable

    WebSocket::Wrapper *ElectrumConnection::checkSetGetWebSocket()
    {
        WebSocket::Wrapper *ws = webSocket.value_or(nullptr);

        if (socket && ( !webSocket.has_value() || (ws && socket != ws) )) { // <--- checks if it's not yet defined or if the underlying socket has changed between calls
            webSocket = ws = dynamic_cast<WebSocket::Wrapper *>(socket);
        }
        return ws;
    }

    bool ElectrumConnection::isWebSocket() const
    {
        if (thread() == QThread::currentThread()) // ensure safe usage
            return const_cast<ElectrumConnection *>(this)->checkSetGetWebSocket();
        return false;
    }

    bool ElectrumConnection::isSsl() const
    {
        if (thread() == QThread::currentThread()) {// ensure safe usage
            auto ws = const_cast<ElectrumConnection *>(this)->checkSetGetWebSocket();
            QTcpSocket * const underlying = ws ? ws->wrappedSocket() : socket;
            return dynamic_cast<QSslSocket *>(underlying);
        }
        return false;
    }

    void ElectrumConnection::on_readyRead()
    {
        TraceM(__func__);
        WebSocket::Wrapper * const ws = checkSetGetWebSocket();
        assert(!ws || ws == socket);  // If `ws` is not null, then `ws` and `socket` must point to the same object.

        // TODO: In the non-WebSocket case, scanning for '\n' may be slow for large loads.
        // Also TODO: This should have some upper bound on how many times it loops and come back later if too much data
        // is available.
        while (!isBad() && socket && (ws ? ws->messagesAvailable() > 0 : socket->canReadLine())) {
            // check if paused -- we may get paused inside processJson below
            if (readPaused) {
                skippedOnReadyRead = true;
                DebugM(prettyName(), " reads paused, skipping on_readyRead",
                       " (bufsz: ", QString::number(socket->bytesAvailable()/1024.0, 'f', 1), " KB) ...");
                break;
            }
            // /pause check
            auto data = ws ? ws->readNextMessage() : socket->readLine();
            nReceived += data.length();
            // may be slow, so use the efficient TraceM
            TraceM("Got: ", (!ws ? data.trimmed() : data));
            processJson(data);
        }
        if (isBad()) { // this may have been set again by processJson() above
            DebugM(prettyName(), " is now bad, ignoring read (buf: ",
                   QString::number((socket ? socket->bytesAvailable() : 0)/1024., 'f', 1), " KB)");
            return;
        }

        // This checks if the client's socket->bytesAvailable() stays >= MAX_BUFFER for longer than 5 seconds,
        // in which case the client is kicked.  Note that a client's bytesAvailable() won't go down if they
        // are being throttled due to many bitcoind requests, but only the strange 3.7.11 clients ever hit MAX_BUFFER
        // here, so it's ok for non-misbehaving, *typical* EC clients to have this check exist here, and it guards
        // against misbehaving clients.  The hope is that by kicking abusing clients, client lib authors will adjust
        // their code.
        memoryWasteDoSProtection();
    }

    void ElectrumConnection::setReadPaused(bool b)
    {
#ifndef NDEBUG
        if (this->thread() != QThread::currentThread()) {
            Error() << __func__ << ": ERROR -- called from a thread outside this object's thread! FIXME!";
            return;
        }
#endif
        if (!!b == !!readPaused)
            return; // already set
        const bool hadSkips = skippedOnReadyRead;
        skippedOnReadyRead = false;
        readPaused = b;
        if (!readPaused && hadSkips)
            // we had some skipped on_readyReads() -- resume
            QTimer::singleShot(0, this, [this]{on_readyRead();} );
    }

    void ElectrumConnection::memoryWasteDoSProtection()
    {
        constexpr const char *memoryWasteTimer = "MemoryWasteDoSTimer";
        constexpr int memoryWasteTimeout = 5000; /// 5 seconds
        // we declare this lamba this way with no captures and static as a performance optimization for the common case
        // where this code passes through doing nothing.  We don't want to be pushing lambdas we never used onto
        // the stack every time this function is called.
        static const auto StopTimer = [](ElectrumConnection *me, qint64 avail) {
            me->memoryWasteTimerActive = false;
            me->stopTimer(memoryWasteTimer);
            DebugM("Memory waste timer STOPPED for ", me->id, " from ", me->peerAddress().toString(),
                   ", read buffer now: ", avail);
        };
        memoryWasteThreshold = MAX_BUFFER;
        if (memoryWasteThreshold < 0) {
            Error() << __func__ << ": MAX_BUFFER is < 0 -- fix me!";
            return;
        }
        // DoS protection logic below for memory exhaustion attacks.  If a client connects from many IPs and with
        // many clients a memory exhaustion attack is possible.  The attack would simply involve filling our buffers
        // and never sending a newline.  The below code detects the situation and disconnects clients whereby too much
        // time has expired (5 seconds) with extant unprocessed read buffers at or past the MAX_BUFFER threshold.
        if (const qint64 avail = socket ? socket->bytesAvailable() : 0;
                UNLIKELY(!memoryWasteTimerActive && avail >= memoryWasteThreshold)) {
            memoryWasteTimerActive = true;
            callOnTimerSoonNoRepeat(memoryWasteTimeout, memoryWasteTimer, [this]{
                if (!memoryWasteTimerActive)
                    Warning() << "Memory waste timer was not active but the timer lambda fired! FIXME!";
                memoryWasteTimerActive = false;
                const qint64 avail = socket ? socket->bytesAvailable() : 0;
                if (avail >= memoryWasteThreshold) {
                    Warning(Log::Magenta)
                            << "Client " << this->id << " from " << this->peerAddress().toString()
                            << " exceeded its \"memory waste threshold\" by filling our receive buffer with "
                            << avail << " bytes for longer than "
                            << QString::number(memoryWasteTimeout/1e3, 'f', 1) << " seconds -- kicking client!";
                    // the below also sets ignoreIncomingMessage = true iff this is of type Client *
                    emit sendError(true, RPC::ErrorCodes::Code_App_ExcessiveFlood,
                                   "Excessive flood, please throttle your client implementation to not do this");
                    status = Bad;
                } else
                    StopTimer(this, avail);
            });
            DebugM("Memory waste timer STARTED for ", this->id, " from ", this->peerAddress().toString(),
                   ", read buffer size: ", avail);
        } else if (UNLIKELY(memoryWasteTimerActive && avail < memoryWasteThreshold)) {
            StopTimer(this, avail);
        }
    }

    QByteArray ElectrumConnection::wrapForSend(const QByteArray &d)
    {
        if (checkSetGetWebSocket()) {
            // in websocket mode we don't wrap anything -- it's already framed.
            return d;
        }
        // regular classic Electrum Cash socket -- newline delimited.
        return d + QByteArrayLiteral("\r\n");
    }

    /* --- HttpConnection --- */
    HttpConnection::~HttpConnection() {} ///< for vtable
    void HttpConnection::setAuth(const QString &username, const QString &password)
    {
        header.authCookie = QStringLiteral("%1:%2").arg(username).arg(password).toUtf8().toBase64();
    }

    struct HttpConnection::StateMachine
    {
        enum State {
            BEGIN=0, HEADER, READING_CONTENT
        };
        State state = BEGIN;
        int status = 0;
        QString statusMsg;
        QString contentType;
        int contentLength = 0;
        QByteArray content = "";
        bool logBad = false;
        bool gotLength = false;
        void clear() { *this = StateMachine(); }
    };
    void HttpConnection::on_readyRead()
    {
        if (!sm)
            // lazy construction first time we need this object. Can't use make_unqiue because we need to specify a deleter.
            sm = std::unique_ptr<StateMachine, SMDel>(new StateMachine, [](StateMachine *sm) { delete sm; });
        if (!socket) {
            // this should never happen. here for paranoia.
            Error() << "on_readyRead with socket == nullptr -- were we called from a defunct timer? FIXME";
            return;
        }
        using St = StateMachine::State;
        try {
            while (sm->state < St::READING_CONTENT  && socket->canReadLine()) {
                // states BEGIN and HEADER are linefeed-based
                QByteArray data = socket->readLine();
                nReceived += data.size();
                data = data.simplified();
                TraceM(__func__, " Got: ", data);
                if (sm->state == St::BEGIN) {
                    // read "HTTP/1.1 200 OK" line
                    auto toks = data.split(' ');
                    if (toks.size() < 3) {
                        // ERROR HERE. Expected eg HTTP/1.1 200 OK, or HTTP/1.1 400 Bad request or HTTP/1.1 500 Internal Server Error
                        throw Exception(QString("Expected HTTP/1.1 line, instead got: %1").arg(QString(data)));
                    }
                    auto proto = toks[0], code = toks[1], msg = toks.mid(2).join(' ');
                    static const QByteArray s_HTTP11("HTTP/1.1");
                    if (proto.toUpper() != s_HTTP11) {
                        // ERROR HERE. Expected HTTP/1.1
                        throw Exception(QString("Protocol not HTTP/1.1: %1").arg(QString(proto)));
                    }
                    if ( (sm->status=code.toInt()) == 0) {
                        // ERROR here, expected integer code
                        throw Exception(QString("Could not parse status code: %1").arg(QString(code)));
                    }
                    if (sm->status != 200 && sm->status != 500) { // bitcoind sends 200 on results= and 500 on error= RPC messages. Everything else is unexpected.
                        Warning() << "Got HTTP status " << sm->status << " " << msg
                                  << (!Trace::isEnabled() ? "; will log the rest of this HTTP response" : "");
                        sm->logBad = true;
                        if (sm->status == 401) // 401 status indicates other side didn't like our auth cookie or we need an auth cookie.
                            emit authFailure(this);
                    }
                    sm->statusMsg = QString::fromUtf8(msg);
                    TraceM("Status message: ", sm->statusMsg);
                    sm->state = St::HEADER;
                } else if (sm->state == St::HEADER) {
                    // read header, line by line
                    if (sm->logBad && !Trace::isEnabled()) {
                        Warning() << sm->status << " (header): " << data;
                    }
                    if (data != "") {
                        // process non-empty HEADER lines...
                        auto toks = data.split(':');
                        if (toks.size() < 2) {
                            // ERROR HERE. Expected header. got non-header.
                            throw Exception(QString("Expected header line: %1").arg(QString(data)));
                        }
                        auto name = toks[0].simplified(), value = toks.mid(1).join(' ').simplified();
                        static const QByteArray s_content_type("content-type"), s_content_length("content-length"),
                                                s_application_json("application/json");
                        if (name.toLower() == s_content_type) {
                            sm->contentType = QString::fromUtf8(value);
                            if (sm->contentType.compare(s_application_json, Qt::CaseInsensitive) != 0) {
                                Warning() << "Got unexpected content type: " << sm->contentType << (!Trace::isEnabled() ? "; will log the rest of this HTTP response" : "");
                                sm->logBad = true;
                            }
                        } else if (name.toLower() == s_content_length) {
                            bool ok = false;
                            sm->contentLength = value.toInt(&ok);
                            if (!ok || sm->contentLength < 0) {
                                // ERROR HERE. Expected numeric length, got nonsense
                                throw Exception(QString("Could not parse content-length: %1").arg(QString(data)));
                            } else if (UNLIKELY(sm->contentLength > MAX_BUFFER)) {
                                // ERROR, defend against memory exhaustion attack.
                                throw Exception(QString("Peer wants to send us more than %1 bytes of data, exceeding our buffer limit!").arg(MAX_BUFFER));
                            }
                            sm->gotLength = true;
                            TraceM("Content length: ", sm->contentLength);
                        }
                    } else {
                        // caught EMPTY line -- this signifies end of header
                        // empty line, advance state
                        if (sm->contentType.isEmpty() || !sm->gotLength) { // enforce server must send us both content-type and content-length, otherwise throw
                            // this is an error condition
                            throw Exception("Premature header end; did not receive BOTH content-type and content-length");
                        }
                        sm->state = St::READING_CONTENT;
                    }
                } // end if state == St::HEADER
            } // end while
            while (sm->state == St::READING_CONTENT && socket->bytesAvailable() > 0 && sm->content.length() < sm->contentLength ) {
                // state READING_CONTENT is not linefeed based but expects sm->contentLenght bytes. read at most that many bytes.
                const qint64 n2read = qMin(socket->bytesAvailable(), qint64(sm->contentLength - sm->content.length()));
                if (QByteArray buf = socket->read(n2read); !buf.isEmpty()) {
                    nReceived += buf.size();
                    sm->content += buf;
                } else {
                    // read 0 bytes, but bytesAvailable was >0, must mean there was some sort of error
                    throw Exception("Read 0 bytes from socket");
                }
            }
            if (sm->state == St::READING_CONTENT && sm->content.length() >= sm->contentLength) {
                // got a full content packet!
                const QByteArray json = sm->content;
                if (sm->content.length() > sm->contentLength) {
                    // this shouldn't happen. if we get here, likely below code will fail with nonsense and connection will be killed. this is here
                    // just as a sanity check.
                    Error() << "Content buffer has extra stuff at the end. Bug in code. FIXME! Crud was: '"
                            << sm->content.mid(sm->contentLength) << "'";
                }
                if (bool trace = Trace::isEnabled(); sm->logBad && !trace)
                    Warning() << sm->status << " (content): " << json.trimmed();
                else if (trace)
                    Trace() << "cl: " << sm->contentLength << " inbound JSON: " << json.trimmed();
                sm->clear(); // reset back to BEGIN state, empty buffers, clean slate.
                processJson(json);
                // If bytesAvailable .. schedule a callback to this function again since we did a partial read just now,
                // and the socket's buffers still have data.
                if (auto avail = socket->bytesAvailable(); avail > 0 && avail <= MAX_BUFFER) {
                    // callback is on socket as receiver this way if socket dies and is deleted, callback never happens.
                    // *taps forehead*
                    QTimer::singleShot(0, socket, [this]{on_readyRead();});
                }
            }
            if (UNLIKELY(socket->bytesAvailable() > MAX_BUFFER)) {
                // this branch normally can't be taken because super class calls setReadBufferSize() on the socket
                // in on_connected, but we leave this code here in the interests of defensive programming.
                throw Exception( QString("Peer backbuffer exceeded %1 bytes! Bad peer?").arg(MAX_BUFFER) );
            }
        } catch (const Exception & e) {
            Error() << prettyName() << " fatal error: " << e.what();
            do_disconnect();
            status = Bad;
        }
    }
    QByteArray HttpConnection::wrapForSend(const QByteArray &data)
    {
        static const QByteArray NL("\r\n"), SLASHN("\n"), EMPTY("");
        QByteArray responseHeader;
        const QByteArray suffix = !data.endsWith(SLASHN) ? NL : EMPTY;
        {
            QTextStream ss(&responseHeader, QIODevice::WriteOnly);
            ss.setCodec(QTextCodec::codecForName("UTF-8"));
            ss << "POST / HTTP/1.1" << NL;
            if (!header.host.isEmpty())
                ss << "Host: " << header.host << NL;
            ss << "Content-Type: application/json-rpc" << NL;
            if (!header.authCookie.isEmpty())
                ss << "Authorization: Basic " << header.authCookie << NL;
            ss << "Content-Length: " << (data.length()+suffix.length()) << NL;
            ss << NL;
        }
        return responseHeader + data + suffix;
    }

    void HttpConnection::setHeaderHost(const QString &s) {
        if (auto trimmed = s.trimmed(); !trimmed.isEmpty())
            header.host = trimmed.toUtf8();
    }

} // end namespace RPC

#if 0
// TESTING
#include <iostream>
namespace RPC {
    /* static */ void HttpConnection::Test()
    {
        std::shared_ptr<HttpConnection> h(new HttpConnection(MethodMap{}, 1), [](HttpConnection *h){
            Debug() << "Calling h->deleteLater...";
            h->deleteLater();
        });
        connect(h.get(), &QObject::destroyed, qApp, [](QObject*){Debug() << "HttpConnection deleted! yay!";});
        h->setV1(true);
        h->errorPolicy = ErrorPolicyDisconnect;
        h->setAuth("CalinsNads", "ENTER PASSWORD HERE");
        h->socket = new QTcpSocket(h.get());
        // below will create circular refs until socket is deleted...
        connect(h->socket, &QAbstractSocket::connected, h.get(), [h]{
            Debug() << h->prettyName() << " connected";
            h->connectedConns.push_back(
                connect(h.get(), &RPC::ConnectionBase::gotMessage, h.get(),
                        [h](qint64 id_in, const RPC::Message &m)
                    {
                        Debug() << "Got message from server: id: " << id_in << " json: " << m.toJsonString();
                    })
            ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
            h->connectedConns.push_back(
                connect(h.get(), &RPC::ConnectionBase::gotErrorMessage, h.get(),
                        [](qint64 id_in, const RPC::Message &m)
                    {
                        Debug() << "Got ERROR message from server: id: " << id_in << " json: " << m.toJsonString();
                    })
            ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
            connect(h.get(), &AbstractConnection::lostConnection, h.get(),
                    [](AbstractConnection *a)
            {
                if (auto h = dynamic_cast<HttpConnection *>(a)) {
                    Debug() << "lost connection, deleting socket. We should also die sometime later...";
                    if (h->socket) { h->socket->deleteLater(); h->socket = nullptr; }
                }
            }, Qt::QueuedConnection);

            auto rgen = QRandomGenerator::securelySeeded();
            const int N = 1000;
            for (int i = 1; i <= N; ++i) {
               // queue up messages
               QTimer::singleShot(0, h.get(), [h]{
                   emit h->sendRequest(newId(), "getblockcount", {});
               });
               QTimer::singleShot(0, h.get(), [h]{
                   emit h->sendRequest(newId(), "getblockchaininfo", {});
               });
               const auto randHeight = rgen.bounded(1, 1000000);
               QTimer::singleShot(0, h.get(), [h, randHeight]{
                   Debug() << "Sending getblockstats " << randHeight << "...";
                   emit h->sendRequest(newId(), "getblockstats", {randHeight});
               });
            }
        });
        h->socketConnectSignals();
        h->socket->connectToHost("192.168.0.15", static_cast<quint16>(8332));
    }
}
#endif
