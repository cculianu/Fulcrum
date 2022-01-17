//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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

#include <atomic>
#include <memory>
#include <type_traits>
#include <utility>

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

    namespace {
        // used internally
        const MethodMap EmptyMethodMap{};
    }

    /* Note that we set `ParserBackend::Default` here, however the actual app default for Fulcrum is
     * `ParserBackend::FastestAvailable` which is set in App.cpp on startup. */
    static std::atomic<Json::ParserBackend> jsonParserBackend = Json::ParserBackend::Default;

    /* static */
    Message Message::fromUtf8(const QByteArray &ba, Id *id_out, bool v1, bool strict)
    {
        const auto backend = jsonParserBackend.load(std::memory_order_relaxed);
        // may throw
        return fromJsonData(Json::parseUtf8(ba, Json::ParseOption::RequireObject, backend).toMap(), id_out, v1, strict);
    }

    /* static */
    Message Message::fromJsonData(const QVariantMap & map, Id * id_out, bool v1, bool strict)
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
            throw InvalidError(QString("Error parsing JSON key \"%1\": %2").arg(s_id, e.what()));
        }

        if (QString ver; !v1 && (ver=ret.jsonRpcVersion()) != RPC::jsonRpcVersion) {// we ignore this key in v1
            if (!ver.isEmpty()) {
                constexpr auto errMsg = "Expected jsonrpc version \"%1\", instead got \"%2\"";
                auto shortVer = ver; // shallow copy
                if (ver.length() > 10)
                    // prevent log file spam DoS by only logging a partial string...
                    shortVer = ver.left(10);
                if (strict)
                    throw InvalidError(QString(errMsg).arg(RPC::jsonRpcVersion, shortVer));
                // Phoenix wallet on BTC actually sends the out-of-spec key: "jsonrpc": "1.0" here. It's not clear
                // what to do here. We will just proceed along as if nothing happened, keeping the same string for
                // "jsonrpc" that they gave us and hope for the best!  We won't parse the string at all and we won't
                // even change the protocol version internally to `ret.v1 = true`.  Phoenix seems to work ok if we do
                // things this way.  Previously Fulcrum used to throw an error here and refuse to proceed, but we
                // decided to be more permissive. See issue: https://github.com/cculianu/Fulcrum/issues/91
                DebugM(QString(errMsg).arg(RPC::jsonRpcVersion, shortVer));
                if (shortVer.length() < ver.length()) {
                    // However, we *DO* prevent memory exhaustion DoS by not "remembering" a potentially huge version
                    // string that we can't even understand.. instead, we accept up to 10 characters of it.
                    ret.data[s_jsonrpc] = shortVer;
                    DebugM("Got excessively long, out-of-spec \"jsonrpc\" value of length ", ver.length(),
                           " (we truncated it to length ", shortVer.length(), ")");
                }
            } else {
                // It turns out Electron Cash doesn't even send this key, even though JSON 2.0 spec specifies it. We
                // accept requests without it if the key is missing entirely, and "fake" it so below code works (what
                // follows is code that was originally written assuming the key is there).
                ret.data[s_jsonrpc] = RPC::jsonRpcVersion;
            }
        }

        if (auto var = map.value(s_method);
                map.contains(s_method) && (!Compat::IsMetaType(var, QMetaType::QString)
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

    ConnectionBase::ConnectionBase(const MethodMap * methods_, IdMixin::Id id_in, QObject *parent, qint64 maxBuffer_)
        : AbstractConnection(id_in, parent, maxBuffer_), methods(methods_ ? *methods_ : EmptyMethodMap)
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

        if (batchPermitted && !(errorPolicy & ErrorPolicySendErrorMessage || errorPolicy & ErrorPolicyDisconnect))
            Warning() << prettyName() << ": batching enabled for connection but error policy flags (" << errorPolicy
                      << ") may lead to out-of-spec or confusing JSON-RPC behavior. FIXME!";
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
        if (batchPermitted || !extantBatchProcessors.isEmpty()) {
            m["extantBatchProcessors"] = [this]{
                QVariantMap bps;
                for (auto *bp : extantBatchProcessors)
                    bps[bp->objectName()] = bp->statsSafe();
                return bps;
            }();
        }
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
        QByteArray jsonData = Message::makeRequest(reqid, method, params, v1).toJsonUtf8();
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
        emit send( wrapForSend(std::move(jsonData)) );
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
        emit send( wrapForSend(std::move(json)) );
    }
    void ConnectionBase::_sendError(bool disc, int code, const QString &msg, const Message::Id & reqId)
    {
        if (status != Connected || !socket) {
            DebugM(__func__, "; Not connected! ", "(id: ", this->id, "), forcing on_disconnect ...");
            // the below ensures socket cleanup code runs.  This guarantees a disconnect & cleanup on bad socket state.
            do_disconnect();
            return;
        }
        QByteArray json;
        {
            Message m = Message::makeError(code, msg, reqId, v1);

            // first, see if the error response corresponds to an extant batch request
            if (batchResponseFilter(m))
                // an extant batch slurped up this response. Don't send it to client.
                return;

            // otherwise produce some Json right now and send it out to the client
            json = m.toJsonUtf8();
        }
        TraceM("Sending json: ", Util::Ellipsify(json));
        ++nErrorsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(std::move(json)) );
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

        QByteArray json;
        {
            Message m = Message::makeResponse(reqid, result, v1);

            // first, see if the response corresponds to an extant batch request
            if (batchResponseFilter(m))
                // an extant batch slurped up this response. Don't send it to client.
                return;

            // otherwise produce some Json right now and send it out to the client
            json = m.toJsonUtf8();
        }
        if (json.isEmpty()) {
            Error() << __func__ << ": Unable to generate result JSON! FIXME!";
            return;
        }
        TraceM("Sending result json: ", Util::Ellipsify(json));
        ++nResultsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(std::move(json)) );
    }

    bool ConnectionBase::batchResponseFilter(const Message & msg)
    {
        // first, see if the response corresponds to an extant batch request
        for (auto * batch : qAsConst(extantBatchProcessors)) {
            if (batch->acceptResponse(msg)) {
                batchZombies.remove(msg.id); // also remove from batchZombies, just in case (this should never happen)
                return true;
            }
        }
        if (batchZombies.contains(msg.id)) {
            batchZombies.remove(msg.id);
            DebugM(prettyName(), ": message id \"", msg.id.toString(), "\" found in batchZombies.",
                   " Removed and message filtered. batchZombies size now: ", batchZombies.size());
            return true;
        }
        return false;
    }

    void ConnectionBase::processJson(QByteArray &&json)
    {
        if (ignoreNewIncomingMessages) {
            // This is only ever latched to true in the "Client" subclass and it signifies that the client is being
            // dropped and so we have this short-circuit conditional to save on cycles in that situation and not
            // bother processing further messages.
            DebugM("ignoring ", json.length(), " byte incoming message from ", id);
            return;
        }
        Message::Id msgId;
        std::optional<ProcessObjectResult::Error> error;
        try {
            const auto backend = jsonParserBackend.load(std::memory_order_relaxed);
            const Json::ParseOption parseOpt = batchPermitted ? Json::ParseOption::AcceptAnyValue
                                                              : Json::ParseOption::RequireObject;
            QVariant var = Json::parseUtf8(json, parseOpt, backend); // may throw
            json.clear(); // release memory right away (needed for ScaleNet)

            if (var.canConvert<QVariantMap>()) {
                // handle immediate request
                const auto res = processObject(var.toMap()); // may throw
                var.clear(); // release unused memory immediately
                msgId = res.parsedMsgId; // copy parsed message id so possible error-sending code below has it (if not null)
                if (res.error) {
                    error = std::move(res.error);
                } else if (res.message) {
                    if (res.message->isError())
                        emit gotErrorMessage(id, *res.message);
                    else
                        emit gotMessage(id, *res.message);
                } else {
                    // No error or no message means callee is telling us to do nothing with this.
                    // This can happen if unexpected/unsupported notification, in which case peerError() was
                    // already emitted by `processObject()`.
                    return;
                }
            } else if (var.canConvert<QVariantList>()) {
                // Note: This branch can only be taken if batchPermitted == true
                enqueueNewBatch(var.toList()); // This may throw InvalidRequest (if list is empty), or BatchLimitExceeded
                return;
            } else {
                // Note: This branch can only be taken if batchPermitted == true
                // Handle error immediately. Note that older Fulcrum (or Fulcrum with batchinPermitted = false)
                // would throw Json::Error here, which technically isn't quite correct.  As per JSON-RPC 2.0 specs,
                // the Invalid request error should happen when a request isn't properly formatted or is of the wrong
                // JSON type.
                throw InvalidRequest{};
            }
        } catch (const BatchLimitExceeded & e) {
            error.emplace(Code_App_LimitExceeded, "Batch limit exceeded");
        } catch (const Json::ParseError & e) {
            error.emplace(Code_ParseError, e.what());
        } catch (const InvalidRequest & e) {
            error.emplace(Code_InvalidRequest, "Invalid request");
        } catch (const Exception & e) {
            error.emplace(Code_Custom, e.what());
        } catch (const std::exception & e) {
            error.emplace(Code_InternalError, e.what());
        }
        if (error)
            on_processJsonFailure(error->code, error->message, msgId);
    }

    void ConnectionBase::on_processJsonFailure(int code, const QString & message, const Message::Id &msgId)
    {
        bool doDisconnect = errorPolicy & ErrorPolicyDisconnect;
        if (errorPolicy & ErrorPolicySendErrorMessage) {
            emit sendError(doDisconnect,code, message.left(120), msgId);
            if (!doDisconnect)
                emit peerError(id, lastPeerError=message);
            doDisconnect = false; // if was true, already enqueued graceful disconnect after error reply, if was false, no-op here
        }
        if (doDisconnect) {
            Error() << "Error processing data coming in: " << (lastPeerError=message);
            do_disconnect();
            status = Bad;
        }
    }

    void ConnectionBase::enqueueNewBatch(QVariantList && varList)
    {
        // handle Batch request -- add it to the extant batches

        // TODO: limit the number of extant batches here, or the complexity of any single batch

        if (varList.empty())
            // empty batch lists are a JSON-RPC error
            throw InvalidRequest();

        auto batch_exception_guard = std::make_unique<RPC::BatchProcessor>(*this, std::move(varList));
        auto *batch = batch_exception_guard.get();
        if ( ! canAcceptBatch(batch) ) {
            DebugM(batch->objectName(), ": rejecting batch ");
            throw BatchLimitExceeded();
        }
        connect(batch, &QObject::destroyed, this, [this, bpId = batch->id](QObject *o) {
            // NB: Qt doesn't deliver this signal to us if `this` is no longer is a ConnectionBase * (which is good)
            if (auto *ptr = extantBatchProcessors.take(bpId); UNLIKELY(ptr && ptr != o)) {
                // this should never happen
                Error() << "Deleted extant batch processor with id " << bpId
                        << ", but the passed-in QObject pointer differs from the pointer in our table! FIXME!";
            }
        });
        extantBatchProcessors[batch->id] = batch;
        connect(batch, &BatchProcessor::finished, this, [this, bpId = batch->id]{
            if (auto *batch = extantBatchProcessors.take(bpId)) {
                if (const auto & zombies = batch->getBatch().unansweredRequests; !zombies.isEmpty()) {
                    batchZombies.unite(zombies);
                    DebugM(batch->objectName(), ": had ", zombies.size(), " zombie requests added to batchZombies set");
                }
                batch->deleteLater();
            }
        });
        // start the batch from event loop after the current event loop stack returns
        Util::AsyncOnObject(batch, [batch]{ batch->process(); });
        batch_exception_guard.release(); // owner is now `this`, as part of Qt QObject ownership model.
    }

    auto ConnectionBase::processObject_internal(QVariantMap && vmap) -> ProcessObjectResult
    {
        Message::Id msgId;
        try {
            Message message = Message::fromJsonData(vmap, &msgId, v1, strict); // may throw
            vmap.clear(); // release memory right away

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
                // don't leak the request -- an error response is an answer! Remove from map.
                message.method = idMethodMap.take(message.id);
                if (!message.id.isNull() && message.method.isEmpty())
                    // Hmm. Error with no corresponding request id.. log that fact to debug log
                    DebugM("Got unexpected error reply for id: ", message.id);
                return {std::move(message), msgId};
            } else if (message.isNotif()) {
                try {
                    const auto it = methods.find(message.method);
                    if (it == methods.end())
                        throw UnknownMethod("Unknown method");
                    const Method & m = it.value();
                    if (m.allowsNotifications) {
                        ValidateParams(message, m);
                        return {std::move(message), msgId};
                    } else {
                        throw Exception(QString("Ignoring unexpected notification"));
                    }
                } catch (const Exception & e) {
                    // Note: we emit peerError here so that the tally of number of errors goes up and we eventually disconnect the offending peer.
                    // This should not cause an error message to be sent to the peer.
                    emit peerError(this->id, lastPeerError=QString("Error processing notification '%1' from %2: %3").arg(message.method, prettyName(), e.what()));
                    return msgId; // tell caller to do nothing with this since we already emitted peerError
                }
            } else if (message.isRequest()) {
                const auto it = methods.find(message.method);
                const Method *m = it != methods.end() ? &it.value() : nullptr;
                if (!m || !m->allowsRequests)
                    throw UnknownMethod(QString("Unsupported request: %1").arg(message.method));
                ValidateParams(message, *m);
                return {std::move(message), msgId};
            } else if (message.isResponse()) {
                QString meth = idMethodMap.take(message.id);
                if (meth.isEmpty()) {
                    throw BadPeer(QString("Unexpected response (id: %1)").arg(message.id.toString()));
                }
                message.method = meth;
                return {std::move(message), msgId};
            } else {
                // Not a Request and not a Response or Notification or Error. Not JSON-RPC 2.0.
                throw InvalidRequest("Invalid JSON");
            }
        } catch (const Exception &e) {
            // TODO: clean this up. It's rather inelegant. :/
            const bool wasUnk = dynamic_cast<const UnknownMethod *>(&e);
            const bool wasInv = dynamic_cast<const InvalidRequest *>(&e) || dynamic_cast<const InvalidError *>(&e);
            const bool wasInvParms = dynamic_cast<const InvalidParameters *>(&e);
            int code = Code_Custom;
            if (wasInvParms) code = Code_InvalidParams;
            else if (wasUnk) code = Code_MethodNotFound;
            else if (wasInv) code = Code_InvalidRequest;
            return {ProcessObjectResult::Error{code, e.what()}, msgId};
        } catch (const std::exception &e) {
            // Other low-level error such as bad_alloc, etc. This is very unlikely. We simply disconnect and give up.
            Error() << prettyName(false, true) << ": Low-level error reading/parsing data coming in: " << (lastPeerError=e.what());
            do_disconnect();
            status = Bad;
            return msgId; // tell caller to do nothing (we already handled it)
        } // end try/catch
    }

    auto ConnectionBase::processObject(QVariantMap && vmap) -> ProcessObjectResult
    {
        auto ret = processObject_internal(std::move(vmap));
        if (!ret.error) lastGood = Util::getTime(); // update "lastGood" as this is used to determine if stale or not.
        return ret;
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
            QByteArray data;
            try {
                data = ws ? ws->readNextMessage() : socket->readLine();
            } catch (const std::exception &e) { // we anticipate only bad_alloc being thrown here in pathological cases
                Error() << prettyName() << " exception copying data from socket: " << e.what() << ", aborting connection";
                do_disconnect();
                status = Bad;
                break;
            }
            nReceived += data.length();
            // may be slow, so use the efficient TraceM
            TraceM("Got: ", (!ws ? data.trimmed() : data));
            processJson(std::move(data));
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
        emit readPausedStateChanged(readPaused);
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
        if (memoryWasteThreshold <= 0) {
            // Buffer limits disabled for this connection. This is not really recommended for general-purpose
            // untrusted Electrum connections so warn in debug and return.
            DebugM(__func__, ": MAX_BUFFER is unlimited for ElectrumConnection \"", objectName(),
                   "\"  -- unlimited MAX_BUFFER is not recommended for ElectrumConnection instances.");
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
                if (memoryWasteThreshold > 0  // we must check memoryWasteThreshold didn't become 0 (unlimited) which may happen in theory but not in practice.
                        && avail >= memoryWasteThreshold) {
                    Warning(Log::Magenta)
                            << "Client " << this->id << " from " << this->peerAddress().toString()
                            << " exceeded its \"memory waste threshold\" by filling our receive buffer with "
                            << avail << " bytes for longer than "
                            << QString::number(memoryWasteTimeout/1e3, 'f', 1) << " seconds -- kicking client!";
                    // the below also sets ignoreNewIncomingMessages = true iff this is of type Client *
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

    QByteArray ElectrumConnection::wrapForSend(QByteArray && d)
    {
        if (checkSetGetWebSocket()) {
            // in websocket mode we don't wrap anything -- it's already framed.
            return std::move(d);
        }
        // regular classic Electrum Cash socket -- newline delimited.
        d.append(QByteArrayLiteral("\r\n"));
        return std::move(d);
    }

    /* --- HttpConnection --- */
    HttpConnection::~HttpConnection() {} ///< for vtable
    void HttpConnection::setAuth(const QString &username, const QString &password)
    {
        header.authCookie = QStringLiteral("%1:%2").arg(username, password).toUtf8().toBase64();
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
        QByteArray content = "";
        int contentLength = 0;
        bool logBad = false;
        bool gotLength = false;
        static constexpr int kLargeContentThresh = 32'000'000; ///< sizes above this threshold get logged to debug log as to how long they took to download
        qint64 largeContentT0 = 0;
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
                        const auto name = toks[0].simplified().toLower(),
                                   value = toks.mid(1).join(':').simplified();
                        static const QByteArray s_content_type("content-type"), s_content_length("content-length"),
                                                s_application_json("application/json"), s_connection("connection"),
                                                s_close("close"), s_keep_alive("keep-alive");
                        if (name == s_content_type) {
                            sm->contentType = QString::fromUtf8(value);
                            if (sm->contentType.compare(s_application_json, Qt::CaseInsensitive) != 0) {
                                Warning() << "Got unexpected content type: " << sm->contentType << (!Trace::isEnabled() ? "; will log the rest of this HTTP response" : "");
                                sm->logBad = true;
                            }
                        } else if (name == s_content_length) {
                            bool ok = false;
                            sm->contentLength = value.toInt(&ok);
                            if (!ok || sm->contentLength < 0) {
                                // ERROR HERE. Expected numeric length, got nonsense
                                throw Exception(QString("Could not parse content-length: %1").arg(QString(data)));
                            } else if (UNLIKELY(MAX_BUFFER > 0 && sm->contentLength > MAX_BUFFER)) {
                                // ERROR, defend against memory exhaustion attack.
                                throw Exception(QString("Peer wants to send us %1 bytes of data, exceeding our buffer limit of %2!")
                                                .arg(sm->contentLength).arg(MAX_BUFFER));
                            } else if (UNLIKELY(sm->contentLength >= sm->kLargeContentThresh)) {
                                // take timestamp for large reads  -- we will print elapsed time to debug log below
                                sm->largeContentT0 = Util::getTime();
                            }
                            sm->gotLength = true;
                            TraceM("Content length: ", sm->contentLength);
                        } else if (name == s_connection) {
                            // we tolerate "Connection: keep-alive", for everything else warn or print a debug message
                            if (const auto lowerVal = value.toLower(); lowerVal != s_keep_alive) {
                                static const auto MakeErrMsg = [](const QString & value) {
                                    return QString("Unsupported \"Connection: %1\" header field in response").arg(value);
                                };
                                if (lowerVal == s_close && sm->status == 200)
                                    Warning() << MakeErrMsg(value);
                                else
                                    DebugM(MakeErrMsg(value));
                            }
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
                    lastGood = Util::getTime(); // we just received data, so update "lastGood" as this is used to determine if stale or not -- and for large downloads we don't want to go stale while downloading.
                } else {
                    // read 0 bytes, but bytesAvailable was >0, must mean there was some sort of error
                    throw Exception("Read 0 bytes from socket");
                }
            }
            if (sm->state == St::READING_CONTENT && sm->content.length() >= sm->contentLength) {
                if (UNLIKELY(sm->largeContentT0)) {
                    DebugM("HttpConnection received large content: ", QString::number(sm->contentLength / 1e6, 'f', 1),
                           " MB in ", QString::number((Util::getTime() - sm->largeContentT0)/1e3, 'f', 3), " secs");
                }
                // got a full content packet!
                {
                    QByteArray json = sm->content;
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

                    processJson(std::move(json));
                    // `json` scope end to ensure not used after move.
                }
                // If bytesAvailable .. schedule a callback to this function again since we did a partial read just now,
                // and the socket's buffers still have data.
                if (auto avail = socket->bytesAvailable(); avail > 0 && (MAX_BUFFER <= 0 || avail <= MAX_BUFFER)) {
                    // callback is on socket as receiver this way if socket dies and is deleted, callback never happens.
                    // *taps forehead*
                    QTimer::singleShot(0, socket, [this]{on_readyRead();});
                }
            }
            if (UNLIKELY(MAX_BUFFER > 0 && socket->bytesAvailable() > MAX_BUFFER)) {
                // this branch normally can't be taken because super class calls setReadBufferSize() on the socket
                // in on_connected, but we leave this code here in the interests of defensive programming.
                throw Exception( QString("Peer backbuffer exceeded %1 bytes! Bad peer?").arg(MAX_BUFFER) );
            }
        } catch (const std::exception & e) { // NB: we catch the broad std::exception in case of bad_alloc
            Error() << prettyName() << " fatal error: " << e.what();
            do_disconnect();
            status = Bad;
            if (sm) sm->clear(); // ensure state machine is "fresh" if we get here
        }
    }
    QByteArray HttpConnection::wrapForSend(QByteArray && data)
    {
        static const QByteArray NL("\r\n"), SLASHN("\n"), EMPTY("");
        static const QByteArray POST("POST / HTTP/1.1");
        static const QByteArray HOST("Host: ");
        static const QByteArray AUTH("Authorization: Basic ");
        static const QByteArray CONTENT_TYPE("Content-Type: application/json-rpc");
        static const QByteArray CONTENT_LENGTH("Content-Length: ");
        const QByteArray &suffix = !data.endsWith(SLASHN) ? NL : EMPTY;
        const bool addHost = !header.host.isEmpty(),
                   addAuth = !header.authCookie.isEmpty();
        const int clen = data.size() + suffix.size();
        const QByteArray clenStr = QByteArray::number(clen);
        // Pre-alloc all space we will need as an optimization. We do this to reduce excess
        // copies and mallocs() because this function is potentially called often, especially
        // when synching the blockchain. Note: If updating the below "+= append" code, be sure
        // to update this calculation as well otherwise we will potentially suffer from
        // extra mallocs.
        QByteArray payload;
        const int reserveSize =
              POST.size() + NL.size()
            + (addHost ? HOST.size() + header.host.size() + NL.size() : 0)
            + CONTENT_TYPE.size() + NL.size()
            + (addAuth ? AUTH.size() + header.authCookie.size() + NL.size() : 0)
            + CONTENT_LENGTH.size() + clenStr.size() + NL.size()
            + NL.size() + clen;
        payload.reserve( reserveSize );

        // Note we originally used a QTextStream here without the above reserve().
        // It turns out QTextStream first converts everything to QString() and does
        // a toUtf8() on the resulting QString when appending QByteArray, which takes
        // extra CPU and is not what we want here.  So we simply hand-crafted the appends
        // ourselves here in order to save cycles and reduce mallocs.

        // POST / HTTP/1.1
        payload += POST; payload += NL;
        if (addHost) {
            // Host: <host>\r\n
            payload += HOST; payload += header.host; payload += NL;
        }
        // Content-Type: application/json-rpc\r\n
        payload += CONTENT_TYPE; payload += NL;
        if (addAuth) {
            // Authorization: Basic <auth>\r\n
            payload += AUTH; payload += header.authCookie; payload += NL;
        }
        // Content-Length: <length>\r\n
        payload += CONTENT_LENGTH; payload += clenStr; payload += NL;
        // \r\n to separate header from data
        payload += NL;
        // actual data payload
        payload += data;
        data.clear(); // release data right away to save memory
        // optional suffix (\r\n because JSON needs this)
        payload += suffix;

        // Sanity check to ensure we estimated the size correctly. This branch is compiled-out of release builds.
        if constexpr (!isReleaseBuild()) {
            if (const auto actualSize = payload.size(); reserveSize != actualSize && Debug::isEnabled())
                Debug() << "reserveSize: " << reserveSize << " != actualSize: " << actualSize
                        << " (this leads to extra mallocs) for: \"" << payload.left(80) << "\" ... ";
        }

        return payload;
    }

    void HttpConnection::setHeaderHost(const QString &s) {
        if (auto trimmed = s.trimmed(); !trimmed.isEmpty())
            header.host = trimmed.toUtf8();
    }

    bool isFastJson()
    {
        switch (jsonParserBackend.load(std::memory_order_relaxed)) {
        case Json::ParserBackend::Default:
            return false;
        case Json::ParserBackend::FastestAvailable:
            return Json::isParserAvailable(Json::ParserBackend::SimdJson);
        case Json::ParserBackend::SimdJson: {
            // this branch should never be taken but we put it here for defensive purposes
            const bool avail = Json::isParserAvailable(Json::ParserBackend::SimdJson);
            if (!avail)
                // uh oh, force it to be the safer option "FastestAvailable" to avoid parse errors
                jsonParserBackend.store(Json::ParserBackend::FastestAvailable, std::memory_order_relaxed);
            return avail;
        }
        }
    }

    bool setFastJson(bool b) {
        if (b) {
            jsonParserBackend.store(Json::ParserBackend::FastestAvailable, std::memory_order_relaxed);
            return isFastJson();
        } else {
            jsonParserBackend.store(Json::ParserBackend::Default, std::memory_order_relaxed);
            return true;
        }
    }

    QVariant Batch::getNextAndIncrement()
    {
        QVariant ret;
        if (hasNext()) {
            auto & v = items[nextItem++];
            ret = v;
            v.clear(); // consume array member right away to free up mmemory
        }
        return ret;
    }

    BatchProcessor::BatchProcessor(ConnectionBase & parent, Batch && batch_)
        : QObject(&parent), IdMixin(newId()), conn(parent), batch(std::move(batch_))
    {
        try {
            cumCost = Json::estimateMemoryFootprint(batch.items);
        } catch (const std::exception &e) {
            Error() << "Exception calculating base cost in " << __func__ << ": " << e.what();
        }
        setObjectName(parent.objectName() + " BatchProcessor." + QString::number(id)
                      + " (" + QString::number(batch.items.size()) + ")");
        connect(&conn, &ConnectionBase::readPausedStateChanged, this, [this](bool readPaused){
            if (!readPaused && isProcessingPaused) {
                // kick-start a paused state back to unpaused
                DebugM(objectName(), " was paused, unpausing due to readPausedStateChanged signal from parent");
                AGAIN();
            }
        });
    }

    BatchProcessor::~BatchProcessor() {
        DebugM(objectName(), " ", __func__, ", elapsed: ", t0.msecStr(6), " msec");
        // signal to listeners that cost is now 0
        addCost(-cumCost);
    }

    bool ConnectionBase::hasMessageIdInBatchProcs(const Message::Id &msgId) const
    {
        if (batchZombies.contains(msgId))
            return true;
        for (const auto *proc : extantBatchProcessors) {
            if (!proc || proc->isFinished()) continue;
            const auto & batch = proc->getBatch();
            if (!batch.isComplete() && (batch.unansweredRequests.contains(msgId) || batch.answeredRequests.contains(msgId)))
                return true;
        }
        return false;
    }

    void BatchProcessor::addCost(qsizetype cost)
    {
        cumCost += cost;
        emit costDelta(cost);
    }

    void BatchProcessor::pushResponse(Message && response)
    {
        batch.responses.push_back(std::move(response));
        addCost(Json::estimateMemoryFootprint(std::as_const(batch.responses).back().data));
    }

    void BatchProcessor::process()
    {
        if (done) {
            DebugM(objectName(), ": (", __func__, ") done = true, aborting early ...");
            return;
        }
        if (UNLIKELY(conn.ignoreNewIncomingMessages)) {
            // This is only ever latched to true in the "Client" subclass and it signifies that the client is being
            // dropped and so we have this short-circuit conditional to save on cycles in that situation and not
            // bother processing further messages.
            DebugM(objectName(), ": ignoring ", batch.items.size() - batch.nextItem, " batch message(s)");
            done = true;
            emit finished();
            return;
        }
        if (killed) {
            // as the batch executed it exceeded a limit, so just return an error to the client
            done = true; // set this flag first so we don't stand a chance of filtering below error message
            conn.on_processJsonFailure(Code_App_LimitExceeded, "Batch limit exceeded");
            emit finished();
        } else if (batch.hasNext()) {
            if (conn.isReadPaused()) {
                // ElectrumConnection subclasses may enter this "read paused" state when the bitcoind request queue
                // backs up. We respect that flag and pause processing. We will be signalled to resume via the
                // `readPausedStateChanged` signal when the backlog clears up in the near future.
                DebugM(objectName(), ": paused on batch item ", batch.nextItem + 1, ", returning early ...");
                isProcessingPaused = true;
                return;
            } else if (isProcessingPaused) {
                DebugM(objectName(), ": unpaused");
                isProcessingPaused = false;
            }
            DebugM(objectName(), ": processing batch item ", batch.nextItem + 1);
            auto var = batch.getNextAndIncrement();
            std::optional<QString> error;
            if (!var.canConvert<QVariantMap>()) {
                pushResponse(Message::makeError(Code_InvalidRequest, *(error="Invalid request"), {}, conn.isV1()));
            } else {
                auto res = conn.processObject(var.toMap());
                if (res.error) {
                    pushResponse(Message::makeError(res.error->code, (error=res.error->message)->left(120),
                                                    res.parsedMsgId, conn.isV1()));
                } else if (res.message) {
                    const auto & m = *res.message;
                    if (m.isRequest()) {
                        if (m.id.isNull()) {
                            // error, null message id (not supported due to potential for clashing with error results)
                            pushResponse(Message::makeError(Code_Custom, *(error="Null id not supported in batch requests"),
                                                            m.id, conn.isV1()));
                        } else if (conn.hasMessageIdInBatchProcs(m.id)) {
                            // error, dupe
                            pushResponse(Message::makeError(Code_Custom, *(error="Duplicate id"), m.id, conn.isV1()));
                        } else {
                            // Ok, proceed to pass the message along to the `conn` instance. We will be notified in
                            // our `acceptResponse()` method by `ConnectionBase::batchResponseFilter` when the result
                            // (or error) is ready.
                            batch.unansweredRequests.insert(m.id);
                            emit conn.gotMessage(conn.id, m);
                        }
                    } else if (m.isNotif()) {
                        ++batch.skippedCt;
                        emit conn.gotMessage(conn.id, m);
                    } else {
                        pushResponse(Message::makeError(Code_InvalidRequest, *(error="Invalid request"), m.id, conn.isV1()));
                    }
                } else {
                    // do nothing, indicate we are not expecting a response
                    ++batch.skippedCt;
                }
            }
            if (error) {
                ++batch.errCt;
                conn.lastPeerError = *error;
                if ( ! (conn.errorPolicy & conn.ErrorPolicyDisconnect))
                    emit conn.peerError(conn.id, conn.lastPeerError);
            }
            if (LIKELY(conn.isGood()))
                // keep sending requests to the conn, but only if we didn't go "Bad" (may happen in corner cases above,
                // or if the connection went down asynchronously between calls)
                AGAIN();
        } else if (batch.isComplete()) {
            DebugM(objectName(), ": completed");
            QVariantList l;
            for (const auto &msg : qAsConst(batch.responses)) {
                if (msg.isError()) ++conn.nErrorsSent;
                else ++conn.nResultsSent;
                l.push_back(msg.data);
            }
            batch.responses.clear(); // clear memory right away
            if (!l.empty() && conn.isGood()) {
                // only send if the response list is not empty and if the connection is still good.
                auto json = Json::toUtf8(l, true);
                l.clear(); // clear memory right away
                TraceM("Sending result json: ", Util::Ellipsify(json));
                // below send() ends up calling do_write immediately (which is connected to send)
                emit conn.send( conn.wrapForSend(std::move(json)) );
            }
            if (batch.errCt && (conn.errorPolicy & conn.ErrorPolicyDisconnect)) {
                Error() << "Error sent to " << conn.prettyName(true)
                        << " in batch request, disconnecting due to ErrorPolicyDisconnect";
                conn.do_disconnect();
                conn.status = conn.Bad;
            }
            done = true;
            emit finished();
        } else {
            // This branch is taken when we have sent out all the requests to the observer(s) but we haven't yet
            // received all the responses we expect. For now, we just time-out the batch request after 20 seconds.
            constexpr int timeoutSec = 20; // TODO: have this come from config?!
            DebugM(objectName(), ": lifecycle state is now idle");
            callOnTimerSoonNoRepeat(timeoutSec * 1000, "+InactivityTimeout", [this, timeoutSec]{
                Error() << objectName() << ": timed out after not receiving a batch response for "
                        << timeoutSec << " seconds.";
                emit conn.sendError(true, Code_InternalError, "Batch request timed out");
                conn.status = conn.Bad;
                this->deleteLater();
            });
        }
    }

    bool BatchProcessor::acceptResponse(const Message &m)
    {
        if (auto it = batch.unansweredRequests.find(m.id); it != batch.unansweredRequests.end()) {
            batch.unansweredRequests.erase(it);
            batch.answeredRequests.insert(m.id);
            pushResponse(m);
            if (batch.isComplete()) AGAIN();
            return true;
        }
        return false;
    }

    void BatchProcessor::killForExceedngLimit()
    {
        if (killed || done || conn.ignoreNewIncomingMessages) return;
        killed = true;
        AGAIN(); // to ensure we die ASAP
    }

    auto BatchProcessor::stats() const -> Stats
    {
        QVariantMap ret;
        ret["done"] = done;
        ret["elapsed (msec)"] = t0.msec<qreal>();
        ret["batch"] = [this]{
            QVariantMap bm;
            bm["cost"] = qlonglong(cost());
            bm["size"] = qlonglong(batch.items.size());
            bm["nextItem"] = qlonglong(batch.nextItem);
            bm["unansweredRequests"] = qlonglong(batch.unansweredRequests.size());
            bm["answeredRequests"] = qlonglong(batch.answeredRequests.size());
            bm["responses"] = qlonglong(batch.responses.size());
            bm["state"] = [this]{
                if (killed) return "killed";
                else if (isProcessingPaused) return "paused";
                else if (batch.hasNext()) return "processing";
                else if (batch.isComplete()) return "completed";
                return "idle";
            }();
            bm["errCt"] = batch.errCt;
            bm["skippedCt"] = batch.skippedCt;
            return bm;
        }();
        ret["timers"] = activeTimerMapForStats();
        return ret;
    }

} // end namespace RPC

#if 0
// TESTING
#include <iostream>
namespace RPC {
    /* static */ void HttpConnection::Test()
    {
        std::shared_ptr<HttpConnection> h(new HttpConnection(nullptr, 1), [](HttpConnection *h){
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
                connect(h.get(), &RPC::ConnectionBase::gotMessage, h.get(), [h](qint64 id_in, const RPC::Message &m) {
                            Debug() << "Got message from server: id: " << id_in << " json: " << m.toJsonUtf8();
                        })
            ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
            h->connectedConns.push_back(
                connect(h.get(), &RPC::ConnectionBase::gotErrorMessage, h.get(), [](qint64 id_in, const RPC::Message &m) {
                            Debug() << "Got ERROR message from server: id: " << id_in << " json: " << m.toJsonUtf8();
                        })
            ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
            connect(h.get(), &AbstractConnection::lostConnection, h.get(), [](AbstractConnection *a) {
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
#endif // if 0
