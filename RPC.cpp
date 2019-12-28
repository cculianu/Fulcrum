//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
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
#include <QtCore>

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
    Message Message::fromString(const QString &s, Id *id_out, bool v1)
    {
        return fromJsonData(Util::Json::parseString(s, true).toMap(), id_out, v1); // may throw
    }

    /* static */
    Message Message::fromJsonData(const QVariantMap & map, Id * id_out, bool v1)
    {
        Message ret;
        ret.v1 = v1;
        ret.data = map;

        if (id_out)
            id_out->clear();

        // Grab the id first in case later processing fails.
        if (auto var = map.value(s_id); !var.isNull()) {
            // note as per JSON-RPC 2.0 spec, we squash floats down to ints, discarding the fractional part
            // we will throw if the id is not a string, integer, or null
            bool ok;
            qint64 id_ll{};
            if (QMetaType::Type(var.type()) == QMetaType::QString)
                ret.id = var;
            // note the below will fail at non-fractional integers > 2^53 (or 9 quadrillion)
            else if (double id_dbl = var.toDouble(&ok); ok && qAbs(double(id_ll=qint64(id_dbl)) - id_dbl) <= 0.0) // this checks that fractional part not present
                ret.id = id_ll;
            else
                // if we get here, id is not a valid type as per our restricted JSON RPC 2.0 (we don't accept fractional parts for id)
                throw InvalidError("id must be a string, a non-fractional number, or null");
            if (id_out)
                *id_out = ret.id;
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

        // todo: see if the below validation needs optimization

        // validate error as per JSON RPC 2.0  -- TODO: See if this is kosher for 1.0 -- it seems to be on first glance
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
                if (KeySet::fromList(ret.data.keys()) != required)
                    throw InvalidError("Error response not valid");
            }
        }
        // validate request as per JSON RPC 2.0
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

        // if we get to this point, the json meets minimal JSON RPC 2.0 specs.

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
        map[s_id] = id; // may be "null"
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
        map[s_id] = reqId;
        map[s_result] = result;
        ret.id = reqId;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantList & params, bool v1)
    {
        Message ret = makeNotification(methodName, params, v1);
        auto & map = ret.data;
        map[s_id] = id;
        ret.id = id;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantMap & params, bool v1)
    {
        Message ret = makeNotification(methodName, params, v1);
        auto & map = ret.data;
        map[s_id] = id;
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

    ConnectionBase::ConnectionBase(const MethodMap & methods, quint64 id_in, QObject *parent, qint64 maxBuffer)
        : AbstractConnection(id_in, parent, maxBuffer), methods(methods)
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
        idMethodMap.clear();
    }

    auto ConnectionBase::stats() const -> Stats
    {
        auto m = AbstractConnection::stats().toMap();
        m["nRequestsSent"] = nRequestsSent;
        m["nResultsSent"] = nResultsSent;
        m["nErrorsSent"] = nErrorsSent;
        m["nNotificationsSent"] = nNotificationsSent;
        m["nUnansweredRequests"] = idMethodMap.size(); // we may care about this
        m["nErrorReplies"] = nErrorReplies;
        return m;
    }

    void ConnectionBase::_sendRequest(const Message::Id & reqid, const QString &method, const QVariantList & params)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        QString json = Message::makeRequest(reqid, method, params, v1).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate request JSON! FIXME!";
            return;
        }
        if (idMethodMap.size() >= MAX_UNANSWERED_REQUESTS) {  // prevent memory leaks in case of misbehaving peer
            Warning() << "Closing connection because too many unanswered requests for: " << prettyName();
            do_disconnect();
            return;
        }
        idMethodMap[reqid] = method; // remember method sent out to associate it back.

        const auto data = json.toUtf8();
        if (Trace::isEnabled()) Trace() << "Sending json: " << Util::Ellipsify(data);
        ++nRequestsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(data) );
    }
    void ConnectionBase::_sendNotification(const QString &method, const QVariant & params)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        QString json;
        if (params.canConvert<QVariantMap>()) {
            json = Message::makeNotification(method, params.toMap(), v1).toJsonString();
        } else if (params.canConvert<QVariantList>()) {
            json = Message::makeNotification(method, params.toList(), v1).toJsonString();
        } else {
            Error() << __FUNCTION__ << " method: " << method << "; Notification requires either a QVarantList or a QVariantMap as its argument! FIXME!";
            return;
        }
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate notification JSON! FIXME!";
            return;
        }
        const auto data = json.toUtf8();
        if (Trace::isEnabled()) Trace() << "Sending json: " << Util::Ellipsify(data);
        ++nNotificationsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(data) );
    }
    void ConnectionBase::_sendError(bool disc, int code, const QString &msg, const Message::Id & reqId)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << "; Not connected!";
            return;
        }
        QString json = Message::makeError(code, msg, reqId, v1).toJsonString();
        const auto data = json.toUtf8();
        if (Trace::isEnabled()) Trace() << "Sending json: " << Util::Ellipsify(data);
        ++nErrorsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(data) );
        if (disc) {
            do_disconnect(true); // graceful disconnect
        }
    }
    void ConnectionBase::_sendResult(const Message::Id & reqid, const QVariant & result)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << ":  Not connected!";
            return;
        }
        QString json = Message::makeResponse(reqid, result, v1).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << ": Unable to generate result JSON! FIXME!";
            return;
        }
        const auto data = json.toUtf8();
        if (Trace::isEnabled()) Trace() << "Sending result json: " << Util::Ellipsify(data);
        ++nResultsSent;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( wrapForSend(data) );
    }

    void ConnectionBase::processJson(const QByteArray &json)
    {
        Message::Id msgId;
        try {
            Message message = Message::fromJsonData( Util::Json::parseString(json, true).toMap() , &msgId, v1); // may throw

            static const auto ValidateParams = [](const Message &msg, const Method &m) {
                if (!msg.hasParams()) {
                    if ( (m.opt_kwParams.has_value() && !m.opt_kwParams->isEmpty())
                         || (m.opt_nPosParams.has_value() && m.opt_nPosParams.value().first != 0) )
                        throw InvalidParameters("Missing required params");
                } else if (msg.isParamsList()) {
                    // positional args specified
                    if (!m.opt_nPosParams.has_value())
                        throw InvalidParameters("Postional params are not supported for this method");
                    const unsigned num = unsigned(msg.paramsList().count());
                    auto [minParams, maxParams] = m.opt_nPosParams.value();
                    if (maxParams < minParams) maxParams = minParams;
                    if (num < minParams)
                        throw InvalidParameters(QString("Expected at least %1 parameters for %2, got %3 instead").arg(minParams).arg(m.method).arg(num));
                    if (num > maxParams)
                        throw InvalidParameters(QString("Expected at most %1 parameters for %2, got %3 instead").arg(maxParams).arg(m.method).arg(num));
                } else if (msg.isParamsMap()) {
                    // named args specified
                    if (!m.opt_kwParams.has_value())
                        throw InvalidParameters("Named params are not supported for this method");
                    const auto nameset = KeySet::fromList(msg.paramsMap().keys());
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
            const bool wasJsonParse = dynamic_cast<const Util::Json::ParseError *>(&e);
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
        } // end try/catch
    }

    /* --- LinefeedConnection --- */
    LinefeedConnection::~LinefeedConnection() {} ///< for vtable

    void LinefeedConnection::on_readyRead()
    {
        Trace() << __FUNCTION__;
        // TODO: This may be slow for large loads.
        while (socket->canReadLine()) {
            auto data = socket->readLine();
            nReceived += data.length();
            if (Trace::isEnabled()) // may be slow, so conditional on trace mode
            {
                auto line = data.trimmed();
                Trace() << "Got: " << line;
            }
            processJson(data);
        }
        if (UNLIKELY(socket->bytesAvailable() > MAX_BUFFER)) {
            // this branch normally can't be taken because super class calls setReadBufferSize() on the socket
            // in on_connected, but we leave this code here in the interests of defensive programming.
            Error() << prettyName() << " fatal error: " << QString("Peer has sent us more than %1 bytes without a newline! Bad peer?").arg(MAX_BUFFER);
            do_disconnect();
            status = Bad;
        }
    }

    QByteArray LinefeedConnection::wrapForSend(const QByteArray &d)
    {
        return d + "\r\n";
    }

    /* --- HttpConnection --- */
    HttpConnection::~HttpConnection() {} ///< for vtable
    void HttpConnection::setAuth(const QString &username, const QString &password)
    {
        authCookie = QString("%1:%2").arg(username).arg(password).toUtf8().toBase64();
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
                if (Trace::isEnabled()) Trace() << __FUNCTION__ << " Got: " << data;
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
                        Warning() << "Got HTTP status " << sm->status << " " << msg << (!Trace::isEnabled() ? "; will log the rest of this HTTP response" : "");
                        sm->logBad = true;
                        if (sm->status == 401) // 401 status indicates other side didn't like our auth cookie or we need an auth cookie.
                            emit authFailure(this);
                    }
                    sm->statusMsg = QString::fromUtf8(msg);
                    if (Trace::isEnabled()) Trace() << "Status message: " << sm->statusMsg;
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
                        auto name = toks[0].simplified(), value = toks.mid(1).join(" ").simplified();
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
                            if (Trace::isEnabled()) Trace() << "Content length: " << sm->contentLength;
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
                    Error() << "Content buffer has extra stuff at the end. Bug in code. FIXME! Crud was: '" << sm->content.mid(sm->contentLength) << "'";
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
            ss << "Content-Type: application/json-rpc" << NL;
            if (!authCookie.isEmpty())
                ss << "Authorization: Basic " << authCookie << NL;
            ss << "Content-Length: " << (data.length()+suffix.length()) << NL;
            ss << NL;
        }
        return responseHeader + data + suffix;
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
