#include "RPC.h"
#include <QtCore>

#include <type_traits>

namespace RPC {

    const QString jsonRpcVersion("2.0");

    /// As per JSON RPC spec, id must be integer (no fractional part), string, or null.
    /// Will throw if that's not the case.
    auto Message::Id::operator=(const QVariant &v) -> Id &
    {
        bool ok;
        if (v.isNull())
            *this = nullptr;
        else if (QMetaType::Type(v.type()) == QMetaType::QString)
            *this = v.toString();
        else if (qint64 id_ll = v.toLongLong(&ok); ok && v.toString() == QString::number(id_ll)) // this checks that fractional part not present
            *this = id_ll;
        else
            // if we get here, id is not a valid type as per JSON RPC 2.0
            throw InvalidError("id must be a string, a non-fractonal number, or null");
        return *this;
    }

    bool Message::Id::operator<(const Id & other) const
    {
        if (index() != other.index()) {
            return index() < other.index();
        } else {
            bool ret = false;

            std::visit(Overloaded {
                [&other, &ret](const auto & arg) {
                    // qint64 or QString
                    ret = arg < std::get< typename std::decay<decltype(arg)>::type >(other);
                },
                [](const std::nullptr_t &) { /* always same, leave ret at false */ },
            }, *this);
            return ret;
        }
    }


    // will return a QVariant whose type is either: qint64, QString, or isNull()
    Message::Id::operator QVariant() const
    {
        QVariant ret;
        std::visit(Overloaded {
            [&ret](const auto & arg) { ret = arg; }, // qint64 or QString
            [](const std::nullptr_t &) { /* noop already null */ },
        }, *this);
        return ret;
    }

    /* static */
    Message Message::fromString(const QString &s)
    {
        return fromJsonData(Util::Json::parseString(s, true).toMap()); // may throw
    }

    /* static */
    Message Message::fromJsonData(const QVariantMap & map, Id * id_out)
    {
        Message ret;
        ret.data = map;

        if (id_out)
            id_out->clear();

        // Grab the id first in case later processing fails.
        if (auto var = map.value("id"); !var.isNull()) {
            // note as per JSON-RPC 2.0 spec, we squash floats down to ints, discarding the fractional part
            // we will throw if the id is not a string, integer, or null
            ret.id = var;
            // inform caller of parsed id asap in case we later throw
            if (id_out)
                *id_out = ret.id;
        }


        if (ret.jsonRpcVersion() != RPC::jsonRpcVersion)
            throw InvalidError("Expected jsonrpc version 2.0");

        if (auto var = map.value("method");
                map.contains("method") && (QMetaType::Type(var.type()) != QMetaType::QString
                                           || (ret.method = var.toString()).isEmpty()
                                           || ret.method.startsWith("rpc.")))
            throw InvalidError("Invalid method");

        // todo: see if the below validation needs optimization


        // validate error as per JSON RPC 2.0
        if (ret.isError()) {
            auto errmap = ret.data.value("error").toMap();
            if (!errmap.contains("code") || !errmap.contains("message"))
                throw InvalidError("Expected error object to contain code and message");
            int n_req = errmap.contains("data") ? 3 : 2;
            if (errmap.count() != n_req)
                throw InvalidError("Unexpected keys in error object");
            bool ok;
            if (int code = errmap.value("code").toInt(&ok); !ok || errmap.value("code").toString() != QString::number(code))
                throw InvalidError("Expected error code to be an integer");
            static const KeySet required = { "id", "error", "jsonrpc" };
            if (KeySet::fromList(ret.data.keys()) != required)
                throw InvalidError("Error response not valid");
        }
        // validate request as per JSON RPC 2.0
        else if (ret.isRequest()) {
            const bool hasParams = ret.hasParams();
            const int n_ok = hasParams ? 4 : 3;
            if (ret.data.count() != n_ok)
                throw InvalidError("Invalid request");
            if (hasParams && !ret.isParamsMap() && !ret.isParamsList())
                throw InvalidError("Invalid params");
        }
        else if (ret.isNotif()) {
            const bool hasParams = ret.hasParams();
            const int n_ok = hasParams ? 3 : 2;
            if (ret.data.count() != n_ok)
                throw InvalidError("Invalid notification");
            if (hasParams && !ret.isParamsMap() && !ret.isParamsList())
                throw InvalidError("Invalid params");
        }
        else if (ret.isResponse()) {
            const int n_ok = 3;
            if (ret.data.count() != n_ok)
                throw InvalidError("Invalid response");
        }
        else {
            throw InvalidError("Invalid JSON RPC object");
        }

        // if we get to this point, the json meets minimal JSON RPC 2.0 specs.

        return ret;
    }

    /* static */
    Message Message::makeError(int code, const QString &message, const Id & id)
    {
        Message ret;
        auto & map = ret.data;
        map["jsonrpc"] = RPC::jsonRpcVersion;
        map["id"] = id; // may be "null"
        QVariantMap errMap;
        errMap["code"] = code;
        errMap["message"] = message;
        map["error"] = errMap;
        return ret;
    }

    /// uses provided schema -- will not throw exception
    /*static*/
    Message Message::makeResponse(const Id & reqId, const QVariant & result)
    {
        Message ret;
        auto & map = ret.data;
        map["jsonrpc"] = RPC::jsonRpcVersion;
        map["id"] = reqId;
        map["result"] = result;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantList & params)
    {
        Message ret = makeNotification(methodName, params);
        auto & map = ret.data;
        map["id"] = id;
        return ret;
    }

    /* static */
    Message Message::makeRequest(const Id & id, const QString &methodName, const QVariantMap & params)
    {
        Message ret = makeNotification(methodName, params);
        auto & map = ret.data;
        map["id"] = id;
        return ret;
    }

    /* static */
    Message Message::makeNotification(const QString &methodName, const QVariantList & params)
    {
        Message ret;
        auto & map = ret.data;
        map["jsonrpc"] = RPC::jsonRpcVersion;
        map["method"] = methodName;
        map["params"] = params;
        return ret;
    }

    /* static */
    Message Message::makeNotification(const QString &methodName, const QVariantMap & params)
    {
        Message ret;
        auto & map = ret.data;
        map["jsonrpc"] = RPC::jsonRpcVersion;
        map["method"] = methodName;
        map["params"] = params;
        return ret;
    }

    Connection::Connection(const MethodMap & methods, qint64 id_in, QObject *parent, qint64 maxBuffer)
        : AbstractConnection(id_in, parent, maxBuffer), methods(methods)
    {
    }

    Connection::~Connection() {}

    void Connection::on_connected()
    {
        AbstractConnection::on_connected();
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &Connection::sendRequest, this, &Connection::_sendRequest));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &Connection::sendNotification, this, &Connection::_sendNotification));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &Connection::sendError, this, &Connection::_sendError));
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &Connection::sendResult, this, &Connection::_sendResult));
    }

    void Connection::on_disconnected()
    {
        AbstractConnection::on_disconnected(); // will auto-disconnect all QMetaObject::Connections appearing in connectedConns
        idMethodMap.clear();
    }

    void Connection::_sendRequest(const Message::Id & reqid, const QString &method, const QVariantList & params)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        QString json = Message::makeRequest(reqid, method, params).toJsonString();
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
        Debug() << "Sending json: " << Util::Ellipsify(data);
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */);  // FIXME for bitcoind!
    }
    void Connection::_sendNotification(const QString &method, const QVariantList & params)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        QString json = Message::makeNotification(method, params).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate request JSON! FIXME!";
            return;
        }
        const auto data = json.toUtf8();
        Debug() << "Sending json: " << Util::Ellipsify(data);
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */); // FIXME for bitcoind!
    }
    void Connection::_sendError(bool disc, int code, const QString &msg, const Message::Id & reqId)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << "; Not connected!";
            return;
        }
        QString json = Message::makeError(code, msg, reqId).toJsonString();
        const auto data = json.toUtf8();
        Debug() << "Sending json: " << Util::Ellipsify(data);
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */); // FIXME for bitcoind!
        if (disc) {
            do_disconnect(true); // graceful disconnect
        }
    }
    void Connection::_sendResult(const Message::Id & reqid, const QString &method, const QVariant & result)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        QString json = Message::makeResponse(reqid, result).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate result JSON! FIXME!";
            return;
        }
        const auto data = json.toUtf8();
        Debug() << "Sending result json: " << Util::Ellipsify(data);
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */); // FIXME for bitcoind!
    }

    void Connection::on_readyRead()
    {
        Debug() << __FUNCTION__;
        Message::Id lastMsgId;
        try {
            // TODO: need to see about how this meshes with bitcoind's large, possibly multiline(?) responses.
            // We may want to not be line-based.  Also this may be slow for large loads.
            while (socket->canReadLine()) {
                lastMsgId.clear();
                auto data = socket->readLine();
                nReceived += data.length();
                auto line = data.trimmed();
                Debug() << "Got: " << line;

                Message message = Message::fromJsonData( Util::Json::parseString(line, true).toMap() , &lastMsgId); // may throw

                static const auto ValidateParams = [](const Message &msg, const Method &m) {
                    if (!msg.hasParams()) {
                        if ( (m.opt_kwParams.has_value() && !m.opt_kwParams->isEmpty())
                             || (m.opt_nPosParams.has_value() && *m.opt_nPosParams != 0
                                 && *m.opt_nPosParams != Method::ANY_POS_PARAMS) )
                            throw InvalidParameters("Missing required params");
                    } else if (msg.isParamsList()) {
                        // positional args specified
                        if (!m.opt_nPosParams.has_value())
                            throw InvalidParameters("Postional params are not supported for this method");
                        const int num = msg.paramsList().count();
                        const int nPosParams = *m.opt_nPosParams;
                        if (nPosParams == Method::ANY_POS_PARAMS)
                            return;
                        if (nPosParams >= 0 && num != nPosParams) {
                            throw InvalidParameters(QString("Expected %1 parameters for %2, got %3 instead").arg(nPosParams).arg(m.method).arg(num));
                        } else if (nPosParams < 0 && num < -nPosParams) {
                            throw InvalidParameters(QString("Expected at least %1 parameters for %2, got %3 instead").arg(-nPosParams).arg(m.method).arg(num));
                        }
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
                    } catch (const std::exception & e) {
                        // Note: we emit peerError here so that the tally of number of errors goes up and we eventually disconnect the offending peer.
                        // This should not cause an error message to be sent to the peer.
                        emit peerError(this->id, QString("Error processing notification '%1' from %2: %3").arg(message.method, prettyName(), e.what()));
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
                //Debug() << "Re-parsed message: " << message.toJsonString();
            } // end while
            if (socket->bytesAvailable() > MAX_BUFFER) {
                // bad server.. sending us garbage data not containing newlines. Kill connection.
                throw BadPeerAbort(QString("Peer has sent us more than %1 bytes without a newline! Bad peer?").arg(MAX_BUFFER));
            }
        } catch (const BadPeerAbort & e) {
            Error() << prettyName() << " fatal error: " << e.what();
            do_disconnect();
            status = Bad;
        } catch (const Exception &e) {
            // TODO: clean this up. It's rather inelegant. :/
            const bool wasJsonParse = dynamic_cast<const Util::Json::ParseError *>(&e);
            const bool wasUnk = dynamic_cast<const UnknownMethod *>(&e);
            const bool wasInv = dynamic_cast<const InvalidRequest *>(&e) || dynamic_cast<const InvalidError *>(&e);
            const bool wasInvParms = dynamic_cast<const InvalidParameters *>(&e);
            int code = Code_Custom;
            if (wasJsonParse) code = Code_ParseError;
            else if (wasInvParms) code = Code_InvalidParams;
            else if (wasUnk) code = Code_MethodNotFOund;
            else if (wasInv) code = Code_InvalidRequest;
            bool doDisconnect = errorPolicy & ErrorPolicyDisconnect;
            if (errorPolicy & ErrorPolicySendErrorMessage) {
                emit sendError(doDisconnect, code, QString(e.what()).left(80), lastMsgId);
                if (!doDisconnect)
                    emit peerError(id, e.what());
                doDisconnect = false; // if was true, already enqueued graceful disconnect after error reply, if was false, no-op here
            }
            if (doDisconnect) {
                Error() << "Error reading/parsing data coming in: " << e.what();
                do_disconnect();
                status = Bad;
            }
        } // end try/catch
    } // end function
} // end namespace RPC
