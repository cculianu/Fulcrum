#include "RPC.h"
#include <QtCore>


namespace RPC {

    const QString jsonRpcVersion("2.0");

    /* static */
    Message Message::fromString(const QString &s)
    {
        return fromJsonData(Util::Json::parseString(s, true).toMap()); // may throw
    }

    /* static */
    Message Message::fromJsonData(const QVariantMap & map)
    {
        Message ret;
        ret.data = map;

        if (ret.jsonRpcVersion() != RPC::jsonRpcVersion)
            throw InvalidError("Expected jsonrpc version 2.0");

        if (auto var = map.value("method");
                map.contains("method") && (QMetaType::Type(var.type()) != QMetaType::QString
                                           || (ret.method = var.toString()).isEmpty()
                                           || ret.method.startsWith("rpc.")))
            throw InvalidError("Invalid method");

        if (auto var = map.value("id"); !var.isNull()) {
            // note as per JSON-RPC 2.0 spec, we squash floats down to ints, discarding the fractional part
            // we will raise if the id is not a string, integer, or null
            bool ok;
            if (qint64 id_ll = var.toLongLong(&ok); ok && var.toString() == QString::number(id_ll)) {
                ret.id = id_ll;
            } else if (QMetaType::Type(var.type()) == QMetaType::QString)
                ret.id = var.toString();
            else
                // if we get here, id is not a valid type as per JSON RPC 2.0
                throw InvalidError("id must be a string, a non-fractonal number, or null");
        }

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
                throw InvalidError("Expected error code to be a numeric integer");
            static const QSet<QString> required = { "id", "error", "jsonrpc" };
            if (ret.data.count() != required.count())
                throw InvalidError("Error response not valid");
            for (const QString & r : required) {
                if (!ret.data.contains(r))
                    throw InvalidError("Error response not valid");
            }
        }
        // validate request as per JSON RPC 2.0
        else if (ret.isRequest()) {
            const int n_ok = ret.hasParams() ? 4 : 3;
            if (ret.data.count() != n_ok)
                throw InvalidError("Invalid request");
        }
        else if (ret.isNotif()) {
            const int n_ok = ret.hasParams() ? 3 : 2;
            if (ret.data.count() != n_ok)
                throw InvalidError("Invalid notification");
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
    Message Message::makeNotification(const QString &methodName, const QVariantList & params)
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
        while (idMethodMap.size() > 20000) {  // prevent memory leaks in case of misbehaving server
            idMethodMap.erase(idMethodMap.begin());
        }
        idMethodMap[reqid] = method; // remember method sent out to associate it back.

        const auto data = json.toUtf8();
        Debug() << "Sending json: " << ( data.size() > 100 ? data.left(100) + "..." : data);
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
        Debug() << "Sending json: " << ( data.size() > 100 ? data.left(100) + "..." : data);
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
        Debug() << "Sending json: " << ( data.size() > 100 ? data.left(100) + "..." : data);
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
        Debug() << "Sending result json: " << ( data.size() > 100 ? data.left(100) + "..." : data);
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */); // FIXME for bitcoind!
    }

    void Connection::on_readyRead()
    {
        Debug() << __FUNCTION__;
        Message::Id lastMsgId;
        try {
            while (socket->canReadLine()) {
                lastMsgId.clear();
                auto data = socket->readLine();
                nReceived += data.length();
                auto line = data.trimmed();
                Debug() << "Got: " << line;
                const QVariantMap jsonData( Util::Json::parseString(line, true).toMap() ); // may throw

                Message message = Message::fromJsonData(jsonData); // may throw

                static const auto ValidateParams = [](const Message &msg, const Method &m) {
                    if (m.numReqParams == Method::ANY_PARAMS)
                        return;
                    const int num = msg.params().count();
                    if (m.numReqParams >= 0 && num != m.numReqParams) {
                        throw InvalidParameters(QString("Expected %1 parameters for %2, got %3 instead").arg(m.numReqParams).arg(m.method).arg(num));
                    } else if (m.numReqParams < 0 && num < -m.numReqParams) {
                        throw InvalidParameters(QString("Expected at least %1 parameters for %2, got %3 instead").arg(-m.numReqParams).arg(m.method).arg(num));
                    }
                };

                if (message.isError()) {
                    // error message
                    emit gotErrorMessage(id, message);
                } else if (message.isNotif()) {
                    // todo fixme
                    const Method & m = methods[message.method];
                    if (m.method != message.method  || !m.allowsNotifications)
                        throw UnknownMethod(QString("Unsupported notification: %1").arg(message.method));
                    ValidateParams(message, m);
                    emit gotMessage(id, message);
                } else if (message.isRequest()) {
                    const Method & m = methods[message.method];
                    if (m.method != message.method || !m.allowsRequests)
                        throw UnknownMethod(QString("Unsupported request: %1").arg(message.method));
                    ValidateParams(message, m);
                    lastMsgId = message.id;
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
        } catch (const std::exception &e) {
            // TODO: clean this up. It's rather inelegant. :/
            const bool wasJsonParse = dynamic_cast<const Util::Json::ParseError *>(&e);
            const bool wasUnk = dynamic_cast<const UnknownMethod *>(&e);
            const bool wasInv = dynamic_cast<const InvalidRequest *>(&e) || dynamic_cast<const InvalidError *>(&e);
            const bool wasInvParms = dynamic_cast<const InvalidParameters *>(&e);
            int code = -32000;
            if (wasJsonParse) code = -32700;
            else if (wasInvParms) code = -32602;
            else if (wasUnk) code = -32601;
            else if (wasInv) code = -32600;
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
        }
    }
} // end namespace RPC
