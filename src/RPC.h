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
#pragma once

#include "AbstractConnection.h"
#include "Json/Json.h"
#include "RPCMsgId.h"
#include "Util.h"

#include <QHash>
#include <QMap>
#include <QSet>
#include <QString>
#include <QVariant>

#include <memory>
#include <optional>
#include <utility> // for std::pair
#include <variant>

namespace WebSocket { class Wrapper; } ///< fwd decl

namespace RPC {

    /// Thrown on json that is a json object but doesn't match JSON-RPC 2.0 spec.
    struct InvalidError : Json::Error {
        using Json::Error::Error;
    };

    enum ErrorCodes {
        /// "Parse error" ; Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.
        Code_ParseError = -32700,
        /// "Invalid Request" ; The JSON sent is not a valid Request object.
        Code_InvalidRequest = -32600,
        /// "Method not found" ; The method does not exist / is not available.
        Code_MethodNotFound = -32601,
        /// "Invalid params" ; Invalid method parameter(s).
        Code_InvalidParams = -32602,
        /// "Internal error" ; Internal JSON-RPC error.
        Code_InternalError = -32603,
        /// "Server error" 100 error codes that are reserved for implementation-defined server-errors.
        Code_ReservedError = -32000,
        /// Anything above this number is ok for us to use for application-specific errors.
        Code_Custom = -31999,
        /// Application-level bad request, eg request a header out of range, etc
        Code_App_BadRequest = 1,
        /// Daemon problem
        Code_App_DaemonError = 2,
        /// Excessive flood
        Code_App_ExcessiveFlood = 3,
        /// Limit exceeded
        Code_App_LimitExceeded = 4,
    };

    using KeySet = QSet<QString>;

    /// this is used to lay out the protocol methods a class supports in code
    /// Trivially constructible and copyable
    struct Method
    {
        QString method; // eg 'server.ping' or 'blockchain.headers.subscribe', etc
        /// If allowsRequests is false, requests for this method will return an error.
        /// If allowsNotifications is false, notifications for this method will be silently ignored.
        bool allowsRequests = true, allowsNotifications = false;
        using PosParamRange = std::pair<unsigned, unsigned>;
        static constexpr unsigned NO_POS_PARAM_LIMIT = UINT_MAX; ///< use this for PosParamsRange.second to specify no limit.
        /// If this optional !has_value, then positional arguments (list for "params") are rejected.
        /// Otherwise, specify an unsigned int range where .first is the minimum and .second is the maximum number
        /// of positional parameters accepted.  If .second is NO_POS_PARAM_LIMIT, then any number of parameters from
        /// .first onward is accepted.
        std::optional<PosParamRange> opt_nPosParams = PosParamRange{0, NO_POS_PARAM_LIMIT};
        /// If this optional !has_value, then named arguments (dict for "params") are rejected.
        /// If this optional has_value, we also accept kwargs (named args) appearing in the specified set
        /// (case sensitive). (Note that a method can theoretically accept both position and kwargs if so configured).
        std::optional<KeySet> opt_kwParams = {}; // '= {}' is how you specify undefined (!has_value)
        /// If true, and if opt_kwParams.has_value, then we are ok with extra 'params' coming in that are not in
        /// *opt_kwParams (but we still reject if keys in *opt_kwParams are missing from incoming 'params', thus
        /// *opt_kwParams becomes a set of minimally required params, and we ignore everything extra if this is true).
        bool allowUnknownNamedParams = false;
    };

    extern const QString jsonRpcVersion; ///< always "2.0"

    /// An RPC message.  A request, response, method call or error all use this generic struct.
    /// Note this struct is cheap to copy because it uses Qt's copy-on-write containers which are fast on copy
    /// because they update a shared data pointer and refct.  So we don't bother wrapping this
    /// in a shared_ptr or other stuff when passing it across threads, emitting it in signals, etc.
    /// TODO: see if performance benefit can be gained by wrapping in shared_ptr anyway..
    struct Message
    {
        using Id = RPCMsgId;

        // -- DATA --

        Id id; ///< guaranteed to be either string, qint64, or nullptr
        QString method; /**< methodName extracted from data['method'] if it was present. If this is empty then no
                             'method' key was present in JSON. May also contain the "matched" method on a response
                             object where we matched the id to a method we knew about in Connection::idMethodMap. */
        QVariantMap data; ///< parsed json. 'method', 'jsonrpc', 'id', 'error', 'result', and/or 'params' get put here
        bool v1 = false; ///< iff true, we parse/validate/generate based on JSON-RPC 1.0 rules, otherwise we enforce 2.0.
        // -- METHODS --

        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromUtf8(const QByteArray &, Id *id_out = nullptr, bool v1 = false);
        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromJsonData(const QVariantMap &jsonData, Id *id_parsed_even_if_failed = nullptr, bool v1 = false);
        // 4 more factories below..
        /// will not throw exceptions
        static Message makeError(int code, const QString & message, const Id & id = Id(), bool v1 = false);
        /// will not throw exceptions
        static Message makeRequest(const Id & id, const QString &methodName, const QVariantList & paramsList = QVariantList(), bool v1 = false);
        static Message makeRequest(const Id & id, const QString &methodName, const QVariantMap & paramsList = QVariantMap(), bool v1 = false);
        /// similar to makeRequest. A notification is just like a request but always lacking an 'id' member. This is used for asynch notifs.
        static Message makeNotification(const QString &methodName, const QVariantList & paramsList = QVariantList(), bool v1 = false);
        static Message makeNotification(const QString &methodName, const QVariantMap & paramsList = QVariantMap(), bool v1 = false);
        /// will not throw exceptions
        static Message makeResponse(const Id & reqId, const QVariant & result, bool v1 = false);

        /// Note in pathological cases bad_alloc may be thrown here, so we just return an empty QString in that case and hope for the best.
        QByteArray toJsonUtf8() const { QByteArray ret; try {ret = Json::toUtf8(data, true);} catch (...) {} return ret; }

        // -- PERFORMANCE OPTIMIZATION --
        // It turns out QString::QString(const char *) is called a lot in typical usase of this class, so we pre-create
        // the strings we will need as static data, app-wide.
        static const QString s_code;    ///< "code"
        static const QString s_data;    ///< "data"
        static const QString s_error;   ///< "error"
        static const QString s_id;      ///< "id"
        static const QString s_jsonrpc; ///< "jsonrpc"
        static const QString s_message; ///< "message"
        static const QString s_method;  ///< "method"
        static const QString s_params;  ///< "params"
        static const QString s_result;  ///< "result"
        // ./

        bool isError() const {
            if (!v1)
                return data.contains(s_error); // v2, error= key missing unless is an actual error result.
            else
                return !data.value(s_error).isNull(); // v1, error=null may always be there. is error if it's not null
        }
        int  errorCode() const { return data.value(s_error).toMap().value(s_code).toInt(); }
        QString  errorMessage() const { return data.value(s_error).toMap().value(s_message).toString(); }
        QVariant errorData() const { return data.value(s_error).toMap().value(s_data); }

        bool isRequest() const { return !isError() && hasMethod() && (hasId() && (!v1 || !id.isNull())) && !hasResult(); }
        bool isResponse() const { return !isError() && hasResult() && hasId(); }
        bool isNotif() const {
            if (!v1)
                return !isError() && !hasId() && !hasResult() && hasMethod(); // v2 notifs -- NO ID present
            else
                return !isError() && hasId() && id.isNull() && !hasResult() && hasMethod(); // v1 notifs..  ID present, but must be null.
        }

        bool hasId() const { return data.contains(s_id); }

        bool hasParams() const { return data.contains(s_params); }
        bool isParamsList() const { return QMetaType::Type(data.value(s_params).type()) == QMetaType::QVariantList; }
        bool isParamsMap() const { return QMetaType::Type(data.value(s_params).type()) == QMetaType::QVariantMap; }
        QVariant params() const { return data.value(s_params); }
        QVariantList paramsList() const { return params().toList(); }
        QVariantMap paramsMap() const { return params().toMap(); }


        bool hasResult() const { return data.contains(s_result); }
        QVariant result() const { return data.value(s_result); }

        bool hasMethod() const { return data.contains(s_method); }

        QString jsonRpcVersion() const { return data.value(s_jsonrpc).toString(); }
    };


    using MethodMap = QHash<QString, Method>;

    /// A semi-concrete derived class of AbstractConnection implementing a
    /// JSON-RPC based method<->result protocol.  This class is client/server
    /// agnostic and it just operates in terms of JSON RPC methods and results.
    /// It can be used for either a client or a server.
    ///
    /// Note that this class is somewhat transport agnostic and is intended to
    /// be re-used for either HTTP or line-based (as in Electrum) JSON-RPC via
    /// subclassing.
    ///
    /// Concrete subclasses should implement on_readyRead() and wrapForSend().
    ///
    /// This class just processes JSON. Subclasses implementing on_readyRead()
    /// should call processJson() in this base to process the potential JSON
    /// further. processJson() does validation and may implicitly close the
    /// connection, etc if it doesn't like the data it received.  processJson()
    /// is intended to be called when the subclass thinks the client has sent it a
    /// full "packet" of a JSON RPC message.
    ///
    /// Note we implement a subset of JSON-RPC 2.0 which requires 'id' to
    /// always be ints, strings, or null.  We do not accept floats for id (the
    /// JSON-RPC 2.0 spec strongly recommends against floats anyway, we are just
    /// slighlty more strict than the spec).
    ///
    /// Methods invoked on the peer need an id, and this id is used to track
    /// the reply back and associate it with the method that was invoked on
    /// the peer (see idMethodMap instance var).
    ///
    /// See class Server for an example class that constructs a MethodMap and
    /// passes it down.
    ///
    /// Classes that manage rpc methods should register for the gotMessage()
    /// signal and process incoming messages further.  All incoming messages
    /// are either requests or notifications.
    ///
    /// gotErrorMessage can be used to receive error messages.
    ///
    /// Note that gotMessage() won't always be emitted if the message was
    /// filtered out (eg, a notification received but no "method" defined for
    /// it, or a result received without a known id in idMethodMap, etc).
    ///
    /// Server's 'Client' class derives from this.
    ///
    class ConnectionBase : public AbstractConnection
    {
        Q_OBJECT

        Q_PROPERTY(bool v1 READ isV1 WRITE setV1)
    protected:
        /// Subclasses should call processJson to process what they think may be a complete JSON-RPC message.
        ///
        /// Note the move semantics here. We take ownership of the passed-in QByteArray and clear it immediately
        /// once JSON processing is done, but before callbacks are dispatched -- this is to reduce peak memory usage
        /// if processing a huge JSON payload containing a big block (for networks like ScaleNet).
        void processJson(QByteArray &&);

        /* --
         * -- Stuff subclasses must implement to make use of this class as base:
         * --
         */

        /// subclasses must implement this to wrap outgoing data for sending.
        virtual QByteArray wrapForSend(const QByteArray &) = 0;

        /* subclasses must also implement this pure virtual inherited from base:
             void on_readyRead() override; */

        /*
         * /end
         */

    public:
        ConnectionBase(const MethodMap & methods, IdMixin::Id id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);
        ~ConnectionBase() override;

        const MethodMap & methods; //< Note: this map needs to remain alive for the lifetime of this connection (and all connections) .. so it should point to static or long-lived data, ideally

        struct BadPeer : public Exception {
            using Exception::Exception;  // bring in c'tor
        };

        /// if peer asked for an unknown method
        struct UnknownMethod : public Exception { using Exception::Exception; };

        /// If peer request object was not JSON-RPC 2.0
        struct InvalidRequest : public BadPeer { using BadPeer::BadPeer; };
        /// If peer request object has invalid number of params
        struct InvalidParameters : public BadPeer { using BadPeer::BadPeer; };


        static constexpr int MAX_UNANSWERED_REQUESTS = 20000; ///< TODO: tune this down. For testing we leave this high for now.

        bool isV1() const { return v1; }
        void setV1(bool b) { v1 = b; }

    signals:
        /// call (emit) this to send a request to the peer
        void sendRequest(const RPC::Message::Id & reqid, const QString &method, const QVariantList & params = QVariantList());
        /// call (emit) this to send a notification to the peer
        void sendNotification(const QString &method, const QVariant & params);
        /// call (emit) this to send a request to the peer
        void sendError(bool disconnectAfterSend, int errorCode, const QString &message, const RPC::Message::Id & reqid = Message::Id());
        /// call (emit) this to send a result reply to the peer (result= message)
        void sendResult(const RPC::Message::Id & reqid, const QVariant & result = QVariant());

        /// this is emitted when a new message arrives that was successfully parsed and matches
        /// a known method described in the 'methods' MethodMap. Unknown messages will eventually result
        /// in auto-disconnect.
        void gotMessage(IdMixin::Id thisId, const RPC::Message & m);
        /// Same as a above, but for 'error' replies
        void gotErrorMessage(IdMixin::Id thisId, const RPC::Message &em);
        /// This is emitted when the peer sent malformed data to us and we didn't disconnect
        /// because errorPolicy is not ErrorPolicyDisconnect
        void peerError(IdMixin::Id thisId, const QString &what);

    protected slots:
        /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in this object's
        /// thread context. Eventually calls send() -> do_write() (from superclass).
        virtual void _sendRequest(const RPC::Message::Id & reqid, const QString &method, const QVariantList & params = QVariantList());
        // ditto for notifications
        virtual void _sendNotification(const QString &method, const QVariant & params);
        /// Actual implementation of sendError, runs in our thread context.
        virtual void _sendError(bool disconnect, int errorCode, const QString &message, const RPC::Message::Id &reqid = Message::Id());
        /// Actual implementation of sendResult, runs in our thread context.
        virtual void _sendResult(const RPC::Message::Id & reqid, const QVariant & result = QVariant());

    protected:
        /// chains to base, connects sendRequest signal to _sendRequest slot
        void on_connected() override;
        /// Chains to base, clears idMethodMap
        void on_disconnected() override;

        /// adds the nRequestsSent, etc stats
        Stats stats() const override;

        /// map of requests that were generated via _sendRequest to method names to build a more meaningful Message
        /// object (which has a .method defined even on 'result=' messages).  It is an error to receive a result=
        /// message from the peer with its id= parameter not having an entry in this map.
        QHash<Message::Id, QString> idMethodMap;

        enum ErrorPolicy {
            /// Send an error RPC message on protocol errors.
            /// If this is set and ErrorPolicyDisconnect is set, the disconnect will be graceful.
            ErrorPolicySendErrorMessage = 1,
            /// Disconnect on RPC protocol errors. If this is set along with ErrorPolicySendErrorMessage,
            /// the disconnect will be graceful.
            ErrorPolicyDisconnect = 2,
        };
        /// derived classes can set this internally (bitwise or of ErrorPolicy*)
        /// to affect on_readyRead()'s behavior on peer protocol error.
        int errorPolicy = ErrorPolicyDisconnect;

        bool v1 = false; // if true, will generate v1 style messages and respond to v1 only

        QString lastPeerError;
        quint64 nRequestsSent = 0, nNotificationsSent = 0, nResultsSent = 0, nErrorsSent = 0;
        quint64 nErrorReplies = 0, nUnansweredLifetime = 0;

        /// New in 1.0.1: This is latched to true in Client::on_disconnect to signal that the client is being
        /// disconnected and to just throw away any future messages from this client.
        bool ignoreNewIncomingMessages = false;
    };

    /// Concrete class. For Electrum Cash style JSON RPC.
    /// This class can be used either with a bare QTcpSocket/QSslSocket in which case newlines delimit RPC messages.
    /// If used with a WebSocket::Wrapper instance, messages are already framed and newlines are not required.
    class ElectrumConnection : public ConnectionBase {
    public:
        using ConnectionBase::ConnectionBase;
        ~ElectrumConnection() override; ///< for vtable

        // the below two can/should only be called from the same thread as this object's thread
        void setReadPaused(bool);
        bool isReadPaused() const { return readPaused; }

        /// Reimplemented from AbstractConnection.
        /// Returns true if the socket is wrapped by a WebSocket::Wrapper, false otherwise.
        bool isWebSocket() const override;
        /// Reimplemnted from AbstractConnection.
        /// Returns true if the underlying socket is a QSslSocket (either the socket itself or the nested one wrapped by
        /// a WebSocket::Wrapper), false otherwise.
        bool isSsl() const override;

    protected:
        /// implements pure virtual from super to handle linefeed-based JSON. When a full line arrives, calls ConnectionBase::processJson
        void on_readyRead() override;
        QByteArray wrapForSend(const QByteArray &) override;

    private:
        bool memoryWasteTimerActive = false;  ///< inticates the DoS protection timer is active, used by memoryWasteDoSProtection
        qint64 memoryWasteThreshold = -1; ///< gets lazy-initialized in memoryWasteDoSProtection below
        void memoryWasteDoSProtection(); ///< must be called from on_readyRead only.

        bool readPaused = false;
        bool skippedOnReadyRead = false;
        std::optional<WebSocket::Wrapper *> webSocket; ///< set once the first time on_readyRead() or wrapForSend() is called. If set and valid, affects the framing behavior of this class.
        WebSocket::Wrapper *checkSetGetWebSocket();
    };

    /// JSON RPC over HTTP.  Wraps the outgoing data in headers and can also parse incoming headers.
    /// For use by the bitcoind rpc mechanism.
    class HttpConnection : public ConnectionBase {
        Q_OBJECT
    public:
        using ConnectionBase::ConnectionBase;
        ~HttpConnection() override; ///< for vtable

        /// For: "Authorization: Basic <cookie>"; used to calculate the <cookie>
        void setAuth(const QString & username, const QString & password);
        void clearAuth() { header.authCookie.clear(); }

        /// Sets the HTTP header "Host:" field.  This string will be sent verbatim to the other end when
        /// doing an HTTP/1.1 POST.  This must be set if acting as a client, otherwise no "Host:" header
        /// field will be sent, which some endpoints don't like (namely bchd) since it violates RFC 2616.
        void setHeaderHost(const QString &);
        QString headerHost() const { return header.host; }
        void clearHeaderHost() { header.host.clear(); }

        //static void Test();
    signals:
        /// emitted when the other side (usually bitcoind) didn't accept our auth cookie.
        void authFailure(HttpConnection *me);

    protected:
        void on_readyRead() override;
        QByteArray wrapForSend(const QByteArray &) override;

    private:
        /// These end up verbatim in the HTTP/1.1 POST header.
        struct {
            QByteArray authCookie; ///< "Authorization: Basic <cookie>"
            QByteArray host; ///< "Host: <host>"; caller should set this if acting as a client
        } header;
        struct StateMachine;
        using SMDel = std::function<void(StateMachine *)>;
        std::unique_ptr<StateMachine, SMDel> sm; ///< we need to declare this with a deleter otherwise subclasses won't be able to inherit from us because StateMachine is a private, opaque struct; the need for a deleter is due to implementation details of how unique_ptr works with opaque types.
    };

    /// Query whether using the simdjson backend or using default for JSON parsing.
    bool isFastJson();
    /// Set fast Json parsing to on or off. Note that the requested setting may not take effect if we are missing
    /// the underlying libs or are on an unsupported platform.  As such, this returns true on success, false on failure.
    bool setFastJson(bool);

} // end namespace RPC

/// So that Qt signal/slots work with this type.  Metatypes are also registered at startup via qRegisterMetatype
Q_DECLARE_METATYPE(RPC::Message);
Q_DECLARE_METATYPE(RPC::Message::Id);
