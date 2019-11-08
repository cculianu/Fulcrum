#ifndef FULCRUM_RPC_H
#define FULCRUM_RPC_H

#include "Util.h"
#include "AbstractConnection.h"
#include <QString>
#include <QVariant>
#include <QMap>

#include <variant>

namespace RPC {

    /// Thrown on json that is a json object but doesn't match JSON-RPC 2.0 spec.
    struct InvalidError : Util::Json::Error {
        using Util::Json::Error::Error;
    };

    /// this is used to lay out the protocol methods a class supports in code
    /// Trivially constructible and copyable
    struct Method
    {
        QString method; // eg 'server.ping' or 'blockchain.headers.subscribe', etc
        bool allowsRequests = true, allowsNotifications = false;
        static constexpr int ANY_PARAMS = 0x7fffffff;
        int numReqParams = ANY_PARAMS; // -N meaning N or more params, 0 = no params expected, positive N == EXACTLY N params, ANY_PARAMS means we accept anything.
    };

    extern const QString jsonRpcVersion; ///< always "2.0"

    /// An RPC message.  A request, response, method call or error all use this generic struct.
    struct Message
    {
        using IdBase = std::variant<std::nullptr_t, qint64, QString>;
        struct Id : public IdBase {
            using IdBase::variant;
            using IdBase::operator=;
            Id & operator=(const QVariant &); // will throw InvalidError if type of QVariant is not one of: qint64, QString, or isNull()
            operator QVariant() const; // will return a QVariant whose type is either: qint64, QString, or isNull()
            void clear() { *this = nullptr; }
            bool isNull() const { return index() == 0; }
            QString toString() const { return static_cast<QVariant>(*this).toString(); }
            bool operator<(const Id & other) const;
        };

        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromString(const QString &);
        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromJsonData(const QVariantMap &jsonData);
        // 4 more factories below..
        /// will not throw exceptions
        static Message makeError(int code, const QString & message, const Id & id = Id());
        /// will not throw exceptions
        static Message makeRequest(const Id & id, const QString &methodName, const QVariantList & params = QVariantList());
        /// similar to makeRequest. A notification is just like a request but always lacking an 'id' member. This is used for asynch notifs.
        static Message makeNotification(const QString &methodName, const QVariantList & params = QVariantList());
        /// will not throw exceptions
        static Message makeResponse(const Id & reqId, const QVariant & result);

        Id id; ///< guaranteed to be either string, qint64, or nullptr
        QString method; /**< methodName extracted from data['method'] if it was present. If this is empty then no
                             'method' key was present in JSON. May also contain the "matched" method on a response
                             object where we matched the id to a method we knew about in Connection::idMethodMap. */
        QVariantMap data; ///< parsed json. 'method', 'jsonrpc', 'id', 'error', 'result', and/or 'params' get put here

        QString toJsonString() const { try {return Util::Json::toString(data, true);} catch (...) {} return QString(); }

        bool isError() const { return data.contains("error"); }
        int  errorCode() const { return data.value("error").toMap().value("code").toInt(); }
        QString  errorMessage() const { return data.value("error").toMap().value("message").toString(); }
        QVariant errorData() const { return data.value("error").toMap().value("data"); }

        bool isRequest() const { return !isError() && hasMethod() && hasId() && !hasResult(); }
        bool isResponse() const { return !isError() && hasResult() && hasId(); }
        bool isNotif() const { return !isError() && !hasId() && !hasResult() && hasMethod(); }


        bool hasId() const { return data.contains("id"); }

        bool hasParams() const { return data.contains("params"); }
        bool isParamsList() const { return QMetaType::Type(data.value("params").type()) == QMetaType::QVariantList; }
        //bool isParamsMap() const { return QMetaType::Type(data.value("params").type()) == QMetaType::QVariantMap; }
        QVariantList params() const { return data.value("params").toList(); }
        //QVariantMap paramsMap() const { return data.value("params").toMap(); }


        bool hasResult() const { return data.contains("result"); }
        QVariant result() const { return data.value("result"); }

        bool hasMethod() const { return data.contains("method"); }

        QString jsonRpcVersion() const { return data.value("jsonrpc").toString(); }
    };


    typedef QMap<QString, Method > MethodMap;

    /// A concrete derived class of AbstractConnection implementing a JSON-RPC
    /// based method<->result protocol similar to ElectrumX's protocol.  This
    /// class is client/server agnostic and it just operates in terms of JSON
    /// RPC methods and results.  It can be used for either a client or a
    /// server.
    ///
    /// Note we implement a subset of JSON-RPC 2.0 which requires 'id' to
    /// always be positive ints, or null.  We do not accept strings for id,
    /// floats, or negative numbers.
    ///
    /// Methods invoked on the peer need an id, and this id is used to track
    /// the reply back and associate it with the method that was invoked on
    /// the peer (see idMethodMap instance var).
    ///
    /// We use this protocol on the client-facing side too to serve clients,
    /// hence why this is abstracted out into a separate class. This
    /// class is responsible for parsing the JSON and closing the connections
    /// on malformed input that doesn't match the expected 'Schema'.  This
    /// class is configured for which methods it supports and what the various
    /// method schemas are via the 'MethodMap' passed to it at construction.
    ///
    /// See class Server for an example class that constructs a MethodMap and
    /// passes it down.
    ///
    /// Classes that manage rpc methods should register for the gotMessage()
    /// signal and process incoming messages further.  All incoming messages
    /// are either errors (errorCode != 0) or have a valid message.method name.
    ///
    /// Server's 'Client' class derives from this.
    ///
    class Connection : public AbstractConnection
    {
        Q_OBJECT
    public:
        Connection(const MethodMap & methods, qint64 id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);
        ~Connection() override;

        const MethodMap methods;

        struct BadPeer : public Exception {
            using Exception::Exception;  // bring in c'tor
        };

        /// If this is thrown we unconditionally disconnect.
        struct BadPeerAbort : public BadPeer { using BadPeer::BadPeer; };

        /// if peer asked for an unknown method
        struct UnknownMethod : public Exception { using Exception::Exception; };

        /// If peer request object was not JSON-RPC 2.0
        struct InvalidRequest : public BadPeer { using BadPeer::BadPeer; };
        /// If peer request object has invalid number of params
        struct InvalidParameters : public BadPeer { using BadPeer::BadPeer; };


        static constexpr int MAX_UNANSWERED_REQUESTS = 20000;

    signals:
        /// call (emit) this to send a request to the peer
        void sendRequest(const Message::Id & reqid, const QString &method, const QVariantList & params = QVariantList());
        /// call (emit) this to send a notification to the peer
        void sendNotification(const QString &method, const QVariantList & params = QVariantList());
        /// call (emit) this to send a request to the peer
        void sendError(bool disconnectAfterSend, int errorCode, const QString &message, const Message::Id & reqid = Message::Id());
        /// call (emit) this to send a result reply to the peer (result= message)
        void sendResult(const Message::Id & reqid, const QString &method, const QVariant & result = QVariant());

        /// this is emitted when a new message arrives that was successfully parsed and matches
        /// a known method described in the 'methods' MethodMap. Unknown messages will eventually result
        /// in auto-disconnect.
        void gotMessage(qint64 thisId, const RPC::Message & m);
        /// Same as a above, but for 'error' replies
        void gotErrorMessage(qint64 thisId, const RPC::Message &em);
        /// This is emitted when the peer sent malformed data to us and we didn't disconnect
        /// because errorPolicy is not ErrorPolicyDisconnect
        void peerError(qint64 thisId, const QString &what);

    protected slots:
        /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in this object's
        /// thread context. Eventually calls send() -> do_write() (from superclass).
        virtual void _sendRequest(const Message::Id & reqid, const QString &method, const QVariantList & params = QVariantList());
        // ditto for notifications
        virtual void _sendNotification(const QString &method, const QVariantList & params = QVariantList());
        /// Actual implementation of sendError, runs in our thread context.
        virtual void _sendError(bool disconnect, int errorCode, const QString &message, const Message::Id &reqid = Message::Id());
        /// Actual implementation of sendResult, runs in our thread context.
        virtual void _sendResult(const Message::Id & reqid, const QString &method, const QVariant & result = QVariant());

    protected:
        /// parses RPC, implements pure virtual from super to handle line-based JSON.
        void on_readyRead() override;
        /// chains to base, connects sendRequest signal to _sendRequest slot
        void on_connected() override;
        /// Chains to base, clears idMethodMap
        void on_disconnected() override;

        /// map of requests that were generated via _sendRequest to method names to build a more meaningful Message
        /// object (which has a .method defined even on 'result=' messages).  It is an error to receive a result=
        /// message from the peer with its id= parameter not having an entry in this map.
        QMap<Message::Id, QString> idMethodMap;

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
    };

} // end namespace RPC

/// So that Qt signal/slots work with this type.  Metatypes are also registered at startup via qRegisterMetatype
Q_DECLARE_METATYPE(RPC::Message);
Q_DECLARE_METATYPE(RPC::Message::Id);

#endif // FULCRUM_RPC_H
