#ifndef SHUFFLEUP_RPC_H
#define SHUFFLEUP_RPC_H

#include "Util.h"
#include "AbstractConnection.h"
#include <QString>
#include <QVariant>
#include <QMap>
#include <QSharedPointer>

namespace RPC {

    struct SchemaError : Util::Json::Error {
        using Util::Json::Error::Error;
    };

    struct SchemaMismatch : SchemaError {
        using SchemaError::SchemaError;
    };

    struct RecursionLimitReached :SchemaError {
        using SchemaError::SchemaError;
    };

    class Schema  {
    public:
        Schema() {}
        Schema(const Schema & other) { *this = other; }
        /// NB: all of the below methods may throw Util::Json::Error or a subclass!
        Schema(const QString & json) { setFromString(json); }
        Schema(const char * json) { setFromString(json); }
        Schema(Schema &&other) : valid(other.valid), vmap(std::move(other.vmap)) {}

        void setFromString(const QString & json); ///< may throw Util::Json::Error
        Schema & updateFromString(const QString &json); ///< may throw Util::Json::Error

        QString toString() const; ///< retuns null string if !isValid, otherwise returns json (control codes included in schema map keys).
        QVariantMap toMap() const; ///< returns null map if !isValid, otherwise returns the schema with control codes included
        QVariantMap toStrippedMap() const; ///< returns null map if !isValid, otherwise returns the schema's map with control codes stripped from keys & values

        bool isValid() const { return valid; }

        /// This method is the whole point of why this class exists. Call it and it will throw
        /// SchemaError (with a possible explanation of what's missing in the excetion.what()),
        /// or it may throw Util::Json::Error if the json itself is bad.
        /// Use this test when parsing JSON RPC requests or replies as a filter against obviously bad
        /// messages.  (Further tests should then be used to check the sanity of the actual messages.)
        QVariantMap parseAndThrowIfNotMatch(const QString &json) const;
        QVariantMap parseAndThrowIfNotMatch(const QVariantMap &map) const;
        /// Alternatively, call this if you don't want to catch exceptions. Empty QVariantMap is returned on error,
        /// with optional errorString pointer set to the error message (if not nullptr).
        QVariantMap match(const QString &json, QString *errorString = nullptr) const;
        QVariantMap match(const QVariantMap &map, QString *errorString = nullptr) const;

        Schema &operator=(const Schema &other) { vmap = other.vmap; valid = other.valid; return *this; }
        Schema &operator=(Schema &&other) { vmap = std::move(other.vmap); valid = other.valid; return *this; }
        Schema &operator=(const QString &json) { setFromString(json);  return *this; }
        Schema &operator+=(const QString &json) { updateFromString(json); return *this; }
        Schema operator+(const QString &json) const { return Schema(*this).updateFromString(json); }
    private:
        bool valid = false;
        QVariantMap vmap;

    public:
        static void test();
    };


    ///
    /// Schema definition bases.  Protocol spec should start with these and do, eg:
    ///    mySchema = schemaMethod + '{ "method" : "my.method.bla" .. }' etc
    ///
    extern const Schema schemaBase; ///< 'base' schema -- jsonrpc is only key ->  '{ "jsonrpc": "2.0!" }'
    extern const Schema schemaError; ///< base + error keys : schemaBase + '{ "error..." ->   { "code" : 1, "message" : "astring" }, "*id" : 1, "method?" : "anystring"  }'
    extern const Schema schemaResult; ///< 'result' schema ('result' : whatever, 'id' : int) (immediate reply from server) ->  schemaBase + ' { "id" : 1, "*result" : "*" }'
    extern const Schema schemaMethod; ///< 'method' (asynch event from peer) schema ( 'method' : 'methodname', 'params' : [params] ) ->  schemaBase + ' { "method": "astring", "params" : [], "*id?" : 1 }'
    extern const Schema schemaMethodNoParams; ///< 'method' (asynch event from peer) schema ( 'method' : 'methodname', 'params' : [params] ) ->  schemaBase + ' { "method": "astring", "params" : [\"=0\"], "*id?" : 1 }'
    extern const Schema schemaMethodOneParam; ///< 'method' (asynch event from peer) schema ( 'method' : 'methodname', 'params' : [params] ) ->  schemaBase + ' { "method": "astring", "params" : [\"=1\"], "*id?" : 1 }'
    extern const Schema schemaMethodTwoParams; ///< 'method' (asynch event from peer) schema ( 'method' : 'methodname', 'params' : [params] ) ->  schemaBase + ' { "method": "astring", "params" : [\"=2\"], "*id?" : 1 }'

    /// this is used to lay out the protocol methods a class supports in code
    struct Method
    {
        QString method; // eg 'server.ping' or 'blockchain.headers.subscribe', etc
        Schema inSchema = schemaMethod; ///< schma used when peer calls this RPC method on us
        Schema resultSchema = schemaResult; ///< schema used for RPC request results
        Schema outSchema = schemaMethod;  ///< schema we use when we send out an RPC request to peer

        Method(const QString & method,
               const Schema & inSchema = schemaMethod,
               const Schema & resultSchema = schemaResult,
               const Schema & outSchema = schemaMethod)
            : method(method), inSchema(inSchema), resultSchema(resultSchema), outSchema(outSchema) {}
        /// default c'tor for convenience
        Method() {}
    };


    constexpr qint64 NO_ID = -1;


    /// An RPC message.  A request, response, method call or error all use this generic struct.
    struct Message
    {
        /// may throw Exception. This factory method should be the way one constructs this object
        static Message fromJsonData(const QVariantMap &jsonData, const Schema & schema);
        /// uses schemaError -- will not throw exception
        static Message makeError(int code, const QString & message, qint64 id = NO_ID);
        /// uses provided schema -- will not throw exception
        static Message makeMethodRequest(qint64 id, const QString &methodName, const QVariantList & params, const Schema & schema);

        QVariantMap jsonData;
        Schema schema;

        QString toJsonString() const { try {return Util::Json::toString(jsonData, true);} catch (...) {} return QString(); }

        QString jsonRpcVersion;
        qint64 id = NO_ID;
        QString method;
        QVariant data; // 'result' or 'params' get put here

        int errorCode = 0;
        QString errorMessage = "";

        bool isError() const { return bool(errorCode); }
        bool isList() const { return QMetaType::Type(data.type()) == QMetaType::QVariantList; }
    };


    typedef QMap<QString, QSharedPointer<Method> > MethodMap;

    /// A concrete derived class of AbstractConnection implementing a JSON-RPC
    /// based method<->result protocol similar to ElectrumX's protocol.  This
    /// class is client/server agnostic and it just operates in terms of JSON
    /// RPC methods and results.  It can be used for either a client or a
    /// server.
    ///
    /// Methods invoked on the peer need an id, and this id is used to track
    /// the reply back and associate it with the method that was invoked on
    /// the peer (see idMethodMap instance var).
    ///
    /// We use this protocol on the client-facing side too to negotiate
    /// shuffles, hence why this is abstracted out into a separate class. This
    /// class is responsible for parsing the JSON and closing the connections
    /// on malformed input that doesn't match the expected 'Schema'.  This
    /// class is configured for which methods it supports and what the various
    /// method schemas are via the 'MethodMap' passed to it at construction.
    ///
    /// See EXMgr for an example class that constructs a MethodMap and passes
    /// it down.
    ///
    /// Classes that manage rpc methods should register for the gotMessage()
    /// signal and process incoming messages further.  All incoming messages
    /// are either errors (errorCode != 0) or have a valid message.method name.
    ///
    /// Both EXClient and TCPServer's 'Client' class derive from this.
    ///
    class Connection : public AbstractConnection
    {
        Q_OBJECT
    public:
        Connection(const MethodMap & methods, qint64 id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);
        ~Connection() override;

        const MethodMap methods;

        struct BadPeer : public Exception {
            using Exception::Exception; /// bring in c'tor
        };

    signals:
        /// call (emit) this to send a request to the server
        void sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());
        /// call (emit) this to send a request to the server
        void sendError(bool disconnectAfterSend, int errorCode, const QString &message, qint64 reqid = NO_ID);
        /// this is emitted when a new message arrives that was successfully parsed and matches
        /// a known method described in the 'methods' MethodMap. Unknown messages will result
        /// in auto-disconnect.  (TODO: Implement error JSON replies to peer as well as tolerance for some malformed
        /// data up until a threshold is reached?)
        void gotMessage(RPC::Connection *, const RPC::Message & m);
        /// Same as a above, but for 'error' replies
        void gotErrorMessage(RPC::Connection *, const RPC::Message &em);

    protected slots:
        /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in this object's
        /// thread context. Eventually calls send() -> do_write() (from superclass).
        virtual void _sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());
        /// Actual implementation of sendError, runs in our thread context.
        virtual void _sendError(bool disconnect, int errorCode, const QString &message, qint64 reqid = NO_ID);

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
        QMap<qint64, QString> idMethodMap;
    };

} // end namespace RPC

/// So that Qt signal/slots work with this type.
Q_DECLARE_METATYPE(RPC::Message);

#endif // SHUFFLEUP_RPC_H
