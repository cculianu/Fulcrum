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

    struct Request;
    struct Result;
    struct ReqResultBase;

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

        inline void setSelf(const QSharedPointer<Method> & ptr) { self = ptr.toWeakRef(); }
        inline void setSelf(const QSharedPointer<const Method> & ptr) { self = ptr.constCast<Method>().toWeakRef(); }
        inline QSharedPointer<const Method> strongSelf() const { return self.toStrongRef().constCast<const Method>(); }

        Request createRequest(qint64 id, const QVariantList & params) const; ///< will use outSchema, requires self ptr be set
        Result createResult(qint64 id, const QVariant & arg) const; ///< will use resultSchema, requires self ptr be set

        // TODO: add a match function here that uses schemas above to construct Error, Result or Request objects

    private:
        QWeakPointer<Method> self; ///< classes that construct Methods should use QSharedPointers and set this.
    };


    constexpr qint64 NO_ID = -1;

    /// Base type for all in-flight method/request/etc data, sent to components that respond to methods, etc.
    struct ReqResultBase
    {
        qint64 id = NO_ID;
        QSharedPointer<const Method> method; ///< may be nullptr if no method parsed or specified.

        virtual ~ReqResultBase();

        bool hasId() const { return id != NO_ID; }

        /// return the map representing the json
        /// derived classes may raise if method is nullptr
        virtual QVariantMap toMap() const = 0;
        QString toJson() const;
    };

    struct ErrorResponse : public ReqResultBase
    {
        int code = 0;
        QString message;

        QVariantMap toMap() const override;
    };

    struct Result : public ReqResultBase
    {
        QVariant result; // check .type() to determine if map or list

        bool isList() const { return QMetaType::Type(result.type()) == QMetaType::QVariantList; }
        bool isMap() const { return QMetaType::Type(result.type()) == QMetaType::QVariantMap; }

        QVariantMap toMap() const override;
    };

    struct Request : public ReqResultBase
    {
        QVariantList params;

        QVariantMap toMap() const override;
    };


    typedef QMap<QString, QSharedPointer<Method> > MethodMap;

    class Connection : public AbstractConnection
    {
        Q_OBJECT
    public:
        Connection(const MethodMap & methods, qint64 id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);
        ~Connection() override;

        const MethodMap methods;

        class BadPeer : public Exception {
        public:
            using Exception::Exception; /// bring in c'tor
            ~BadPeer();
        };

    signals:
        /// call (emit) this to send a requesst to the server
        void sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());

    protected slots:
        /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in thread. Eventually calls send() -> do_write()
        virtual void _sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());

        /// parses RPC, implements pure virtual from base
        void on_readyRead() override;
    protected:
        /// chains to base, connects sendRequest signal to _sendRequest slot
        void on_connected() override;
    };
}

#endif // SHUFFLEUP_RPC_H
