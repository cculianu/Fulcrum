#ifndef SHUFFLEUP_RPC_H
#define SHUFFLEUP_RPC_H

#include <QString>
#include <QVariant>
#include "Util.h"

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
        QVariantMap toStrippedMap() const; ///< returns null map if !isValid, otherwise returns the schema's map with control codes stripped from keys

        bool isValid() const { return valid; }

        /// This method is the whole point of why this class exists. Call it and it will throw
        /// SchemaError (with a possible explanation of what's missing in the excetion.what()),
        /// or it may throw Util::Json::Error if the json itself is bad.
        /// Use this test when parsing JSON RPC requests or replies as a filter against obviously bad
        /// messages.  (Further tests should then be used to check the sanity of the actual messages.)
        QVariantMap parseAndThrowIfNotMatch(const QString &json) const;
        /// Alternatively, call this if you don't want to catch exceptions. Empty QVariantMap is returned on error,
        /// with optional errorString pointer set to the error message (if not nullptr).
        QVariantMap match(const QString &json, QString *errorString = nullptr) const;

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

    struct MethodData;

    /// this is used to lay out the protocol methods a class supports in code
    struct Method
    {
        QString method; // eg 'server.ping' or 'blockchain.headers.subscribe', etc
        Schema schema = schemaMethod;
        Schema resultSchema = RPC::schemaResult;

        Method(const QString &method, const Schema &schema = schemaMethod, const Schema & resultSchema = RPC::schemaResult)
            : method(method), schema(schema), resultSchema(resultSchema) {}
        /// constructs an invalid ProtocolMethod
        Method() {}
        bool isValid() const { return !method.isEmpty() && schema.isValid() && resultSchema.isValid(); }
    };


    constexpr qint64 NO_ID = LONG_LONG_MIN;

    /// this is used for in-flight method data, sent to components that respond to method.
    struct MethodData
    {
        QSharedPointer<const Method> spec; ///< pointer to always-around data that outlives the lifetime of this object, ideally. If not sharedptr takes care of it.
        QString method;
        QVariantList params;
        qint64 id = NO_ID; // NO_ID indicatess it was missing from the protocol cmd, otherwise it will be a positive integer

        bool hasId() const { return id != NO_ID; }
    };

}

#endif // SHUFFLEUP_RPC_H
