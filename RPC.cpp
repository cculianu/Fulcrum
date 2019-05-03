#include "RPC.h"
#include <QtCore>


namespace RPC {

    /// Schema definitions
    ///
    /// Note:
    ///     Key Modifiers:
    ///         "*key" : means the key allows 'null', plus whatever type the value is in the spec
    ///         "key?" : means the key can be missing
    ///     Value Modifiers:
    ///         "text!" : means the value must match the string "text" exactly
    ///                   keys if specific in a dict must match and all be present.
    ///         ["=N"] (ex: ["=0"]) : means the value should be a list with exactly N strings
    ///         "*" : for a value means the value can be anything and any type (number, float, list, dict, null), but must be present.
    ///               anything else is taken as a type spec, so only the type of the thing must match.
    ///     A nested dict is analyzed for keys and keys must be present. An empty dict just means any dict. An
    ///     empty list just means any list.

    Schema const schemaBase = "{ \"jsonrpc\": \"2.0!\" }";
    Schema const schemaError = schemaBase + "{ \"error\" : { \"code\" : 1, \"message\" : \"astring\" }, \"*id\" : 1, \"method?\" : \"anystring\"  }";
    Schema const schemaResult = schemaBase + " { \"id\" : 1, \"*result\" : \"*\" }";
    Schema const schemaMethod = schemaBase + " { \"method\": \"astring\", \"params\" : [], \"*id?\" : 1 }";
    Schema const schemaMethodNoParams = schemaBase + " { \"method\": \"astring\", \"params\" : [\"=0\"], \"*id?\" : 1 }";
    Schema const schemaMethodOneParam = schemaBase + " { \"method\": \"astring\", \"params\" : [\"=1\"], \"*id?\" : 1 }";
    Schema const schemaMethodTwoParams = schemaBase + " { \"method\": \"astring\", \"params\" : [\"=2\"], \"*id?\" : 1 }";

    QString Schema::toString() const {
        if (!isValid()) return QString();
        return Util::Json::toString(vmap, true);
    }

    QVariantMap Schema::toMap() const {
        if (!isValid()) return QVariantMap();
        return vmap;
    }

    namespace {
        QString stripKeyControlCodes(const QString & key_in) {
            QString key(key_in);
            if (key.startsWith("*")) key = key.mid(1);
            if (key.endsWith("?")) key.resize(key.length()-1);
            return key;
        }
        QString stripValueControlCodes(const QString & s_in) {
            QString s(s_in);
            if (s.startsWith("=")) s = s.mid(1); // strip "=N" where N is some int
            else if (s.endsWith("!")) s.resize(s.length()-1);
            return s;
        }
        /// Note since the schema controls how far we recurse, this constant and check is likely unnecessary but we
        /// add it here as a defensive programming technique. At most we expect to recurse 2-3 deep during normal use.
        constexpr int MAX_RECURSION = 10;

        QVariantMap stripMap(int recursion_depth, const QVariantMap &vmap);
        QVariantList stripList(int recursion_depth, const QVariantList &vlist) {
            if (recursion_depth > MAX_RECURSION)
                throw RecursionLimitReached(QString("Recursion limit of %1 reached when parsing schema").arg(MAX_RECURSION));
            QVariantList ret;
            for (const auto & val : vlist ) {
                auto vtype = QMetaType::Type(val.type());
                if (vtype == QMetaType::QString) {
                    ret.push_back(stripValueControlCodes(val.toString()));
                } else if (vtype == QMetaType::QVariantList) {
                    ret.push_back(stripList(recursion_depth+1, val.toList()));
                } else if (vtype == QMetaType::QVariantMap) {
                    ret.push_back(stripMap(recursion_depth+1, val.toMap()));
                } else
                    ret.push_back(ret);
            }
            return ret;
        }
        QVariantMap stripMap(int recursion_depth, const QVariantMap &vmap) {
            if (recursion_depth > MAX_RECURSION)
                throw RecursionLimitReached(QString("Recursion limit of %1 reached when parsing schema").arg(MAX_RECURSION));
            QVariantMap ret;
            for (auto it = vmap.begin(); it != vmap.end(); ++it) {
                QString key ( stripKeyControlCodes(it.key()) );
                if (auto vtype = QMetaType::Type(it.value().type()); vtype == QMetaType::QVariantMap) {
                    // recursively strip
                    ret[key] = stripMap(recursion_depth+1, it.value().toMap());
                } else if (vtype == QMetaType::QVariantList) {
                    // recursively strip
                    ret[key] = stripList(recursion_depth+1, it.value().toList());
                } else if (vtype == QMetaType::QString) {
                    ret[key] = stripValueControlCodes(it.value().toString());
                } else
                    ret[key] = it.value();
            }
            return ret;
        }
    } // end anon namespace

    QVariantMap Schema::toStrippedMap() const {
        QVariantMap ret;
        if (!isValid())
            return ret;
        ret = stripMap(0, vmap);
        return ret;
    }

    void Schema::setFromString(const QString &json) {
        vmap = Util::Json::parseString(json, true).toMap();
        valid = true;
    }
    Schema & Schema::updateFromString(const QString &json) {
        const auto updates = Util::Json::parseString(json, true).toMap();
        for (auto it = updates.begin(); it != updates.end(); ++it) {
            QString key = it.key();
            // first strip key of all modifiers (if any)
            stripKeyControlCodes(key);
            if (!key.length())
                throw SchemaError(QString("Schema spec has a 0-length key! FIXME! Json = '%1'").arg(Util::Json::toString(updates, true)));
            // remove key with all permutations of "*key?" modifiers
            vmap.remove(key);  // remove bare 'key'
            key.insert(0, '*'); vmap.remove(key); // '*key'
            key += "?"; vmap.remove(key);   // '*key?'
            key = key.mid(1); vmap.remove(key); // 'key?'
            // now add the original key with whatever * ? modifier it had (if any)
            QVariant val ( it.value() );
            vmap[it.key()] = it.value();
        }
        valid = true;
        return *this;
    }

    namespace {
        QString spacePlusQuotedNameOrNothing(const QString &name) {
            return name.isEmpty() ? "" : QString(" \"") + name + "\"";
        }
        QString typeToName(QMetaType::Type t) {
            const char *ret = QMetaType::typeName(t);
            if (!ret) ret = "(Unknown)";
            return ret;
        }
        bool throwIfTypeMismatch(QMetaType::Type expected, QMetaType::Type testee, const QString & key) {
            if (expected != testee)
                throw SchemaMismatch(QString("Wrong type: expected %1 for \"%2\", instead got %3")
                                     .arg(typeToName(expected))
                                     .arg(key)
                                     .arg(typeToName(testee)));
            return false;
        }

        QVariantMap schemaMatchMap(int recursion_depth, const QVariantMap & sch, const QVariantMap & m, const QString &name = ""); ///< forward declaration
        QVariantList schemaMatchList(int recursion_depth, const QVariantList & sch, const QVariantList &m, const QString &name = ""); ///< fwd decl
        QVariant schemaInnerTest(int recursion_depth, QMetaType::Type stype, QMetaType::Type mtype, const QVariant &sval, const QVariant &mval, const QString &name) {
            if (stype == mtype) {
                if (stype == QMetaType::QVariantMap) {
                    // ok, we got a nested map. recursively test this map's schema
                    return schemaMatchMap(recursion_depth+1, sval.toMap(), mval.toMap(), name);
                } else if (stype == QMetaType::QVariantList) {
                    return schemaMatchList(recursion_depth+1, sval.toList(), mval.toList(), name);
                }
                return mval;// same type, just return the matchee-val
            } else if (stype == QMetaType::QVariantMap || stype == QMetaType::QVariantList) {
                // don't try to call canConvert() for List or Map
                throwIfTypeMismatch(stype, mtype, name);
            } else {
                // otherwise try and call canConvert() and if success, update returned map.
                if (/*stype != QMetaType::QString &&*/ mval.canConvert(stype)) {
                    QVariant ret(mval);
                    ret.convert(stype);
                    return ret;
                }
            }
            // stype != mtype
            throwIfTypeMismatch(stype, mtype, name); // will always throw here
            Q_UNREACHABLE();
            return QVariant(); // not reached
        }

        QVariantList schemaMatchList(int recursion_depth, const QVariantList & sch, const QVariantList &m, const QString &name) {
            if (recursion_depth > MAX_RECURSION)
                throw RecursionLimitReached(QString("Recursion limit of %1 reached when parsing schema").arg(MAX_RECURSION));
            if (sch.isEmpty())
                // empty list indicates we accept anything
                return m;
            QVariantList ret;
            auto & sval = sch.front(); // non-empty schema can only contain 1 item which is itself a schem spec (list, map, or simple item with a type)
            int reqLen = -1;
            const auto stype = QMetaType::Type(sval.type());
            if (stype == QMetaType::QString) {
                // check for special control code in lsst "=N", eg "=0" or "=3", etc to specify the required length of the list.
                if (const auto sstr = sval.toString(); sstr.startsWith("=")) {
                    bool ok;
                    if (int tmp = sstr.mid(1).toInt(&ok); ok && tmp >= 0) {
                        reqLen = tmp;
                    }
                }
            }
            if (reqLen > -1 && m.length() != reqLen) {
                throw SchemaMismatch(QString("Schema specified a list of length %1, but got a list of length %2 for %3")
                                     .arg(reqLen).arg(m.length()).arg(name));
            }
            for (auto & mval : m) {
                const auto mtype = QMetaType::Type(mval.type());
                ret.push_back( schemaInnerTest(recursion_depth, stype, mtype, sval, mval, name) );
            }
            // if we get here, every item in the list matches the template first item in the schema list.
            return ret;
        }
        QVariantMap schemaMatchMap(int recursion_depth, const QVariantMap & sch, const QVariantMap & m, const QString &name) {
            if (recursion_depth > MAX_RECURSION)
                throw RecursionLimitReached(QString("Recursion limit of %1 reached when parsing schema").arg(MAX_RECURSION));
            QVariantMap accepted;
            QSet<QString> requiredKeySet, acceptedKeySet;
            // iterate over schema keys
            for (auto it = sch.cbegin(); it != sch.cend(); ++it) {
                QString skey = it.key();  // skey is the stripped schema key (stripepd of * and ? symbols)
                const bool nullOk = skey.startsWith('*');
                if (nullOk) skey = skey.mid(1);
                const bool requiredKey = !skey.endsWith('?');
                if (!requiredKey) {
                    // optional key, strip the '?'
                    skey = skey.left(skey.length()-1);
                } else {
                    // required key
                    requiredKeySet.insert(skey);
                }
                // see if key is in target test map
                if (auto it2 = m.find(skey); it2 == m.end()) {
                    if (!requiredKey)
                        // continue with loop, ignore fact that a non-required key is issing
                        continue;
                    // key missing, indicate this
                    throw SchemaMismatch(QString("Dict%1 missing required key \"%2\"")
                                         .arg( spacePlusQuotedNameOrNothing(name) )
                                         .arg(skey));
                } else {
                    acceptedKeySet.insert(skey);
                    accepted[skey] = it2.value(); // copy value into accepted map
                    const QVariant & sval = it.value(), & mval = it2.value();
                    // next, extract the type of each QVariant. stype and mtype must match only if stype is not a "*" string.
                    if (auto stype = QMetaType::Type(sval.type()), mtype = QMetaType::Type(mval.type());
                            nullOk && mtype == QMetaType::Nullptr) {
                        // accept null
                        continue;
                    } else if (stype == QMetaType::QString) {
                        QString ss = sval.toString();
                        if (ss == "*")
                            continue; // "*" means accept anything, don't test mtype
                        else if (throwIfTypeMismatch(stype, mtype, skey)) {} /// <-- require both QString after this point
                        // at this point we are sure stype and mtype are both QString
                        else if (ss.endsWith("!")) {
                            if (auto expectedString = ss.left(ss.length()-1); expectedString == mval.toString()) {
                                // matches "expectedString!" == "expectedString"
                                continue; // accept!
                            } else {
                                // mistmatch "expectedString!" != "whateverWeGot"
                                throw SchemaMismatch(QString("Dict%1 expected string for key \"%2\" is \"%3\"; instead got \"%4\"")
                                                     .arg( spacePlusQuotedNameOrNothing(name) )
                                                     .arg(skey).arg(expectedString).arg(mval.toString()));
                            }
                        }
                        // ok, not a "!string" in schema. Accept any string.
                        continue;
                    } else {
                        accepted[skey] = schemaInnerTest(recursion_depth, stype, mtype, sval, mval, skey);
                        // at this point either we throw if no match or got an accepted key.
                    }
                }
            } // end for

            // forbid extra/unknown keys
            if (m.size() != acceptedKeySet.size()) { // initial filter -- just check sizes, as a performance optimization since the below needs to build a keySet for error display.
                // ok, size of accepted set != input map size -- figure out if keys are missing
                if (auto extraKeys(m.keys().toSet() - acceptedKeySet) ; !extraKeys.isEmpty()) {
                    throw SchemaMismatch(QString("Dict%1 contains extra unexpected key(s): (\"%2\"%3)")
                                         .arg( spacePlusQuotedNameOrNothing(name) )
                                         .arg(extraKeys.toList().mid(0, 5).join("\", \""))
                                         .arg(extraKeys.count() > 5 ? ", ..." : ""));
                }
            }

            // if we get here, everything was accepted and converted
            return accepted;
        }
    } // end anonymous namespace

    QVariantMap Schema::parseAndThrowIfNotMatch(const QString &json) const
    {
        if (!isValid())
            throw SchemaError("Invalid schema");
        QVariantMap data(Util::Json::parseString(json, true).toMap()); /// throws on json error
        return schemaMatchMap(0, vmap, data); /// recursively examine schema. throws on error/mismatch, returns a modified map of accepted keys
    }
    QVariantMap Schema::parseAndThrowIfNotMatch(const QVariantMap &data) const
    {
        if (!isValid())
            throw SchemaError("Invalid schema");
        return schemaMatchMap(0, vmap, data); /// recursively examine schema. throws on error/mismatch, returns a modified map of accepted keys
    }
    QVariantMap Schema::match(const QString &json, QString *errorString) const
    {
        QVariantMap ret;
        try {
            ret = parseAndThrowIfNotMatch(json);
            if (errorString) *errorString = QString();
        } catch (const std::exception &e) { // we catch this very general exception in case we get some bad_alloc or something due to a json super recursion.
            if (errorString) *errorString = e.what();
        }
        return ret;
    }
    QVariantMap Schema::match(const QVariantMap &data, QString *errorString) const
    {
        QVariantMap ret;
        try {
            ret = parseAndThrowIfNotMatch(data);
            if (errorString) *errorString = QString();
        } catch (const std::exception &e) { // we catch this very general exception in case we get some bad_alloc or something due to a json super recursion.
            if (errorString) *errorString = e.what();
        }
        return ret;
    }


    /* static */
    void Schema::test()
    {
        auto tryCatchPrint = [](const Schema &s, const QString &json) {
            try {
                Debug() << "Parsing: " << json << " ...";
                auto m = s.parseAndThrowIfNotMatch(json);
                Debug() << "Parsed ok to: " << Util::Json::toString(m, true);
            } catch (const Exception &e) {
                Error() << "Exception: " << e.what();
            }
        };
        Method m("1"), m2("2"), m3 = { "1", "{\"2\":3}" }, m4;
        m = m2 = m3;
        QVariant v = QVariant("1.25");
        Debug() << "Can convert? " << v.canConvert<qint64>() << " converted: " << v.value<qint64>();
        Debug() << "Can convert? " << v.canConvert<double>() << " converted: " << v.value<double>();
        v = QVariant("10");
        Debug() << "Can convert? " << v.canConvert<qint64>() << " converted: " << v.value<qint64>();
        Debug() << "Can convert? " << v.canConvert<double>() << " converted: " << v.value<double>();
        QString err1 = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32700, \"message\": \"invalid JSON\"}, \"id\": null, \"method\" : null }";
        tryCatchPrint(schemaError, err1);
        QString test = "{\"jsonrpc\": \"2.1\", \"error\": {\"code\": -32700, \"message\": \"invalid JSON\"}, \"id\": null}";
        tryCatchPrint(schemaError, test);
        test = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32700, \"message\": \"invalid JSON\"}, \"id\": null}";
        tryCatchPrint(schemaError, test);
        test = "{\"jsonrpc\": \"2.0\", \"result\": [\"ElectronX 1.10.1\", \"1.4\"], \"id\": 1}";
        tryCatchPrint(schemaResult + "{ \"result\": [\"anystring\"] }", test);
        test = "{\"jsonrpc\": \"2.0\", \"result\": [\"ElectronX 1.10.1\", \"1.4\", 123], \"id\": 1}";
        tryCatchPrint(schemaResult + "{ \"result\": [\"anystring\"]  }", test);
        QString recurs = "{\"jsonrpc\": \"2.0\", \"result\": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]], \"id\": 1}";
        tryCatchPrint(schemaResult + "{ \"result\": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]  }", recurs);
        tryCatchPrint(schemaResult + "{ \"result\": [[[{ \"hi\" : [[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]}]]]  }", recurs);
        test = "{\"jsonrpc\": \"2.0\", \"result\": [\"ElectronX 1.10.1\", \"1.4\", 123], \"id\": 1, \"extraKey1\" : 1, \"anotherExtra\" : 2, \"extraKey2\" : 3, \"anotherExtra2\" : 3, \"extraKey4\" : 4, \"anotherExtra3\" : 5}";
        tryCatchPrint(schemaResult + "{ \"result\": []  }", test);
        test = "{\"jsonrpc\": \"2.0\", \"result\": [\"ElectronX 1.10.1\", \"1.4\", 123], \"id\": 1, \"extraKey1\" : 1}";
        tryCatchPrint(schemaResult + "{ \"result\": []  }", test);

    }

    /* static */
    Message Message::fromJsonData(const QVariantMap &jsonData, const Schema &schema)
    {
        auto map = schema.parseAndThrowIfNotMatch(jsonData);
        Message ret;
        ret.jsonData = map;
        ret.schema = schema;
        ret.jsonRpcVersion = map.value("jsonrpc").toString();
        if (auto var = map.value("id", QVariant()); !var.isNull()) {
            bool ok;
            ret.id = var.toLongLong(&ok);
            if (!ok || ret.id < 0) ret.id = NO_ID;
        }
        if (auto var = map.value("method", QVariant()); !var.isNull() && var.canConvert<QString>()) {
            ret.method = var.toString();
        }
        if (auto var = map.value("error", QVariant()); !var.isNull() && var.canConvert<QVariantMap>()) {
            auto emap = var.toMap();
            ret.errorCode = emap.value("code", 0).toInt();
            ret.errorMessage = emap.value("message", "").toString();
        }
        if (auto var = map.value("params", QVariant()); !var.isNull() && var.canConvert<QVariantList>()) {
            ret.data = var.toList();
        } else {
            ret.data = map.value("result");
        }
        return ret;
    }

    /* static */
    Message Message::makeError(int code, const QString &message, qint64 id)
    {
        Message ret;
        ret.schema = schemaError;
        auto map = ret.schema.toStrippedMap();
        ret.errorCode = code;
        ret.errorMessage = message;
        ret.id = id;
        if (id == NO_ID) map["id"] = QVariant(); // null
        else map["id"] = id;
        map.remove("method");
        auto errMap = map["error"].toMap();
        errMap["code"] = code;
        errMap["message"] = message;
        map["error"] = errMap;
        ret.jsonData = map;
        ret.jsonRpcVersion = map.value("jsonrpc").toString();
        return ret;
    }

    /// uses provided schema -- will not throw exception
    /*static*/
    Message Message::makeResult(const QVariant & result, const Schema &schema, qint64 reqId)
    {
        Message ret;
        ret.schema = schema;
        auto map = ret.schema.toStrippedMap();
        ret.data = result;
        map["result"] = result;
        if (reqId == NO_ID) map["id"] = QVariant(); // null
        else map["id"] = reqId;
        ret.jsonData = map;
        ret.jsonRpcVersion = map.value("jsonrpc").toString();
        return ret;
    }

    /* static */
    Message Message::makeMethodRequest(qint64 id, const QString &methodName, const QVariantList &params, const Schema &sch)
    {
        Message ret;
        ret.schema = sch;
        auto map = sch.toStrippedMap();
        map["id"] = ret.id = id;
        map["method"] = ret.method = methodName; /// schema may have already set this but we set it again
        ret.data = params;
        map["params"] = params;
        ret.jsonRpcVersion = map.value("jsonrpc").toString();
//#ifdef QT_DEBUG
//        QString err;
//        ret.jsonData = ret.schema.match(map, &err);
//        if (ret.jsonData.isEmpty()) {
//            Error() << __FUNCTION__ << " schema verify failure: " << err << "; FIXME!";
//        }
//#else
        ret.jsonData = map;
//#endif
        return ret;
    }

    Connection::Connection(const MethodMap & methods, qint64 id, QObject *parent, qint64 maxBuffer)
        : AbstractConnection(id, parent, maxBuffer), methods(methods)
    {
        static bool initted_meta = false;
        if (!initted_meta) {
            // finish registering RPC::Message metatype so that signals/slots work. This needs to only happen
            // once in main thread at app init.
            qRegisterMetaType<RPC::Message>();
            initted_meta = true;
        }
    }

    Connection::~Connection() {}

    void Connection::on_connected()
    {
        AbstractConnection::on_connected();
        // connection will be auto-disconnected on socket disconnect
        connectedConns.push_back(connect(this, &Connection::sendRequest, this, &Connection::_sendRequest));
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

    void Connection::_sendRequest(qint64 reqid, const QString &method, const QVariantList & params)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        auto mptr = methods.value(method);
        if (!mptr) {
            Error() << __FUNCTION__ << " method: " << method << "; Unknown method! FIXME!";
            return;
        }
        QString json = Message::makeMethodRequest(reqid, method, params, mptr->outSchema).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate request JSON! FIXME!";
            return;
        }
        while (idMethodMap.size() > 20000) {  // prevent memory leaks in case of misbehaving server
            idMethodMap.erase(idMethodMap.begin());
        }
        idMethodMap[reqid] = method; // remember method sent out to associate it back.

        auto data = json.toUtf8();
        Debug() << "Sending json: " << data;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */);
    }
    void Connection::_sendError(bool disc, int code, const QString &msg, qint64 reqId)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << "; Not connected!";
            return;
        }
        QString json = Message::makeError(code, msg, reqId).toJsonString();
        auto data = json.toUtf8();
        Debug() << "Sending json: " << data;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */);
        if (disc) {
            do_disconnect(true); // graceful disconnect
        }
    }
    void Connection::_sendResult(qint64 reqid, const QString &method, const QVariant & result)
    {
        if (status != Connected || !socket) {
            Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
            return;
        }
        auto mptr = methods.value(method);
        if (!mptr) {
            Error() << __FUNCTION__ << " method: " << method << "; Unknown method! FIXME!";
            return;
        }
        QString json = Message::makeResult(result, mptr->resultSchema, reqid).toJsonString();
        if (json.isEmpty()) {
            Error() << __FUNCTION__ << " method: " << method << "; Unable to generate result JSON! FIXME!";
            return;
        }
        auto data = json.toUtf8();
        Debug() << "Sending result json: " << data;
        // below send() ends up calling do_write immediately (which is connected to send)
        emit send( data + "\n" /* "\n" <-- is crucial! (Protocol is linefeed-based) */);
    }

    void Connection::on_readyRead()
    {
        Debug() << __FUNCTION__;
        qint64 lastMsgId = NO_ID;
        try {
            while (socket->canReadLine()) {
                lastMsgId = NO_ID;
                auto data = socket->readLine();
                nReceived += data.length();
                auto line = data.trimmed();
                Debug() << "Got: " << line;
                const QVariantMap jsonData( Util::Json::parseString(line, true).toMap() ); // may throw

                Message message;
                if (!jsonData.value("error").isNull()) {
                    // error message
                    message = Message::fromJsonData(jsonData, schemaError); // may throw
                    emit gotErrorMessage(id, message);
                } else {
                    // either a 'id','result' or a 'method','params' message
                    bool isResult = true;
                    if (!jsonData.value("method").isNull()) {
                        // 'method','params' message
                        message = Message::fromJsonData(jsonData, schemaMethod); // may throw
                        lastMsgId = message.id;
                        isResult = false;
                    } else {
                        // 'id','result' message -- find originating method in map -- if not found will throw.
                        message = Message::fromJsonData(jsonData, schemaResult); // may throw
                        QString meth = message.id > 0 ? idMethodMap.take(message.id) : message.method;
                        if (meth.isEmpty()) {
                            throw BadPeer(QString("Unexpected/unknown message id (%1) in server reply").arg(message.id));
                        }
                        message.method = meth;
                    }
                    auto mptr = methods.value(message.method);
                    if (!mptr) {
                        throw BadPeer(QString("Could not find method %1").arg(message.method));
                    }
                    const Schema & schema = isResult ? mptr->resultSchema : mptr->inSchema;
                    // re-verify incoming message against more method-specific schema again
                    message = Message::fromJsonData(jsonData, schema);
                    message.method = mptr->method; // write to the method var again in case it was a result with no method name in the json
                    emit gotMessage(id, message);
                }
                lastGood = Util::getTime(); // update "lastGood" as this is used to determine if stale or not.
                //Debug() << "Re-parsed message: " << message.toJsonString();
            }
            if (socket->bytesAvailable() > MAX_BUFFER) {
                // bad server.. sending us garbage data not containing newlines. Kill connection.
                throw BadPeerAbort(QString("Peer has sent us more than %1 bytes without a newline! Bad peer?").arg(MAX_BUFFER));
            }
        } catch (const BadPeerAbort & e) {
            Error() << prettyName() << " fatal error: " << e.what();
            do_disconnect();
            status = Bad;
        } catch (const std::exception &e) {
            bool doDisconnect = errorPolicy & ErrorPolicyDisconnect;
            if (errorPolicy & ErrorPolicySendErrorMessage) {
                emit sendError(doDisconnect, -123, QString(e.what()).left(80), lastMsgId);
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
