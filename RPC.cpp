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
    ///         "*" : for a value means the value can be anything and any type (number, float, list, dict, null), but must be present.
    ///               anything else is taken as a type spec, so only the type of the thing must match.
    ///     A nested dict is analyzed for keys and keys must be present. An empty dict just means any dict. An
    ///     empty list just means any list.

    Schema const schemaBase = "{ \"jsonrpc\": \"2.0!\" }";
    Schema const schemaError = schemaBase + "{ \"error\" : { \"code\" : 1, \"message\" : \"astring\" }, \"*id\" : 1, \"method?\" : \"anystring\"  }";
    Schema const schemaResult = schemaBase + " { \"id\" : 1, \"*result\" : \"*\" }";
    Schema const schemaMethod = schemaBase + " { \"method\": \"astring\", \"params\" : [], \"*id?\" : 1 }";

    QString Schema::toString() const {
        if (!isValid()) return QString();
        return Util::Json::toString(vmap, true);
    }

    QVariantMap Schema::toMap() const {
        if (!isValid()) return QVariantMap();
        return vmap;
    }

    static void stripKeyControlCodes(QString &key) {
        if (key.startsWith("*")) key = key.mid(1);
        if (key.endsWith("?")) key = key.left(key.length()-1);
    }

    QVariantMap Schema::toStrippedMap() const {
        QVariantMap ret;
        if (!isValid())
            return ret;
        for (auto it = vmap.begin(); it != vmap.end(); ++it) {
            QString key = it.key();
            stripKeyControlCodes(key);
            if (QMetaType::Type(it.value().type()) == QMetaType::QVariantMap)
                // recursively strip
                ret[key] = Schema(Util::Json::toString(it.value(), true)).toStrippedMap();
            else
                ret[key] = it.value();
        }
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

        /// Note since the schema controls how far we recurse, this constant and check is likely unnecessary but we
        /// add it here as a defensive programming technique. At most we expect to recurse 2-3 deep during normal use.
        static constexpr int MAX_RECURSION = 10;

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
            for (auto & mval : m) {
                auto stype = QMetaType::Type(sval.type()), mtype = QMetaType::Type(mval.type());
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
                    const QVariant & sval = it.value(), mval = it2.value();
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
        QVariantMap data(Util::Json::parseString(json, true).toMap()); /// throws on json error
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
        Method m("1"), m2("2"), m3 = { "1", "{\"2\":3}" };
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
}
