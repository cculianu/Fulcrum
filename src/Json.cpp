//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
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
// Portions of the below code are adapted from Bitcoin Cash Node's custom
// "UniValue" library, and they have the following copyrights and license:
// Copyright 2014 BitPay Inc.
// Copyright 2015 Bitcoin Core Developers
// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.
//
#include "Json.h"
#include "Json_Parser.h"
#include "Util.h"

#include <QFile>
#include <QMetaType>
#include <QVariant>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <limits>
#include <type_traits>

namespace {
    // JSON escapes -- used in jsonEscape()
    extern const std::array<const char *, 256> escapes;

    // Opaque type used for writing. This can be further optimized later.
    struct Writer {
        QByteArray & buf; // this is a reference for RVO to always work in write() below
        void put(char c) { buf.push_back(c); }
        void put(char c, size_t nFill) { buf.append(int(nFill), c); }
        void write(const char *s, size_t len) { buf.append(s, len); }
        void write(const QByteArray &ba) { buf.append(ba); }
        Writer & operator<<(const char *s) { buf.append(s); return *this; }
        Writer & operator<<(const QString &s) { buf.append(s.toUtf8()); return *this; }
        Writer & operator<<(const QByteArray &ba) { buf.append(ba); return *this; }

        template<typename Num>
        bool writeIntOrFloat(Num num) {
            constexpr int bufSize = std::is_integral<Num>::value ? 32 : 64; // use 32 byte buffer for ints, 64 for double
            constexpr auto fmt =
                    std::is_same<Num, double>::value
                    ? "%1.16g"
                    : (std::is_same<Num, int64_t>::value
                       ? "%" PRId64
                       : (std::is_same<Num, uint64_t>::value
                          ? "%" PRIu64
                            // this is here to enforce uint64_t, int64_t or double (if evaluated will fail at compile-time)
                          : throw std::runtime_error("Unexpected type")));
            if (std::is_floating_point<Num>::value) {
                // ensure not NaN or inf, which are not representable by the JSON Number type
                if (!std::isfinite(num))
                    return false;
            }
            std::array<char, bufSize> tmp;
            int n = std::snprintf(tmp.data(), size_t(bufSize), fmt, num); // C++11 snprintf always NUL terminates
            if (n <= 0 || n >= bufSize) // should never happen
                return false;
            write(tmp.data(), size_t(n));
            return true;
        }

        void jsonEscape(const QByteArray & inS) {
            for (const auto ch : inS) {
                const char * const escStr = escapes[uint8_t(ch)];

                if (escStr)
                    *this << escStr;
                else
                    put(ch);
            }
        }

        void indentStr(unsigned prettyIndent, unsigned indentLevel) { put(' ', prettyIndent * indentLevel); }

        template <typename List>
        void writeArray(const List &vl, unsigned prettyIndent, unsigned indentLevel);
        template <typename Map>
        void writeObject(const Map &vm, unsigned prettyIndent, unsigned indentLevel);
        void writeVariant(const QVariant &v, unsigned prettyIndent, unsigned indentLevel);
        void writeString(const QByteArray &ba) { put('"'); jsonEscape(ba); put('"'); };
        void writeString(const QString &qs) { writeString(qs.toUtf8()); }
    };


    const QByteArray NullLiteral = QByteArrayLiteral("null");
    const QByteArray TrueLiteral = QByteArrayLiteral("true");
    const QByteArray FalseLiteral = QByteArrayLiteral("false");


    void Writer::writeVariant(const QVariant &v, unsigned prettyIndent, unsigned indentLevel) noexcept(false)
    {
        const auto typ = QMetaType::Type(v.type());

        if (v.isNull()) {
            // Note that QString.isNull() in the QVariant can also satisfy this, so we must
            // special-case this: null and empty QStrings all end up as "" uniformly, whereas empty QByteArray will be
            // null. We must do this here to preserve compatibility with how we wrote this application initially
            // to follow that assumption, because Qt 5.14 and before always did it that way.
            if (typ == QMetaType::QString)
                writeString(QByteArrayLiteral("")); // writes: ""  (two quotes)
            else
                write(NullLiteral); // write literal `null`
            return;
        }

        if (Q_UNLIKELY(!v.isValid())) {
            throw Json::Error("Variant is not valid");
        }

        switch(typ) {
        case QMetaType::QByteArray: {
            const auto ba = v.toByteArray();
            if (ba.isEmpty())
                write(NullLiteral); // empty QByteArray is treated specially in this codebase as `null`
            else
                writeString(ba);
            break;
        }
        case QMetaType::QString:
            writeString(v.toString());
            break;
        case QMetaType::QStringList: // unlikely
            writeArray(v.toStringList(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::QByteArrayList: // uncommon
            writeArray(v.value<QByteArrayList>(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::QVariantList: // common case for arrays
            writeArray(v.toList(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::QVariantMap: // common case for maps
            writeObject(v.toMap(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::QVariantHash: // uncommon
            writeObject(v.toHash(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::Bool:
            write(v.toBool() ? TrueLiteral : FalseLiteral);
            break;
        case QMetaType::Int:
        case QMetaType::Long:
        case QMetaType::LongLong: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(int64_t(v.toLongLong(&ok1)));
            if (Q_UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize int64 for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        case QMetaType::UInt:
        case QMetaType::ULong:
        case QMetaType::ULongLong: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(uint64_t(v.toULongLong(&ok1)));
            if (Q_UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize uint64 for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        case QMetaType::Double:
        case QMetaType::Float: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(v.toDouble(&ok1));
            if (Q_UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize double for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        default:
            throw Json::Error(QString("Unsupported type %1 (%2) for '%3'").arg(int(typ)).arg(QMetaType::typeName(typ)).arg(v.toString()));
        }
    }

    template<typename List>
    void Writer::writeArray(const List &v, unsigned prettyIndent, unsigned indentLevel)
    {
        put('[');
        if (prettyIndent)
            put('\n');

        for (int i = 0, nValues = v.size(); i < nValues; ++i) {
            if (prettyIndent)
                indentStr(prettyIndent, indentLevel);
            if constexpr (std::is_same_v<QString, typename List::value_type>) {
                // Minor optimization to avoid creating a temporary QVariant if we are writing a QStringList.
                writeString(v[i]);
            } else {
                // The below static_assert catches usages that lead to extra implicit temporaries that we don't want.
                // We do however allow QByteArray through to be implicitly cast to QVariant so it can end up with its
                // special "" -> null treatment in writeVariant() below.
                static_assert (std::is_same_v<QVariant, typename List::value_type>
                               || std::is_same_v<QByteArray, typename List::value_type>);
                writeVariant(v[i], prettyIndent, indentLevel + 1);
            }
            if (i != (nValues - 1)) {
                put(',');
            }
            if (prettyIndent)
                put('\n');
        }

        if (prettyIndent)
            indentStr(prettyIndent, indentLevel - 1);
        put(']');
    }

    template<typename Map>
    void Writer::writeObject(const Map &v, unsigned prettyIndent, unsigned indentLevel)
    {
        static_assert(std::is_same_v<QVariantMap, Map> || std::is_same_v<QVariantHash, Map>); // enforce supported types
        put('{');
        if (prettyIndent)
            put('\n');

        int i = 0, nEntries = v.size();
        for (auto it = v.begin(); i < nEntries; ++i, ++it) {
            if (prettyIndent)
                indentStr(prettyIndent, indentLevel);
            auto &key = it.key();
            auto &value = it.value();
            put('"'); jsonEscape(key.toUtf8()); write("\":", 2);
            if (prettyIndent)
                put(' ');
            writeVariant(value, prettyIndent, indentLevel + 1);
            if (i != (nEntries - 1))
                put(',');
            if (prettyIndent)
                put('\n');
        }

        if (prettyIndent)
            indentStr(prettyIndent, indentLevel - 1);
        put('}');
    }

    QByteArray serialize(const QVariant &v, unsigned prettyIndent, unsigned indentLevel = 0) noexcept(false)
    {
        QByteArray ba; // we do it this way for RVO to work on all compilers
        Writer writer{ba};
        ba.reserve(1024);
        writer.writeVariant(v, prettyIndent, indentLevel); // this may throw
        return ba;
    }

}

namespace Json {
    QVariant parseUtf8(const QByteArray &ba, ParseOption opt)
    {
        QVariant ret;
        if (!detail::parse(ret, ba))
            throw ParseError(QString("Failed to parse Json from string: %1%2").arg(QString(ba.left(80)))
                             .arg(ba.size() > 80 ? "..." : ""));
        if (opt == ParseOption::RequireObject && QMetaType::Type(ret.type()) != QMetaType::QVariantMap)
            throw Error("Json Error: expected object");
        if (opt == ParseOption::RequireArray && QMetaType::Type(ret.type()) != QMetaType::QVariantList)
            throw Error("Json Error: expected array");
        return ret;
    }
    QVariant parseFile(const QString &file, ParseOption opt) {
        QFile f(file);
        if (!f.open(QFile::ReadOnly))
            throw Error(QString("Could not open file: %1").arg(file));
        const QByteArray ba{f.readAll()};
        return parseUtf8(ba, opt);
    }
    QByteArray toUtf8(const QVariant &v, bool compact, SerOption opt) {
        if (opt == SerOption::NoBareNull && v.isNull())
            throw Error("Attempted to serialize a null variant, but serialization option is NoBareNull");
        return serialize(v, compact ? 0 : 4); // may throw on low-level error or if !v.isValid()
    }

} // end namespace Json

namespace {
    const std::array<const char *, 256> escapes = {{
        "\\u0000",
        "\\u0001",
        "\\u0002",
        "\\u0003",
        "\\u0004",
        "\\u0005",
        "\\u0006",
        "\\u0007",
        "\\b",
        "\\t",
        "\\n",
        "\\u000b",
        "\\f",
        "\\r",
        "\\u000e",
        "\\u000f",
        "\\u0010",
        "\\u0011",
        "\\u0012",
        "\\u0013",
        "\\u0014",
        "\\u0015",
        "\\u0016",
        "\\u0017",
        "\\u0018",
        "\\u0019",
        "\\u001a",
        "\\u001b",
        "\\u001c",
        "\\u001d",
        "\\u001e",
        "\\u001f",
        nullptr,
        nullptr,
        "\\\"",
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        "\\\\",
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        "\\u007f",
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
    }};
} // end namespace


#ifdef ENABLE_TESTS
#include "App.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>

#include <cstdlib>
#include <cstdint>

namespace Json {
namespace {
    void bench() {
        const char * const dir = std::getenv("DATADIR");
        if (!dir) {
            Warning() << "Json benchmark requires the DATADIR environment variable, which should be a directory on the "
                         "filesystem containing *.json files to use for the benchmark.";
            throw Exception("No DATADIR specified");
        }
        QDir dataDir(dir);
        if (!dataDir.exists()) throw BadArgs(QString("DATADIR '%1' does not exist").arg(dir));
        auto files = dataDir.entryList({{"*.json"}}, QDir::Filter::Files);
        if (files.isEmpty()) throw BadArgs(QString("DATADIR '%1' does not have any *.json files").arg(dir));
        std::vector<QByteArray> fileData;
        std::size_t total = 0;
        Log() << "Reading " << files.size() << " *.json files from DATADIR=" << dir << " ...";

        for (auto & fn : files) {
            QFile f(dataDir.path() + QDir::separator() + fn);
            if (!f.open(QFile::ReadOnly|QFile::Text))
                throw Exception(QString("Cannot open %1").arg(f.fileName()));
            fileData.push_back(f.readAll());
            total += fileData.back().size();
        }
        Log() << "Read " << total << " bytes total";
        std::vector<QVariant> parsed;
        parsed.reserve(fileData.size());
        int iters = 10;
        {
            auto itenv = std::getenv("ITERS");
            if (itenv) {
                bool ok;
                iters = QString(itenv).toInt(&ok);
                if (!ok || iters <= 0)
                    throw BadArgs("Expected ITERS= to be a positive integer");
            }
        }
        Log() << "---";
        Log() << "Benching custom Json lib parse: Iterating " << iters << " times ...";
        double t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & ba : fileData) {
                auto var = parseUtf8(ba, ParseOption::AcceptAnyValue);
                if (var.isNull()) throw Exception("Parse result is null");
                if (parsed.size() != fileData.size())
                    parsed.push_back(var); // save parsed data
            }
        }
        double tf = Util::getTimeSecs();
        Log() << "Custom lib parse - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";
        parsed.clear();
        parsed.reserve(fileData.size());

        Log() << "---";
        Log() << "Benching Qt Json parse: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & ba : fileData) {
                QJsonParseError err;
                auto d = QJsonDocument::fromJson(ba, &err);
                if (d.isNull())
                    throw Exception(QString("Could not parse: %1").arg(err.errorString()));
                auto var = d.toVariant();
                if (var.isNull()) throw Exception("Parse result is null");
                if (parsed.size() != fileData.size())
                    parsed.push_back(var); // save parsed data
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Qt Json parse - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        Log() << "---";
        Log() << "Benching custom Json lib serialize: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & var : parsed) {
                auto json = serialize(var, 4); // throw on error
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Custom lib serialize - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        Log() << "---";
        Log() << "Benching Qt lib serialize: Iterating " << iters << " times ...";
        t0 = Util::getTimeSecs();
        for (int i = 0; i < iters; ++i) {
            for (const auto & var : parsed) {
                auto d = QJsonDocument::fromVariant(var);
                auto json = d.toJson(QJsonDocument::JsonFormat::Indented);
                if (json.isEmpty()) throw Exception("Serializaiton error");
            }
        }
        tf = Util::getTimeSecs();
        Log() << "Qt lib serialize - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";

        Log() << "---";
    }

    void test()
    {
        // basic tests
        {
            const auto expect1 = "[\"astring\",\"anotherstring\",\"laststring\",null]";
            const auto expect2 = "[\"astringl1\",\"anotherstringl2\",\"laststringl3\",\"\"]";
            const auto expect3 = "{\"7 item list\":[1,true,false,1.4e-07,null,{},[-777777.293678102,null,1.000000000000001,"
                                 "-999999999999999999]],\"a bytearray\":\"bytearray\",\"a null\":null,"
                                 "\"a null bytearray\":null,\"a null string\":\"\",\"a string\":\"hello\","
                                 "\"an empty bytearray\":null,\"an empty string\":\"\",\"another empty bytearray\":"
                                 "null,\"empty balist\":[],\"empty strlist\":[],\"empty vlist\":[],\"nested map key\":"
                                 "3.140000001,\"u64_max\":18446744073709551615,\"z_i64_min\":-9223372036854775808}";
            QByteArray json;
            QByteArrayList bal = {{ "astring", "anotherstring", "laststring", QByteArray{} }};
            QVariant v;
            v.setValue(bal);
            Log() << "QByteArrayList -> JSON: " << (json=toUtf8(v, true, SerOption::BareNullOk));
            if (json != expect1) throw Exception(QString("Json does not match, excpected: %1").arg(expect1));
            QStringList sl = {{ "astringl1", "anotherstringl2", "laststringl3", QString{} }};
            v.setValue(sl);
            Log() << "QStringList -> JSON: " << (json=toUtf8(v, true, SerOption::BareNullOk));
            if (json != expect2) throw Exception(QString("Json does not match, excpected: %1").arg(expect2));
            Log() << "Parse \"1.01000\": " << (json=toUtf8(parseUtf8("1.01000", ParseOption::AcceptAnyValue), true, SerOption::BareNullOk));
            if (json != "1.01") throw Exception(QString("Json does not match, excpected: %1").arg("1.01"));
            QVariantHash h;
            QByteArray empty; empty.resize(10); empty.resize(0);
            h["key1"] = 1.2345;
            h["another key"] = sl;
            h["mapkey"] = QVariantMap{{
               {"nested map key", 3.140000001},
               {"a null", QVariant{}},
               {"a null bytearray", QByteArray{}},
               {"a null string", QString{}},
               {"an empty string", QString{""}},
               {"an empty bytearray", QByteArray{""}},
               {"another empty bytearray", empty},
               {"a string", QString{"hello"}},
               {"a bytearray", QByteArray{"bytearray"}},
               {"empty vlist", QVariantList{}},
               {"empty strlist", QStringList{}},
               {"empty balist", QVariant::fromValue(QByteArrayList{})},
               {"7 item list", QVariantList{{
                    1,true,false,14e-8,QVariant{}, QVariantMap{}, QVariantList{{-777777.293678102, QVariant{},
                    1.000000000000001, qlonglong(-999999999999999999)}}}},
               },
               {"u64_max", qulonglong(18446744073709551615ULL)},
               {"z_i64_min", qlonglong(0x8000000000000000LL)},
            }};
            Log() << "QVariantHash -> JSON: " << toUtf8(h, true, SerOption::BareNullOk);
            // we can't do the top-level hash since that has random order based on hash seed.. so we do this
            json = toUtf8(h, false /* !compact */, SerOption::BareNullOk);
            auto hh = parseUtf8(json, ParseOption::RequireObject).toMap();
            json = toUtf8(hh["mapkey"], true, SerOption::BareNullOk);
            if (json != expect3) throw Exception(QString("Json \"mapkey\" does not match\nexcpected:\n%1\n\ngot:\n%2").arg(expect3).arg(QString(json)));
            Log() << "Basic tests: passed";
        }
        // /end basic tests
        const char *dir = std::getenv("DATADIR");
        if (!dir) dir = "test/json";
        QDir dataDir(dir);
        if (!dataDir.exists()) throw BadArgs(QString("DATADIR '%1' does not exist").arg(dir));
        struct TFile {
            QString path;
            bool wantsFail{}, wantsRound{};
        };
        std::list<TFile> files;
        for (auto & file : dataDir.entryList({{"*.json"}}, QDir::Filter::Files)) {
            TFile t;
            if (file.startsWith("pass"))
                t.wantsFail = false;
            else if (file.startsWith("fail"))
                t.wantsFail = true;
            else if (file.startsWith("round"))
                t.wantsFail = false, t.wantsRound = true;
            else
                // skip unrelated json file
                continue;
            t.path = dataDir.path() + QDir::separator() + file;
            files.push_back(std::move(t));
        }
        if (files.empty()) throw BadArgs(QString("DATADIR '%1' does not have any [pass/fail/round]*.json files").arg(dir));
        Log() << "Found " << files.size() << " json test files, running extended tests ...";
        const auto runTest = [](const TFile &t) {
            QFile f(t.path);
            auto baseName = QFileInfo(t.path).baseName();
            if (!f.open(QFile::ReadOnly|QFile::Text))
                throw Exception(QString("Cannot open %1").arg(f.fileName()));
            const QByteArray json = f.readAll();
            QVariant var;
            bool didFail = false;
            try {
                var = parseUtf8(json, ParseOption::AcceptAnyValue);
            } catch (...) {
                if (!t.wantsFail)
                    throw;
                didFail = true;
            }
            if (t.wantsFail && !didFail)
                throw Exception(QString("Expected to fail test: %1 (Json: %2)").arg(baseName).arg(QString(toUtf8(var, true, SerOption::BareNullOk))));
            if (t.wantsRound) {
                if (auto json2 = toUtf8(var, true, SerOption::BareNullOk); json.trimmed() != json2.trimmed())
                    throw Exception(QString("Round-trip deser/ser failed for: %1\n\nExpected:\n%2\nHex: %3\n\nGot:\n%4\nHex: %5").arg(baseName)
                                    .arg(QString(json)).arg(QString(json.toHex()))
                                    .arg(QString(json2)).arg(QString(json2.toHex())));
            }
            Log() << baseName << ": passed";
        };
        for (const auto & t : files)
            runTest(t);
    }

    static const auto bench_ = App::registerBench("json", &bench);
    static const auto test_  = App::registerTest("json", &test);
}
}
#endif
