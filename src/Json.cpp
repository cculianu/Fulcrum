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

        void writeArray(const QVariantList &v, unsigned prettyIndent, unsigned indentLevel);
        void writeObject(const QVariantMap &v, unsigned prettyIndent, unsigned indentLevel);
        void writeVariant(const QVariant &v, unsigned prettyIndent, unsigned indentLevel);
        void writeString(const QByteArray &ba) { put('"'); jsonEscape(ba); put('"'); };
    };


    const QByteArray NullLiteral = QByteArrayLiteral("null");
    const QByteArray TrueLiteral = QByteArrayLiteral("true");
    const QByteArray FalseLiteral = QByteArrayLiteral("false");


    void Writer::writeVariant(const QVariant &v, unsigned prettyIndent, unsigned indentLevel)
    {
        if (v.isNull()) {
            write(NullLiteral);
            return;
        }
        if (UNLIKELY(!v.isValid())) {
            throw Json::Error("Variant has unknown type");
        }

        const auto typ = QMetaType::Type(v.type());
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
            writeString(v.toString().toUtf8());
            break;
        case QMetaType::QStringList:
        case QMetaType::QVariantList:
            writeArray(v.toList(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::QVariantMap:
            writeObject(v.toMap(), prettyIndent, std::max(indentLevel, 1U));
            break;
        case QMetaType::Bool:
            write(v.toBool() ? TrueLiteral : FalseLiteral);
            break;
        case QMetaType::Int:
        case QMetaType::Long:
        case QMetaType::LongLong: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(int64_t(v.toLongLong(&ok1)));
            if (UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize int64 for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        case QMetaType::UInt:
        case QMetaType::ULong:
        case QMetaType::ULongLong: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(uint64_t(v.toULongLong(&ok1)));
            if (UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize uint64 for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        case QMetaType::Double:
        case QMetaType::Float: {
            bool ok1, ok2;
            ok2 = writeIntOrFloat(v.toDouble(&ok1));
            if (UNLIKELY(!ok1 || !ok2))
                throw Json::Error(QString("Unable to serialize double for '%1' (%2, %3)").arg(v.toString()).arg(int(ok1)).arg(int(ok2)));
            break;
        }
        default:
            throw Json::Error(QString("Unsupported type %1 for '%2'").arg(int(typ)).arg(v.toString()));
        }
    }

    void Writer::writeArray(const QVariantList &v, unsigned prettyIndent, unsigned indentLevel)
    {
        put('[');
        if (prettyIndent)
            put('\n');

        for (int i = 0, nValues = v.size(); i < nValues; ++i) {
            if (prettyIndent)
                indentStr(prettyIndent, indentLevel);
            writeVariant(v[i], prettyIndent, indentLevel + 1);
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

    void Writer::writeObject(const QVariantMap &v, unsigned prettyIndent, unsigned indentLevel)
    {
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

    QByteArray serialize(const QVariant &v, unsigned prettyIndent, unsigned indentLevel = 0)
    {
        QByteArray ba; // we do it this way for RVO to work on all compilers
        try {
            Writer writer{ba};
            ba.reserve(1024);
            writer.writeVariant(v, prettyIndent, indentLevel);
        } catch (const std::exception & e) {
            Warning() << "Unable to write json: " << e.what();
            ba.clear();
        }
        return ba;
    }

}

namespace Json {
    QVariant parseFragmentUtf8(const QByteArray &ba) {
        QVariant ret;
        if (!detail::parse(ret, ba))
            throw ParseError(QString("Failed to parse Json from string: %1%2").arg(QString(ba.left(80)))
                             .arg(ba.size() > 80 ? "..." : ""));
        return ret;
    }
    QVariant parseUtf8(const QByteArray &ba, bool expectMap)
    {
        QVariant ret = parseFragmentUtf8(ba); // may throw
        if (expectMap && QMetaType::Type(ret.type()) != QMetaType::QVariantMap)
            throw Error("Json Error, expected map, got a list instead");
        if (!expectMap && QMetaType::Type(ret.type()) != QMetaType::QVariantList)
            throw Error("Json Error, expected list, got a map instead");
        return ret;
    }
    QVariant parseFile(const QString &file, bool expectMap) {
        QFile f(file);
        if (!f.open(QFile::ReadOnly))
            throw Error(QString("Could not open file: %1").arg(file));
        const QByteArray ba{f.readAll()};
        return parseUtf8(ba, expectMap);
    }
    QByteArray toJsonUtf8(const QVariant &v, bool compact) {
        if (v.isNull() || !v.isValid()) throw Error("Empty or invalid QVariant passed to Json::toString");
        return serialize(v, compact ? 0 : 4);
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
#include <QJsonDocument>

#include <cstdlib>
#include <cstdint>

namespace Json {
namespace {
    void bench() {
        const char *dir = std::getenv("DATADIR");
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
                auto var = parseFragmentUtf8(ba);
                if (var.isNull()) throw Exception("Parse result is null");
                if (parsed.size() != fileData.size())
                    parsed.push_back(var); // save parsed data
            }
        }
        double tf = Util::getTimeSecs();
        Log() << "Custom lib parse - total: " << (tf-t0) << " secs" << " - per-iter: "
              << QString::asprintf("%1.16g", ((tf-t0)/iters) * 1e3) << " msec";
        parsed.clear();

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
                auto json = serialize(var, 4);
                if (json.isEmpty()) throw Exception("Serializaiton error");
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

    static const auto bench_ = App::registerBench("json", &bench);
}
}
#endif
