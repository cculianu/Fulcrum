/*
Json - A lightweight JSON parser and serializer for Qt.
Copyright (c) 2020-2021 Calin A. Culianu <calin.culianu@gmail.com>

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Json.h"

#include <QFile>
#include <QMetaType>
#include <QtDebug>
#include <QVariant>

#include <algorithm>
#include <array>
#include <cinttypes>
#include <clocale>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <type_traits>

#ifdef __clang__
// turn off the dreaded "warning: class padded with xx bytes, etc" since we aren't writing wire protocols using structs..
#pragma clang diagnostic ignored "-Wpadded"
#endif
// EXPECT, LIKELY, and UNLIKELY
#if defined(__clang__) || defined(__GNUC__)
#define EXPECT(expr, constant) __builtin_expect(expr, constant)
#else
#define EXPECT(expr, constant) (expr)
#endif

#define LIKELY(bool_expr)   EXPECT(bool(bool_expr), 1)
#define UNLIKELY(bool_expr) EXPECT(bool(bool_expr), 0)

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
            if constexpr (std::is_floating_point<Num>::value) {
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

        if (UNLIKELY(!v.isValid())) {
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

}
namespace Json {
    Error::~Error() {}                         // for vtable
    ParseError::~ParseError() {}               // for vtable
    ParserUnavailable::~ParserUnavailable() {} // for vtable

    bool autoFixLocale = true; // Not atomic for performance. Assumption is this is set by client code before threads are started.

    bool checkLocale(bool autoFix) {
        const auto *const lconv = std::localeconv();
        // check that the decimal point is ".", otherwise we will produce bad Json on serialize
        if (!lconv || 0 != std::strcmp(lconv->decimal_point, ".")) {
            const auto l = std::setlocale(LC_NUMERIC, nullptr);
            qWarning("Json::checkLocale: LC_NUMERIC was not as expected, but instead was \"%s\"", l ? l : "???");
            if (autoFix) {
                static std::mutex mut; // prevent multiple threads from entering here
                std::unique_lock g(mut);
                const auto fallback = "C";
                const auto res = std::setlocale(LC_NUMERIC, fallback);
                if (res && 0 == std::strcmp(fallback, res))
                    qWarning("Json::checkLocale: Forced LC_NUMERIC to \"%s\"", fallback);
                else
                    qWarning("Json::checkLocale: Attempted to force LC_NUMERIC to \"%s\", but setlocale returned \"%s\"",
                             fallback, res ? res : "???");
            } else {
                qCritical("\n"
                          "!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!\n"
                          "!  We may produce or parse JSON incorrectly !\n"
                          "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            }
            return false;
        }
        return true;
    }

    namespace { std::once_flag once_checkLocale; }

    QByteArray serialize(const QVariant &v, unsigned prettyIndent, unsigned indentLevel)
    {
        if (autoFixLocale)
            checkLocale(true);
        else
            std::call_once(once_checkLocale, checkLocale, false);
        QByteArray ba; // we do it this way for RVO to work on all compilers
        Writer writer{ba};
        ba.reserve(1024);
        writer.writeVariant(v, prettyIndent, indentLevel); // this may throw
        return ba;
    }

    QVariant parseUtf8(const QByteArray &ba, ParseOption opt, ParserBackend backend)
    {
        if (autoFixLocale)
            checkLocale(true);
        else
            std::call_once(once_checkLocale, checkLocale, false);
        QVariant ret;
        if (!detail::parse(ret, ba, backend))
            throw ParseError(QString("Failed to parse Json from string: %1%2").arg(QString(ba.left(80)))
                             .arg(ba.size() > 80 ? "..." : ""));
        if (opt == ParseOption::RequireObject && QMetaType::Type(ret.type()) != QMetaType::QVariantMap)
            throw Error("Json Error: expected object");
        if (opt == ParseOption::RequireArray && QMetaType::Type(ret.type()) != QMetaType::QVariantList)
            throw Error("Json Error: expected array");
        return ret;
    }
    QVariant parseFile(const QString &file, ParseOption opt, ParserBackend backend) {
        QFile f(file);
        if (!f.open(QFile::ReadOnly))
            throw Error(QString("Could not open file: %1").arg(file));
        const QByteArray ba{f.readAll()};
        return parseUtf8(ba, opt, backend);
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
