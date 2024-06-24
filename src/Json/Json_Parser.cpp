/*
Json - A lightweight JSON parser and serializer for Qt.
Copyright (c) 2020-2024 Calin A. Culianu <calin.culianu@gmail.com>

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

#include <QMetaType>
#include <QtDebug>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

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

#define LIKELY(bool_expr)   EXPECT(int(bool(bool_expr)), 1)
#define UNLIKELY(bool_expr) EXPECT(int(bool(bool_expr)), 0)

// embed simdjson here, if we are on a known 64-bit platform and the header & sources are available
#if defined(__x86_64__) || defined(_M_AMD64) || defined(__aarch64__) || defined(_M_ARM64)
#if defined(SYSTEM_SIMDJSON)
#include <simdjson.h>
#define HAVE_SIMDJSON 1
#elif __has_include("simdjson/simdjson.h") && __has_include("simdjson/simdjson.cpp")
#include "simdjson/simdjson.h"
#include "simdjson/simdjson.cpp"
#define HAVE_SIMDJSON 1
#elif __has_include("simdjson.h") && __has_include("simdjson.cpp")
#include "simdjson.h"
#include "simdjson.cpp"
#define HAVE_SIMDJSON 1
#endif
#endif
#ifndef HAVE_SIMDJSON
#define HAVE_SIMDJSON 0
#endif

namespace {

enum jtokentype {
    JTOK_ERR        = -1,
    JTOK_NONE       =  0,                           // eof
    JTOK_OBJ_OPEN,
    JTOK_OBJ_CLOSE,
    JTOK_ARR_OPEN,
    JTOK_ARR_CLOSE,
    JTOK_COLON,
    JTOK_COMMA,
    JTOK_KW_NULL,
    JTOK_KW_TRUE,
    JTOK_KW_FALSE,
    JTOK_NUMBER,
    JTOK_STRING,
};

inline bool jsonTokenIsValue(jtokentype jtt) noexcept {
    switch (jtt) {
    case JTOK_KW_NULL:
    case JTOK_KW_TRUE:
    case JTOK_KW_FALSE:
    case JTOK_NUMBER:
    case JTOK_STRING:
        return true;

    default:
        return false;
    }

    // not reached
}

inline bool json_isspace(uint8_t ch) noexcept {
    switch (ch) {
    case 0x20:
    case 0x09:
    case 0x0a:
    case 0x0d:
        return true;

    default:
        return false;
    }

    // not reached
}

/*
 * According to stackexchange, the original json test suite wanted
 * to limit depth to 22.  Widely-deployed PHP bails at depth 512,
 * so we will follow PHP's lead, which should be more than sufficient
 * (further stackexchange comments indicate depth > 32 rarely occurs).
 */
inline constexpr size_t MAX_JSON_DEPTH = 512;

inline bool json_isdigit(uint8_t ch) noexcept { return ch >= '0' && ch <= '9'; }

// convert hexadecimal (big endian) string to unsigned integer (machine byte orer)
const char *hextouint(const char *first, const char *last, uint32_t &out) noexcept
{
    out = 0;
    for (; first < last; ++first)
    {
        int digit;
        if (json_isdigit(*first))
            digit = *first - '0';

        else if (*first >= 'a' && *first <= 'f')
            digit = *first - 'a' + 10;

        else if (*first >= 'A' && *first <= 'F')
            digit = *first - 'A' + 10;

        else
            break;

        out = 16 * out + digit;
    }

    return first;
}

/**
 * Filter that generates and validates UTF-8, as well as collates UTF-16
 * surrogate pairs as specified in RFC4627.
 */
class JSONUTF8StringFilter
{
public:
    explicit JSONUTF8StringFilter(QByteArray &s) noexcept
        : str(s), is_valid(true), codepoint(0), state(0), surpair(0)
    { /* Note: this object must not clear the passed-in str */ }

    // Write single 8-bit char (may be part of UTF-8 sequence)
    void push_back(unsigned char ch)
    {
        if (state == 0) {
            if (ch < 0x80) // 7-bit ASCII, fast direct pass-through
                str.push_back(ch);
            else if (ch < 0xc0) // Mid-sequence character, invalid in this state
                is_valid = false;
            else if (ch < 0xe0) { // Start of 2-byte sequence
                codepoint = (ch & 0x1f) << 6;
                state = 6;
            } else if (ch < 0xf0) { // Start of 3-byte sequence
                codepoint = (ch & 0x0f) << 12;
                state = 12;
            } else if (ch < 0xf8) { // Start of 4-byte sequence
                codepoint = (ch & 0x07) << 18;
                state = 18;
            } else // Reserved, invalid
                is_valid = false;
        } else {
            if ((ch & 0xc0) != 0x80) // Not a continuation, invalid
                is_valid = false;
            state -= 6;
            codepoint |= (ch & 0x3f) << state;
            if (state == 0)
                push_back_u(codepoint);
        }
    }
    // Write codepoint directly, possibly collating surrogate pairs
    void push_back_u(uint32_t cp)
    {
        if (state) // Only accept full codepoints in open state
            is_valid = false;
        if (cp >= 0xD800 && cp < 0xDC00) { // First half of surrogate pair
            if (surpair) // Two subsequent surrogate pair openers - fail
                is_valid = false;
            else
                surpair = cp;
        } else if (cp >= 0xDC00 && cp < 0xE000) { // Second half of surrogate pair
            if (surpair) { // Open surrogate pair, expect second half
                // Compute code point from UTF-16 surrogate pair
                append_codepoint(0x10000 | ((surpair - 0xD800)<<10) | (cp - 0xDC00));
                surpair = 0;
            } else // Second half doesn't follow a first half - fail
                is_valid = false;
        } else {
            if (surpair) // First half of surrogate pair not followed by second - fail
                is_valid = false;
            else
                append_codepoint(cp);
        }
    }
    // Check that we're in a state where the string can be ended
    // No open sequences, no open surrogate pairs, etc
    bool finalize() noexcept
    {
        if (state || surpair)
            is_valid = false;
        return is_valid;
    }
private:
    QByteArray &str;
    bool is_valid;
    // Current UTF-8 decoding state
    uint32_t codepoint;
    int state; // Top bit to be filled in for next UTF-8 byte, or 0

    // Keep track of the following state to handle the following section of
    // RFC4627:
    //
    //    To escape an extended character that is not in the Basic Multilingual
    //    Plane, the character is represented as a twelve-character sequence,
    //    encoding the UTF-16 surrogate pair.  So, for example, a string
    //    containing only the G clef character (U+1D11E) may be represented as
    //    "\uD834\uDD1E".
    //
    //  Two subsequent \u.... may have to be replaced with one actual codepoint.
    uint32_t surpair; // First half of open UTF-16 surrogate pair, or 0

    void append_codepoint(uint32_t cp)
    {
        if (cp <= 0x7f)
            str.push_back(char(cp));
        else if (cp <= 0x7FF) {
            str.push_back(char(0xC0 | (cp >> 6)));
            str.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            str.push_back(char(0xE0 | (cp >> 12)));
            str.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            str.push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp <= 0x1FFFFF) {
            str.push_back(char(0xF0 | (cp >> 18)));
            str.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
            str.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            str.push_back(char(0x80 | (cp & 0x3F)));
        }
    }
};

/// ** Note ** this may end up making `tokenVal` be a *shallow copy* that points into `raw`
jtokentype getJsonToken(QByteArray &tokenVal, unsigned &consumed, const char *raw, const char * const end)
{
    consumed = 0;

    const char * const rawStart = raw;

    while (raw < end && (json_isspace(*raw)))          // skip whitespace
        ++raw;

    if (raw >= end)
        return JTOK_NONE;

    switch (*raw) {

    case '{':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_OBJ_OPEN;
    case '}':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_OBJ_CLOSE;
    case '[':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_ARR_OPEN;
    case ']':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_ARR_CLOSE;

    case ':':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_COLON;
    case ',':
        ++raw;
        consumed = raw - rawStart;
        return JTOK_COMMA;

    case 'n':
        if (0 == std::strncmp(raw, "null", 4)) {
            raw += 4;
            consumed = raw - rawStart;
            return JTOK_KW_NULL;
        }
        return JTOK_ERR;
    case 't':
        if (0 == std::strncmp(raw, "true", 4)) {
            raw += 4;
            consumed = raw - rawStart;
            return JTOK_KW_TRUE;
        }
        return JTOK_ERR;
    case 'f':
        if (0 == std::strncmp(raw, "false", 5)) {
            raw += 5;
            consumed = raw - rawStart;
            return JTOK_KW_FALSE;
        }
        return JTOK_ERR;

    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9': {
        // part 1: int
        const char * const first = raw;
        const bool firstIsMinus = *first == '-';

        const char * const firstDigit = first + firstIsMinus; // if first == '-', firstDigit = first + 1, else firstDigit = first

        if (UNLIKELY(*firstDigit == '0' && firstDigit + 1 < end && json_isdigit(firstDigit[1])))
            return JTOK_ERR;

        ++raw;                                  // consume first char

        if (UNLIKELY(firstIsMinus && (raw >= end || !json_isdigit(*raw)))) // fail if buffer ends in '-', or matches '-[^0-9]'
            return JTOK_ERR;

        while (raw < end && json_isdigit(*raw)) {  // consume digits
            ++raw;
        }

        // part 2: frac
        if (raw < end && *raw == '.') {
            ++raw;                              // consume .

            if (UNLIKELY(raw >= end || !json_isdigit(*raw)))
                return JTOK_ERR;
            while (raw < end && json_isdigit(*raw)) { // consume digits
                ++raw;
            }
        }

        // part 3: exp
        if (raw < end && (*raw == 'e' || *raw == 'E')) {
            ++raw;                              // consume E

            if (raw < end && (*raw == '-' || *raw == '+')) { // consume +/-
                ++raw;
            }

            if (UNLIKELY(raw >= end || !json_isdigit(*raw)))
                return JTOK_ERR;
            while (raw < end && json_isdigit(*raw)) { // consume digits
                ++raw;
            }
        }
        tokenVal = QByteArray::fromRawData(first, int(raw - first));  // SHALLOW COPY
        consumed = raw - rawStart;
        return JTOK_NUMBER;
    }

    case '"': {
        constexpr int reserveSize = 0; // set to 0 to not pre-alloc anything
        ++raw;                                // skip "

        // First, try the fast path which doesn't use the (slow) JSONUTF8StringFilter.
        // This is a common-case optimization: we optimistically scan to ensure string
        // is a simple ascii string with no unicode and no escapes, and if so, return it.
        // If we do encounter non-ascii or escapes, we accept the partial string into
        // `tokenVal`, then we proceed to the slow path.  In most real-world JSON for
        // this app, the fast path below is the only path taken and is the common-case.
        constexpr bool tryFastPath = true;
        if constexpr (tryFastPath) {
            enum class FastPath {
                Processed, NotFullyProcessed, Error
            };

            static const auto FastPathParseSimpleString = [](const char *& raw, const char * const end) -> FastPath {
                for (; raw < end; ++raw) {
                    const uint8_t ch = uint8_t(*raw);
                    if (ch == '"') {
                        // fast-path accept case: simple string end at " char
                        return FastPath::Processed;
                    } else if (ch == '\\') {
                        // has escapes -- cannot process as simple string, must continue using slow path
                        return FastPath::NotFullyProcessed;
                    } else if (ch < 0x20) {
                        // is not legal JSON because < 0x20
                        return FastPath::Error;
                    } else if (ch >= 0x80) {
                        // has a funky unicode character.. must take slow path
                        return FastPath::NotFullyProcessed;
                    }
                }
                // premature string end
                return FastPath::Error;
            };
            switch (const auto begin = raw; FastPathParseSimpleString(raw /*pass-by-ref*/, end)) {
            case FastPath::Processed:
                // fast path taken -- the string had no embedded escapes or non-ascii characters, return
                // early, set tokenVal, set consumed. Note: raw now points to trailing " char
                assert(*raw == '"');
                tokenVal = QByteArray::fromRawData(begin, int(raw - begin)); // SHALLOW COPY
                ++raw; // consume trailing "
                consumed = raw - rawStart;
                return JTOK_STRING;
            case FastPath::NotFullyProcessed:
                // we partially processed, put accepted chars into `tokenVal`
                tokenVal = QByteArray{begin, int(raw - begin)};  // DEEP COPY
                break; // will take slow path below
            case FastPath::Error:
                // the fast path encountered premature string end or char < 0x20 -- abort early
                return JTOK_ERR;
            }
        } else {
            // this is taken if tryFastPath is disabled at compile-time
            // -- just ensure output buffer is cleared so we can append to it below
            tokenVal.clear();
        }
        // -----
        // Slow path -- scan 1 character at a time and process the chars thru JSONUTF8StringFilter
        // -----
        if constexpr (reserveSize > 0)
            tokenVal.reserve(reserveSize);
        JSONUTF8StringFilter writer(tokenVal); // note: this filter object must *not* clear tokenVal in its c'tor

        while (true) {
            if (UNLIKELY(raw >= end || uint8_t(*raw) < 0x20))
                return JTOK_ERR;

            else if (*raw == '\\') {
                ++raw;                        // skip backslash

                if (UNLIKELY(raw >= end))
                    return JTOK_ERR;

                switch (*raw++) {             // read then skip esc'd char
                case '"':  writer.push_back('"'); break;
                case '\\': writer.push_back('\\'); break;
                case '/':  writer.push_back('/'); break;
                case 'b':  writer.push_back('\b'); break;
                case 'f':  writer.push_back('\f'); break;
                case 'n':  writer.push_back('\n'); break;
                case 'r':  writer.push_back('\r'); break;
                case 't':  writer.push_back('\t'); break;

                case 'u': {
                    uint32_t codepoint;
                    if (auto * const cpend = raw + 4; cpend >= end || hextouint(raw, cpend, codepoint) != cpend)
                        return JTOK_ERR;
                    writer.push_back_u(codepoint);
                    raw += 4;                 // skip hex chars
                    break;
                }

                default:
                    return JTOK_ERR;

                } // switch
            }

            else if (*raw == '"') {
                ++raw;                        // skip "
                break;                        // stop scanning
            }

            else {
                writer.push_back(*raw);
                ++raw;
            }
        }

        if (UNLIKELY(!writer.finalize()))
            return JTOK_ERR;

        if constexpr (reserveSize > 0)
            tokenVal.squeeze();
        // -- At this point `tokenVal` contains the entire accepted string from
        // -- inside the enclosing quotes "", unescaped and UTF-8-processed.
        consumed = raw - rawStart;
        return JTOK_STRING;
        }

    default:
        return JTOK_ERR;
    }
}

/// Note: The QByteArrays in this struct may be "views of" or shallow copies of the original `bytes` buffer
/// being parsed (e.g. via QByteArray::fromRawData) -- so when producing the final result we need to always
/// take deep copies of any QByteArray data.
struct Container {
    enum Typ {
        Null, BoolFalse, BoolTrue, Num, Str, Arr, Obj
    };
    Typ typ = Null;
    // Note: I tried using a union class here to conserve memory but that was actually 10-20% slower
    // than simply doing this, and had lots of boilerplate for copy/move c'tor and copy/move assign, so
    // we just go with this.  This consumes ~48 bytes of extra memory on avg. per parsed json value;
    // but since this data structure is ephemeral and only used during parsing, that's acceptable since
    // the memory will be freed once parsing finishes.  It would only be a problem if we anticipated
    // parsing json that ends up containing hundreds of millions of json values, but since we don't,
    // this is fine.
    //
    // We could have also used a std::variant here but that is not implemented yet on all compilers
    // that we target.
    QByteArray data; // only for Num, Str -- may be a shallow copy pointing into the `bytes` QByteArray passed to Json::detail::parse()
    std::vector<Container> values; // only for Arr
    // Note that the below pair.first QByteArray may be a shallow copy pointing into the `bytes` QByteArray
    std::vector<std::pair<QByteArray, Container>> entries; // only for Obj
    void clear() { data.clear(); values.clear(); entries.clear(); typ = Null; }
    void setArr() { clear(); typ = Arr; }
    void setObj() { clear(); typ = Obj; }
    void setBool(bool b) { clear(); typ = b ? BoolTrue: BoolFalse; }

    /// Recursively scours this container and its sub-containers and builds the proper QVariant / nesting.
    /// Unlike this intermediate object, the resultant QVariant's string data (if any) will always be deep
    /// copies of the original string data that came in.
    QVariant toVariant() const;
};

/// recursively scours this container and its sub-containers and builds the proper QVariant / nesting
QVariant Container::toVariant() const {
    QVariant ret;
    switch(typ) {
    case Null:
        // no further processing needed
        break;
    case Num: {
        // NB: for `Num` type, `data` is always a shallow copy of the data in the original `bytes` arg
        if (UNLIKELY(data.isEmpty())) {
            // this should never happen
            throw Json::ParseError("Data is empty for a nested item of type Num");
        }
        // NOTE .toDouble() is unsafe on raw shallow QByteArray - see QT-BUG 85580 and 86681.
        // Also note that .toLongLong() and .toULongLong() make an implicit deep copy of the data.
        // Since we want to avoid excess mallocs, we take a copy ourselves on the stack of the C-string
        // data to ensure NUL termination, and then we call into the C functions for parsing ourselves.
        // - 47 chars are more than enough for doubles; we won't support excessively long notations.
        //   See: https://stackoverflow.com/questions/1701055/what-is-the-maximum-length-in-chars-needed-to-represent-any-double-value
        // - int64's need about ~22 bytes, so 47 is plenty
        std::array<char, 48> dcopy;
        const QByteArray::size_type len = std::min<QByteArray::size_type>(dcopy.size()-1, data.size());
        std::memcpy(dcopy.data(), data.constData(), len);
        dcopy[len] = 0; // ensure nul termination
        const char * const begin = dcopy.data(); char *parseEnd = nullptr;
        const auto HasChar = [begin, len](char c) { return std::memchr(begin, c, len) != nullptr; };
        bool ok;
        if (HasChar('.') || HasChar('e') || HasChar('E')) {
            errno = 0; // NB: errno lives in thread-local storage so this is fine
            const double d = std::strtod(begin, &parseEnd);
            ok = !errno && parseEnd != begin; /* accept junk at end, just in case? */
            ret = d;
        } else if (*begin == '-') {
            errno = 0; // NB: errno lives in thread-local storage so this is fine
            const auto ll = std::strtoll(begin, &parseEnd, 10);
            ok = !errno && parseEnd == begin + len; /* do not accept junk at end */
            // the below is just in case qlonglong differs from long long
            constexpr auto MIN = std::numeric_limits<qlonglong>::min(), MAX = std::numeric_limits<qlonglong>::max();
            if constexpr (MIN != std::numeric_limits<decltype(ll)>::min() || MAX != std::numeric_limits<decltype(ll)>::max())
                ok = ok && ll >= MIN && ll <= MAX;
            ret = qlonglong(ll);
        } else {
            errno = 0; // NB: errno lives in thread-local storage so this is fine
            const auto ull = std::strtoull(begin, &parseEnd, 10);
            ok = !errno && parseEnd == begin + len; /* do not accept junk at end */
            // the below is just in case qulonglong differs from unsigned long long
            constexpr auto MIN = std::numeric_limits<qulonglong>::min(), MAX = std::numeric_limits<qulonglong>::max();
            if constexpr (MIN != std::numeric_limits<decltype(ull)>::min() || MAX != std::numeric_limits<decltype(ull)>::max())
                ok = ok && ull >= MIN && ull <= MAX;
            ret = qulonglong(ull);
        }
        if (UNLIKELY(!ok)) {
            // this should never happen
            throw Json::ParseError(QString("Failed to parse number from string: %1 (original: %2)")
                                   .arg(begin, QString::fromUtf8(data.constData(), data.size())));
        }
        break;
    }
    case BoolTrue:
        ret = true;
        break;
    case BoolFalse:
        ret = false;
        break;
    case Str:
        // NB: data may be a shallow or deep copy of the original data in `bytes`
        // We use this C string syntax because it's faster, as well as more correct.
        // Also note that round1.json test fails (because it contains the 0 codepoint)
        // unless we do this C-string syntax to construct the QString.
        // QString quirks, see:  https://github.com/qt/qtbase/blob/ba3b53cb501a77144aa6259e48a8e0edc3d1481d/src/corelib/text/qstring.h#L701
        //              versus:  https://github.com/qt/qtbase/blob/ba3b53cb501a77144aa6259e48a8e0edc3d1481d/src/corelib/text/qstring.h#L709
        ret = QString::fromUtf8(data.constData(), data.size());
        break;
    case Arr: {
        QVariantList vl;
        vl.reserve(values.size());
        for (const auto & cont : values) {
            vl.push_back(cont.toVariant());
        }
        ret = vl;
        break;
    }
    case Obj: {
        // NB: pair.first in entries may be a deep or shallow copy of the data in `bytes`
        QVariantMap vm;
        for (const auto & [key, cont] : entries) {
            // We use this C string syntax because it's faster & more accurate. (QString quirks)
            vm[QString::fromUtf8(key.constData(), key.size())] = cont.toVariant();
        }
        ret = vm;
        break;
    }
    }
    return ret;
}
} // end anonymous namespace

namespace Json {

bool isParserAvailable(ParserBackend backend) {
    switch (backend) {
    case ParserBackend::FastestAvailable:
    case ParserBackend::Default: return true;
    case ParserBackend::SimdJson: return bool(HAVE_SIMDJSON);
    }
    return false; // not normally reached; suppress compiler warnings
}

namespace detail {

namespace {
/// May throw ParserUnavailable if the simdjson parser is not compiled-in
bool sjParse(QVariant &out, const QByteArray &bytes);
}

bool parse(QVariant &out, const QByteArray &bytes, ParserBackend backend)
{
    if (backend == ParserBackend::SimdJson
            || (backend == ParserBackend::FastestAvailable && isParserAvailable(ParserBackend::SimdJson)))
        return sjParse(out, bytes);

    // "Default" (internal) parser implementation below

    enum ExpectBits : uint32_t {
        EXP_OBJ_NAME = 1U << 0,
        EXP_COLON = 1U << 1,
        EXP_ARR_VALUE = 1U << 2,
        EXP_VALUE = 1U << 3,
        EXP_NOT_VALUE = 1U << 4,
    };
    uint32_t expectMask = 0;
#   define expect(bit) (expectMask & ExpectBits::EXP_##bit)
#   define setExpect(bit) (expectMask |= ExpectBits::EXP_##bit)
#   define clearExpect(bit) (expectMask &= ~ExpectBits::EXP_##bit)

    out = QVariant{}; // ensure cleared

    Container root;
    std::vector<Container *> stack;

    QByteArray tokenVal;
    unsigned consumed;
    jtokentype tok = JTOK_NONE;
    jtokentype last_tok = JTOK_NONE;
    const char *raw = bytes.constData();
    const char * const end = raw + bytes.size();
    do {
        using VType = Container::Typ;

        last_tok = tok;

        /* Note: getJsonToken modifies `tokenVal` *only if* return val was
         * JTOK_NUMBER or JTOK_STRING, but it may also modify it on JTOK_ERR,
         * leaving `tokenVal` in an unspecified state. */
        tok = getJsonToken(tokenVal, consumed, raw, end);
        if (tok == JTOK_NONE || tok == JTOK_ERR)
            return false;
        raw += consumed;

        const bool isValueOpen = jsonTokenIsValue(tok) || tok == JTOK_OBJ_OPEN || tok == JTOK_ARR_OPEN;

        if (expect(VALUE)) {
            if (!isValueOpen)
                return false;
            clearExpect(VALUE);

        } else if (expect(ARR_VALUE)) {
            bool isArrValue = isValueOpen || tok == JTOK_ARR_CLOSE;
            if (!isArrValue)
                return false;

            clearExpect(ARR_VALUE);

        } else if (expect(OBJ_NAME)) {
            bool isObjName = tok == JTOK_OBJ_CLOSE || tok == JTOK_STRING;
            if (!isObjName)
                return false;

        } else if (expect(COLON)) {
            if (tok != JTOK_COLON)
                return false;
            clearExpect(COLON);

        } else if (!expect(COLON) && tok == JTOK_COLON) {
            return false;
        }

        if (expect(NOT_VALUE)) {
            if (isValueOpen)
                return false;
            clearExpect(NOT_VALUE);
        }

        switch (tok) {

        case JTOK_OBJ_OPEN:
        case JTOK_ARR_OPEN: {
            VType utyp = (tok == JTOK_OBJ_OPEN ? VType::Obj : VType::Arr);
            if (stack.empty()) {
                if (utyp == VType::Obj)
                    root.setObj();
                else
                    root.setArr();
                stack.push_back(&root);
            } else {
                Container *top = stack.back();
                if (top->typ == VType::Obj) {
                    // paranoia
                    if (UNLIKELY(top->entries.empty())) {
                        qCritical() << "Json Parser ERROR: Obj 'entries' is empty; FIXME!";
                        return false;
                    }
                    // /paranoia
                    auto& entry = top->entries.back();
                    if (utyp == VType::Obj)
                        entry.second.setObj();
                    else
                        entry.second.setArr();
                    stack.push_back(&entry.second);
                } else {
                    top->values.emplace_back(Container{utyp, {}, {}, {}});
                    stack.push_back(&top->values.back());
                }
            }

            if (UNLIKELY(stack.size() > MAX_JSON_DEPTH))
                return false;

            if (utyp == VType::Obj)
                setExpect(OBJ_NAME);
            else
                setExpect(ARR_VALUE);
            break;
        }

        case JTOK_OBJ_CLOSE:
        case JTOK_ARR_CLOSE: {
            if (UNLIKELY(stack.empty() || last_tok == JTOK_COMMA))
                return false;

            VType utyp = (tok == JTOK_OBJ_CLOSE ? VType::Obj : VType::Arr);
            Container *top = stack.back();
            if (UNLIKELY(utyp != top->typ))
                return false;

            stack.pop_back();
            clearExpect(OBJ_NAME);
            setExpect(NOT_VALUE);
            break;
        }

        case JTOK_COLON: {
            if (UNLIKELY(stack.empty()))
                return false;

            Container *top = stack.back();
            if (UNLIKELY(top->typ != VType::Obj))
                return false;

            setExpect(VALUE);
            break;
        }

        case JTOK_COMMA: {
            if (UNLIKELY(stack.empty() || last_tok == JTOK_COMMA || last_tok == JTOK_ARR_OPEN))
                return false;

            Container *top = stack.back();
            if (top->typ == VType::Obj)
                setExpect(OBJ_NAME);
            else
                setExpect(ARR_VALUE);
            break;
        }

        case JTOK_KW_NULL:
        case JTOK_KW_TRUE:
        case JTOK_KW_FALSE: {
            Container tmpVal;
            switch (tok) {
            case JTOK_KW_NULL:
                // do nothing more
                break;
            case JTOK_KW_TRUE:
                tmpVal.setBool(true);
                break;
            case JTOK_KW_FALSE:
                tmpVal.setBool(false);
                break;
            default: /* impossible */ break;
            }

            if (stack.empty()) {
                root = std::move(tmpVal);
                break;
            }

            Container *top = stack.back();
            if (top->typ == VType::Obj) {
                // paranoia
                if (UNLIKELY(top->entries.empty())) {
                    qCritical() << "Json Parser ERROR: Obj 'entries' is empty when parsing a keyword; FIXME!";
                    return false;
                }
                // /paranoia
                top->entries.back().second = std::move(tmpVal);
            } else {
                top->values.emplace_back(std::move(tmpVal));
            }

            setExpect(NOT_VALUE);
            break;
        }

        case JTOK_NUMBER: {
            Container tmpVal{VType::Num, std::move(tokenVal), {}, {}};
            if (stack.empty()) {
                root = std::move(tmpVal);
                break;
            }

            Container *top = stack.back();
            if (top->typ == VType::Obj) {
                // paranoia
                if (UNLIKELY(top->entries.empty())) {
                    qCritical() << "Json Parser ERROR: Obj 'entries' is empty when parsing a number; FIXME!";
                    return false;
                }
                // /paranoia
                top->entries.back().second = std::move(tmpVal);
            } else {
                top->values.emplace_back(std::move(tmpVal));
            }

            setExpect(NOT_VALUE);
            break;
        }

        case JTOK_STRING: {
            if (expect(OBJ_NAME)) {
                Container *top = stack.back();
                top->entries.emplace_back(std::piecewise_construct,
                                          std::forward_as_tuple(std::move(tokenVal)),
                                          std::forward_as_tuple());
                clearExpect(OBJ_NAME);
                setExpect(COLON);
            } else {
                Container tmpVal{VType::Str, std::move(tokenVal), {}, {}};
                if (stack.empty()) {
                    root = std::move(tmpVal);
                    break;
                }
                Container *top = stack.back();
                if (top->typ == VType::Obj) {
                    // paranoia
                    if (UNLIKELY(top->entries.empty())) {
                        qCritical() << "Json Parser ERROR: Obj 'entries' is empty when parsing a string; FIXME!";
                        return false;
                    }
                    // /paranoia
                    top->entries.back().second = std::move(tmpVal);
                } else {
                    top->values.emplace_back(std::move(tmpVal));
                }
            }

            setExpect(NOT_VALUE);
            break;
        }

        default:
            return false;
        }
    } while (!stack.empty());

    /* Check that nothing follows the initial construct (parsed above).  */
    tok = getJsonToken(tokenVal, consumed, raw, end);
    if (tok != JTOK_NONE)
        return false;

    try {
        out = root.toVariant(); // convert to (possibly nested) QVariant containing QVariants
    } catch (const std::exception &e) {
        // this is unlikely to happen, but may if std::bad_alloc (or if bugs in this code).
        qWarning() << "Failed to parse JSON: " << e.what();
        return false;
    }

    return true;
#   undef expect
#   undef setExpect
#   undef clearExpect
}

namespace {
#if HAVE_SIMDJSON
QVariant sjToVariant(const simdjson::dom::element &e)
{
    QVariant var;
    using T = simdjson::dom::element_type;
    switch (e.type()) {
    case T::ARRAY: {
        QVariantList l;
        auto && res = e.get_array();
        auto && arr = res.value();
        l.reserve(arr.size());
        for (const auto &e2 : arr)
            l.push_back(sjToVariant(e2));
        var = l;
        break;
    }
    case T::OBJECT: {
        QVariantMap m;
        auto && res = e.get_object();
        auto && o = res.value();
        for (auto && [k, v] : o)
            m.insert(QString::fromUtf8(k.data(), k.size()), sjToVariant(v));
        var = m;
        break;
    }
    case T::INT64:
        var = static_cast<qlonglong>(e.get_int64().value());
        break;
    case T::UINT64:
        var = static_cast<qulonglong>(e.get_uint64().value());
        break;
    case T::DOUBLE:
        var = e.get_double().value();
        break;
    case T::BOOL:
        var = e.get_bool().value();
        break;
    case T::STRING: {
        const std::string_view s = e.get_string().value();
        // this fromUtf8 syntax is preferred since it can pick up embedded NULs
        var = QString::fromUtf8(s.data(), s.size());
        break;
    }
    case T::NULL_VALUE:
        // default constructed QVariant is already null
        break;
    }
    return var;
}
#endif

// does not normally throw unless !HAVE_SIMDJSON in which case it always throws ParserUnavailable
bool sjParse(QVariant &out, const QByteArray &bytes)
{
#if HAVE_SIMDJSON
    simdjson::dom::parser parser;
    simdjson::dom::element elem;
    auto error = parser.parse(std::string_view{bytes.data(), size_t(bytes.size())}).get(elem);
    if (error)
        return false;
    out = sjToVariant(elem);
    return true;
#else
    (void)out; (void)bytes;
    throw ParserUnavailable("Json Error: The SimdJson parser is not available");
#endif
}
} // namespace
} // namespace detail

namespace SimdJson {
std::optional<const Info> getInfo()
{
    std::optional<Info> ret;
#if HAVE_SIMDJSON
    ret.emplace();
    const auto &activeName = simdjson::active_implementation->name();
    for (auto *implementation : simdjson::available_implementations) {
        auto & imp = ret->implementations.emplace_back();
        imp.name = QString::fromStdString(implementation->name());
        imp.description = QString::fromStdString(implementation->description());
        imp.supported = implementation->supported_by_runtime_system();
        if (implementation->name() == activeName)
            ret->active = imp; // copy
    }
#endif
    return ret;
}
QString versionString()
{
    QString ret;
#if HAVE_SIMDJSON
    ret = QString("%1.%2.%3").arg(simdjson::SIMDJSON_VERSION_MAJOR).arg(simdjson::SIMDJSON_VERSION_MINOR).arg(simdjson::SIMDJSON_VERSION_REVISION);
#endif
    return ret;
}
} // namespace SimdJson
} // namespace Json
