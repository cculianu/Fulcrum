// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utilities for converting data from/to strings.
 */
#pragma once

#include "concepts.h"
#include "Span.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace bitcoin  {

/** Used by SanitizeString() */
enum SafeChars {
    //!< The full set of allowed chars
    SAFE_CHARS_DEFAULT,
    //!< BIP-0014 subset
    SAFE_CHARS_UA_COMMENT,
    //!< Chars allowed in filenames
    SAFE_CHARS_FILENAME,
};

/**
 * Remove unsafe chars. Safe chars chosen to allow simple messages/URLs/email
 * addresses, but avoid anything even possibly remotely dangerous like & or >
 * @param[in] str    The string to sanitize
 * @param[in] rule   The set of safe chars to choose (default: least
 * restrictive)
 * @return           A new string without unsafe chars
 */
std::string SanitizeString(const std::string &str,
                           int rule = SAFE_CHARS_DEFAULT);
std::vector<uint8_t> ParseHex(const char *psz);
std::vector<uint8_t> ParseHex(const std::string &str);
signed char HexDigit(char c) noexcept;
/**
 * Returns true if each character in str is a hex character, and has an even
 * number of hex digits.
 */
bool IsHex(const std::string &str) noexcept;
/**
 * Return true if the string is a hex number, optionally prefixed with "0x"
 */
bool IsHexNumber(const std::string &str);
std::vector<uint8_t> DecodeBase64(const char *p, bool *pfInvalid = nullptr);
std::string DecodeBase64(const std::string &str);
std::string EncodeBase64(const uint8_t *pch, size_t len);
std::string EncodeBase64(const std::string &str);
std::vector<uint8_t> DecodeBase32(const char *p, bool *pfInvalid = nullptr);
std::string DecodeBase32(const std::string &str);
std::string EncodeBase32(const uint8_t *pch, size_t len);
std::string EncodeBase32(const std::string &str);

void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
std::string i64tostr(int64_t n);
std::string itostr(int n);
int64_t atoi64(const char *psz);
int64_t atoi64(const std::string &str);
int atoi(const std::string &str);

/**
 * Tests if the given character is a whitespace character. The whitespace
 * characters are: space, form-feed ('\f'), newline ('\n'), carriage return
 * ('\r'), horizontal tab ('\t'), and vertical tab ('\v').
 *
 * This function is locale independent. Under the C locale this function gives
 * the same result as std::isspace.
 *
 * @param[in] c     character to test
 * @return          true if the argument is a whitespace character; otherwise
 * false
 */
constexpr inline bool IsSpace(char c) noexcept {
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' ||
           c == '\v';
}

/**
 * Convert string to signed 32-bit integer with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid integer, false if
 * not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseInt32(const std::string &str, int32_t *out);

/**
 * Convert string to signed 64-bit integer with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid integer, false if
 * not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseInt64(const std::string &str, int64_t *out);

/**
 * Convert decimal string to unsigned 32-bit integer with strict parse error
 * feedback.
 * @returns true if the entire string could be parsed as valid integer, false if
 * not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseUInt32(const std::string &str, uint32_t *out);

/**
 * Convert decimal string to unsigned 64-bit integer with strict parse error
 * feedback.
 * @returns true if the entire string could be parsed as valid integer, false if
 * not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseUInt64(const std::string &str, uint64_t *out);

/**
 * Convert string to double with strict parse error feedback.
 * @returns true if the entire string could be parsed as valid double, false if
 * not the entire string could be parsed or when overflow or underflow occurred.
 */
bool ParseDouble(const std::string &str, double *out);

namespace strencodings {
// We use a hex lookup table with a series of hex pairs all in 1 string in order to ensure locality of reference.
// This is indexed as hexmap[ubyte_val * 2].
extern const char hexmap[513];
} // namespace strencodings

template <std::random_access_iterator T>
requires (ByteLike<std::iter_value_t<T>>)
std::string HexStr(const T itbegin, const T itend, bool fSpaces = false) {
    std::string rv;
    using strencodings::hexmap;
    using diff_t = std::iter_difference_t<T>;
    const diff_t iSpaces = diff_t(fSpaces);
    diff_t size = (itend - itbegin) * (2 + iSpaces);
    if (size <= 0) // short-circuit return and/or guard against invalid usage
        return rv;
    size -= iSpaces;  // fSpaces only: deduct 1 space for first item
    rv.resize(static_cast<size_t>(size)); // pre-allocate the entire array to avoid using the slower push_back
    size_t pos = 0;
    if (!fSpaces) {
        // this branch is the most likely branch in this codebase
        for (T it = itbegin; it < itend; ++it) {
            const char *hex = &hexmap[static_cast<uint8_t>(*it) * 2u];
            rv[pos++] = *hex++;
            rv[pos++] = *hex;
        }
    } else {
        // we unroll the first iteration (which prints no space) to avoid any branching while looping
        T it = itbegin;
        if (it < itend) {
            // first iteration, no space
            const char *hex = &hexmap[static_cast<uint8_t>(*it) * 2u];
            rv[pos++] = *hex++;
            rv[pos++] = *hex;
            ++it;
            for (; it < itend; ++it) {
                // subsequent iterations (if any), unconditionally prepend space
                rv[pos++] = ' ';
                hex = &hexmap[static_cast<uint8_t>(*it) * 2u];
                rv[pos++] = *hex++;
                rv[pos++] = *hex;
            }
        }
    }
    assert(pos == rv.size());

    return rv;
}

/**
 * Convert a span of bytes to a lower-case hexadecimal string.
 */
inline std::string HexStr(const Span<const uint8_t> input, bool fSpaces = false) {
    return HexStr(input.begin(), input.end(), fSpaces);
}
inline std::string HexStr(const Span<const char> input, bool fSpaces = false) {
    return HexStr(MakeUInt8Span(input), fSpaces);
}
inline std::string HexStr(const Span<const std::byte> input, bool fSpaces = false) {
    return HexStr(MakeUInt8Span(input), fSpaces);
}

/**
 * Format a paragraph of text to a fixed width, adding spaces for indentation to
 * any added line.
 */
std::string FormatParagraph(const std::string &in, size_t width = 79,
                            size_t indent = 0);

/**
 * Timing-attack-resistant comparison.
 * Takes time proportional to length of first argument.
 */
template <typename T> bool TimingResistantEqual(const T &a, const T &b) {
    if (b.size() == 0) return a.size() == 0;
    size_t accumulator = a.size() ^ b.size();
    for (size_t i = 0; i < a.size(); i++)
        accumulator |= a[i] ^ b[i % b.size()];
    return accumulator == 0;
}

/**
 * Parse number as fixed point according to JSON number syntax.
 * See http://json.org/number.gif
 * @returns true on success, false on error.
 * @note The result must be in the range (-10^18,10^18), otherwise an overflow
 * error will trigger.
 */
bool ParseFixedPoint(const std::string &val, int decimals, int64_t *amount_out);

/**
 * Convert from one power-of-2 number base to another.
 *
 * If padding is enabled, this always return true. If not, then it returns true
 * of all the bits of the input are encoded in the output.
 */
template <int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(O &out, I it, I end) {
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((acc >> bits) & maxv);
        }
        ++it;
    }

    // We have remaining bits to encode but do not pad.
    if (!pad && bits) {
        return false;
    }

    // We have remaining bits to encode so we do pad.
    if (pad && bits) {
        out.push_back((acc << (tobits - bits)) & maxv);
    }

    return true;
}

/**
 * Converts the given character to its lowercase equivalent.
 * This function is locale independent. It only converts uppercase
 * characters in the standard 7-bit ASCII range.
 * @param[in] c     the character to convert to lowercase.
 * @return          the lowercase equivalent of c; or the argument
 *                  if no conversion is possible.
 */
constexpr unsigned char ToLower(unsigned char c) {
    return (c >= 'A' && c <= 'Z' ? (c - 'A') + 'a' : c);
}

/**
 * Returns the lowercase equivalent of the given string.
 * This function is locale independent. It only converts uppercase
 * characters in the standard 7-bit ASCII range.
 * This is a feature, not a limitation.
 *
 * @param[in] str   the string to convert to lowercase.
 * @returns         lowercased equivalent of str
 */
std::string ToLower(const std::string &str);

/**
 * Converts the given string to its lowercase equivalent.
 * This function is locale independent. It only converts uppercase
 * characters in the standard 7-bit ASCII range.
 * @param[in,out] str   the string to convert to lowercase.
 */
void Downcase(std::string &str);

/**
 * Converts the given character to its uppercase equivalent.
 * This function is locale independent. It only converts lowercase
 * characters in the standard 7-bit ASCII range.
 * @param[in] c     the character to convert to uppercase.
 * @return          the uppercase equivalent of c; or the argument
 *                  if no conversion is possible.
 */
constexpr unsigned char ToUpper(unsigned char c) {
    return (c >= 'a' && c <= 'z' ? (c - 'a') + 'A' : c);
}

/**
 * Returns the uppercase equivalent of the given string.
 * This function is locale independent. It only converts lowercase
 * characters in the standard 7-bit ASCII range.
 * This is a feature, not a limitation.
 *
 * @param[in] str   the string to convert to uppercase.
 * @returns         UPPERCASED EQUIVALENT OF str
 */
std::string ToUpper(const std::string& str);

/**
 * Capitalizes the first character of the given string.
 * This function is locale independent. It only capitalizes the
 * first character of the argument if it has an uppercase equivalent
 * in the standard 7-bit ASCII range.
 * @param[in] str   the string to capitalize.
 * @return          string with the first letter capitalized.
 */
std::string Capitalize(std::string str);

} // end namespace bitcoin
