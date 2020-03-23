// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

namespace bitcoin {
namespace {
/** All alphanumeric characters except for "0", "I", "O", and "l" */
const char *pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Do not construct this class. Instead, use the singleton instance provided below as b58CarryTable.
class B58CarryTable {
    std::array<int8_t, 256> table;
public:
    B58CarryTable();
    constexpr int8_t operator[](decltype(table)::size_type i) const noexcept { return table[i]; }
};

B58CarryTable::B58CarryTable()
{
    table.fill(-1);
    for (auto p = pszBase58; *p; ++p)
        // build table, storing the carry value for each character in our base58 alphabet, or -1 if not in alphabet
        table[uint8_t(*p)] = int8_t(p - pszBase58); // (0,57) range here
}

B58CarryTable b58CarryTable; ///< singleton instance -- used by our modified DecodeBase58.

} // end anonymous namespace

/* Original Bitcoin implementation below.. removed by Calin and replaced with faster alternative (15% faster on average)
   which doesn't call strchr() repeatedly on the pszBase58 like the original did, but instead builds
   a table once (~256 byte memory cost), and then subsequent calls use the table. */
#if 0
bool DecodeBase58(const char *psz, std::vector<uint8_t> &vch) {
    // Skip leading spaces.
    while (*psz && IsSpace(*psz)) {
        psz++;
    }
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    // log(58) / log(256), rounded up.
    int size = strlen(psz) * 733 / 1000 + 1;
    std::vector<uint8_t> b256(size);
    // Process the characters.
    while (*psz && !IsSpace(*psz)) {
        // Decode base58 character
        const char *ch = strchr(pszBase58, *psz);
        if (ch == nullptr) {
            return false;
        }
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        int i = 0;
        for (std::vector<uint8_t>::reverse_iterator it = b256.rbegin();
             (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (IsSpace(*psz)) {
        psz++;
    }
    if (*psz != 0) {
        return false;
    }
    // Skip leading zeroes in b256.
    std::vector<uint8_t>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end()) {
        vch.push_back(*(it++));
    }
    return true;
}
#else
// Calin's 15% faster implementation here
bool DecodeBase58(const char *psz, std::vector<uint8_t> &vch) {
    // Skip leading spaces.
    while (*psz && IsSpace(*psz)) {
        psz++;
    }
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    // log(58) / log(256), rounded up.
    int size = strlen(psz) * 733 / 1000 + 1;
    std::vector<uint8_t> b256(size);
    // Process the characters.
    while (*psz && !IsSpace(*psz)) {
        // Decode base58 character
        int carry = b58CarryTable[uint8_t(*psz)];
        if (carry < 0) {
            // invalid character
            return false;
        }
        // Apply "b256 = b256 * 58 + ch".
        int i = 0;
        for (std::vector<uint8_t>::reverse_iterator it = b256.rbegin();
             (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (IsSpace(*psz)) {
        psz++;
    }
    if (*psz != 0) {
        return false;
    }
    // Skip leading zeroes in b256.
    std::vector<uint8_t>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end()) {
        vch.push_back(*(it++));
    }
    return true;
}
#endif
std::string EncodeBase58(const uint8_t *pbegin, const uint8_t *pend) {
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    // log(256) / log(58), rounded up.
    int size = (pend - pbegin) * 138 / 100 + 1;
    std::vector<uint8_t> b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<uint8_t>::reverse_iterator it = b58.rbegin();
             (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<uint8_t>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0) {
        it++;
    }
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end()) {
        str += pszBase58[*(it++)];
    }
    return str;
}

std::string EncodeBase58(const std::vector<uint8_t> &vch) {
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

bool DecodeBase58(const std::string &str, std::vector<uint8_t> &vchRet) {
    return DecodeBase58(str.c_str(), vchRet);
}

std::string EncodeBase58Check(const std::vector<uint8_t> &vchIn) {
    // add 4-byte hash check to the end
    std::vector<uint8_t> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (uint8_t *)&hash, (uint8_t *)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const char *psz, std::vector<uint8_t> &vchRet) {
    if (!DecodeBase58(psz, vchRet) || (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string &str, std::vector<uint8_t> &vchRet) {
    return DecodeBase58Check(str.c_str(), vchRet);
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
