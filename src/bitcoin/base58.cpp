// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>
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

// Added by Calin for performance -- Always succeeds and returns an array of size 256, with invalid postions being -1,
// and valid ones being the carry (from 0 to 57).
const int8_t * GetB58CarryTable()
{
#if defined(__clang__) || defined(__GNUC__)
#define EXPECT(expr, constant) __builtin_expect(expr, constant)
#else
#define EXPECT(expr, constant) (expr)
#endif
#define UNLIKELY(bool_expr) EXPECT(int(bool_expr), 0)
    static std::mutex mut;
    static std::atomic_size_t ptr{0};
    static std::vector<int8_t> b58Carry;
    using RetType = const int8_t *;
    auto ret = reinterpret_cast<RetType>(ptr.load());
    if (UNLIKELY(!ret)) {
        std::unique_lock g(mut);
        if (!(ret = reinterpret_cast<RetType>(ptr.load()))) { // check again with mutex held
            // this branch will only ever be visited once for the lifetime of this process (by 1 thread)
            b58Carry.clear();
            b58Carry.resize(256, -1);
            for (auto p = pszBase58; *p; ++p)
                // build table, storing the carry value for each character in our base58 alphabet, or -1 if not in alphabet
                b58Carry[uint8_t(*p)] = int8_t(p - pszBase58); // (0,57) range here
            ptr.store( reinterpret_cast<decltype (ptr.load())>(ret = b58Carry.data()) );
        }
    }
    return ret;
#undef UNLIKELY
#undef EXPECT
}

} // end anonymous namespace

/* Original Bitcoin implementation below.. removed by Calin and replaced with faster alternative (15% faster on average)
   which doesn't call strchr() repeatedly on the pszBase58 like the original did, but instead builds
   a table in a thread safe manner once, and then subsequent calls use the table. */
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
    // Grab the carry table -- the first time through, the carry table is initted atomically with an exclusive
    // lock, but subsequent times, it will always be returned immediately by reference.
    const auto b58Table = GetB58CarryTable();
    while (*psz && !IsSpace(*psz)) {
        // Decode base58 character
        int carry = b58Table[uint8_t(*psz)];
        if (carry < 0) {
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
