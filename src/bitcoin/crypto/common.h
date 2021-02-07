// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <cstdint>
#include <cstring>

#include "endian.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif

namespace bitcoin {
inline uint16_t ReadLE16(const uint8_t *ptr) noexcept {
    uint16_t x;
    std::memcpy((char *)&x, ptr, 2);
    return le16toh(x);
}

inline uint32_t ReadLE32(const uint8_t *ptr) noexcept {
    uint32_t x;
    std::memcpy((char *)&x, ptr, 4);
    return le32toh(x);
}

inline uint64_t ReadLE64(const uint8_t *ptr) noexcept {
    uint64_t x;
    std::memcpy((char *)&x, ptr, 8);
    return le64toh(x);
}

inline void WriteLE16(uint8_t *ptr, uint16_t x) noexcept {
    uint16_t v = htole16(x);
    std::memcpy(ptr, (char *)&v, 2);
}

inline void WriteLE32(uint8_t *ptr, uint32_t x) noexcept {
    uint32_t v = htole32(x);
    std::memcpy(ptr, (char *)&v, 4);
}

inline void WriteLE64(uint8_t *ptr, uint64_t x) noexcept {
    uint64_t v = htole64(x);
    std::memcpy(ptr, (char *)&v, 8);
}

inline uint32_t ReadBE32(const uint8_t *ptr) noexcept {
    uint32_t x;
    std::memcpy((char *)&x, ptr, 4);
    return be32toh(x);
}

inline uint64_t ReadBE64(const uint8_t *ptr) noexcept {
    uint64_t x;
    std::memcpy((char *)&x, ptr, 8);
    return be64toh(x);
}

inline void WriteBE32(uint8_t *ptr, uint32_t x) noexcept {
    uint32_t v = htobe32(x);
    std::memcpy(ptr, (char *)&v, 4);
}

inline void WriteBE64(uint8_t *ptr, uint64_t x) noexcept {
    uint64_t v = htobe64(x);
    std::memcpy(ptr, (char *)&v, 8);
}

/**
 * Return the smallest number n such that (x >> n) == 0 (or 64 if the highest
 * bit in x is set.
 */
inline uint64_t CountBits(uint64_t x) noexcept {
#ifdef HAVE_DECL___BUILTIN_CLZL
    if constexpr (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long) - __builtin_clzl(x) : 0;
    }
#endif
#ifdef HAVE_DECL___BUILTIN_CLZLL
    if constexpr (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long long) - __builtin_clzll(x) : 0;
    }
#endif
    int ret = 0;
    while (x) {
        x >>= 1;
        ++ret;
    }
    return ret;
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif // BITCOIN_CRYPTO_COMMON_H
