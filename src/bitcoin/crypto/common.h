// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "endian.h"

namespace bitcoin {
inline uint16_t ReadLE16(const uint8_t *ptr) noexcept {
    uint16_t x;
    std::memcpy(reinterpret_cast<std::byte *>(&x), ptr, 2);
    return le16toh(x);
}

inline uint32_t ReadLE32(const uint8_t *ptr) noexcept {
    uint32_t x;
    std::memcpy(reinterpret_cast<std::byte *>(&x), ptr, 4);
    return le32toh(x);
}

inline uint64_t ReadLE64(const uint8_t *ptr) noexcept {
    uint64_t x;
    std::memcpy(reinterpret_cast<std::byte *>(&x), ptr, 8);
    return le64toh(x);
}

inline void WriteLE16(uint8_t *ptr, const uint16_t x) noexcept {
    const uint16_t v = htole16(x);
    std::memcpy(ptr, reinterpret_cast<const std::byte *>(&v), 2);
}

inline void WriteLE32(uint8_t *ptr, const uint32_t x) noexcept {
    const uint32_t v = htole32(x);
    std::memcpy(ptr, reinterpret_cast<const std::byte *>(&v), 4);
}

inline void WriteLE64(uint8_t *ptr, const uint64_t x) noexcept {
    const uint64_t v = htole64(x);
    std::memcpy(ptr, reinterpret_cast<const std::byte *>(&v), 8);
}

inline uint32_t ReadBE32(const uint8_t *ptr) noexcept {
    uint32_t x;
    std::memcpy(reinterpret_cast<std::byte *>(&x), ptr, 4);
    return be32toh(x);
}

inline uint64_t ReadBE64(const uint8_t *ptr) noexcept {
    uint64_t x;
    std::memcpy(reinterpret_cast<std::byte *>(&x), ptr, 8);
    return be64toh(x);
}

inline void WriteBE32(uint8_t *ptr, const uint32_t x) noexcept {
    const uint32_t v = htobe32(x);
    std::memcpy(ptr, reinterpret_cast<const std::byte *>(&v), 4);
}

inline void WriteBE64(uint8_t *ptr, const uint64_t x) noexcept {
    const uint64_t v = htobe64(x);
    std::memcpy(ptr, reinterpret_cast<const std::byte *>(&v), 8);
}

/**
 * Return the smallest number n such that (x >> n) == 0 (or 64 if the highest
 * bit in x is set.
 */
inline uint64_t CountBits(uint64_t x) noexcept {
    if (!x) return 0;
#ifdef HAVE_DECL___BUILTIN_CLZL
    if constexpr (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return 8 * sizeof(unsigned long) - __builtin_clzl(x);
    }
#endif
#ifdef HAVE_DECL___BUILTIN_CLZLL
    if constexpr (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return 8 * sizeof(unsigned long long) - __builtin_clzll(x);
    }
#endif
    int ret = 0;
    do {
        x >>= 1;
        ++ret;
    } while (x);
    return ret;
}

} // end namespace bitcoin
