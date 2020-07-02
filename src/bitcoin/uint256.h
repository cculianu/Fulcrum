// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include "crypto/common.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

[[maybe_unused]] inline constexpr int xxx_to_suppress_warning_2{}; // without this the below sometimes warns
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

namespace bitcoin {

/** Template base class for fixed-sized opaque blobs. */
template <unsigned int BITS> class base_blob {
protected:
    static constexpr int WIDTH = BITS / 8;
    uint8_t data[WIDTH];

public:
    constexpr base_blob() noexcept : data{0} { }

    explicit base_blob(const std::vector<uint8_t> &vch) noexcept;

    constexpr bool IsNull() const noexcept {
        for (int i = 0; i < WIDTH; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    void SetNull() noexcept { std::memset(data, 0, sizeof(data)); }

    constexpr int Compare(const base_blob &other) const noexcept {
        for (size_t i = 0; i < sizeof(data); i++) {
            uint8_t a = data[sizeof(data) - 1 - i];
            uint8_t b = other.data[sizeof(data) - 1 - i];
            if (a != b) {
                if (a > b)
                    return 1;
                // else a < b...
                return -1;
            }
        }

        return 0;
    }

    friend inline constexpr bool operator==(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) == 0;
    }
    friend inline constexpr bool operator!=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) != 0;
    }
    friend inline constexpr bool operator<(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) < 0;
    }
    friend inline constexpr bool operator<=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) <= 0;
    }
    friend inline constexpr bool operator>(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) > 0;
    }
    friend inline constexpr bool operator>=(const base_blob &a, const base_blob &b) noexcept {
        return a.Compare(b) >= 0;
    }

    std::string GetHex() const;
    void SetHex(const char *psz);
    void SetHex(const std::string &str);
    std::string ToString() const { return GetHex(); }

    constexpr uint8_t *begin() noexcept { return &data[0]; }

    constexpr uint8_t *end() noexcept { return &data[WIDTH]; }

    constexpr const uint8_t *begin() const noexcept { return &data[0]; }

    constexpr const uint8_t *end() const noexcept { return &data[WIDTH]; }

    constexpr unsigned int size() const noexcept { return sizeof(data); }

    static constexpr int width() noexcept { return WIDTH; } // added by Calin

    constexpr uint64_t GetUint64(int pos) const noexcept {
        const uint8_t *ptr = data + pos * 8;
        return uint64_t(ptr[0]) | (uint64_t(ptr[1]) << 8) |
               (uint64_t(ptr[2]) << 16) | (uint64_t(ptr[3]) << 24) |
               (uint64_t(ptr[4]) << 32) | (uint64_t(ptr[5]) << 40) |
               (uint64_t(ptr[6]) << 48) | (uint64_t(ptr[7]) << 56);
    }

    template <typename Stream> void Serialize(Stream &s) const {
        s.write((char *)data, sizeof(data));
    }

    template <typename Stream> void Unserialize(Stream &s) {
        s.read((char *)data, sizeof(data));
    }
};


/**
 * 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an
 * opaque blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    // inherit c'tors
    using base_blob<160>::base_blob;
    // base type copy
    explicit constexpr uint160(const base_blob<160> &b) noexcept : base_blob<160>(b) {}
};

/**
 * 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    // inherit c'tors
    using base_blob<256>::base_blob;
    // base type copy
    explicit constexpr uint256(const base_blob<256> &b) noexcept : base_blob<256>(b) {}

    /**
     * A cheap hash function that just returns 64 bits from the result, it can
     * be used when the contents are considered uniformly random. It is not
     * appropriate when the value can easily be influenced from outside as e.g.
     * a network adversary could provide values to trigger worst-case behavior.
     */
    uint64_t GetCheapHash() const { return ReadLE64(data); }
};

/**
 * uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can
 * result in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str) {
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

/**
 * uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string
 * &str) can result in dangerously catching uint256(0) via std::string(const
 * char*).
 */
inline uint256 uint256S(const std::string &str) {
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

inline uint160 uint160S(const char *str) {
    uint160 rv;
    rv.SetHex(str);
    return rv;
}
inline uint160 uint160S(const std::string &str) {
    uint160 rv;
    rv.SetHex(str);
    return rv;
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif // BITCOIN_UINT256_H
