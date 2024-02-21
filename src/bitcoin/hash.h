// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "uint256.h"
#include "version.h"
#include "serialize.h"

#include <cstddef> // for std::byte
#include <type_traits>
#include <vector>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif

namespace bitcoin {

using ChainCode = uint256;

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
    const bool once = false;
public:
    CHash256(bool once = false) : once(once) {}
    static constexpr size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(uint8_t hash[OUTPUT_SIZE]) {
        if (!once) {
            uint8_t buf[CSHA256::OUTPUT_SIZE];
            sha.Finalize(buf);
            sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
        } else {
            sha.Finalize(hash);
        }
    }

    CHash256 &Write(const uint8_t *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256 &Reset() {
        sha.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;

public:
    static constexpr size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(uint8_t hash[OUTPUT_SIZE]) {
        uint8_t buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash160 &Write(const uint8_t *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash160 &Reset() {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template <typename T1> inline uint256 Hash(const T1 pbegin, const T1 pend, bool once = false) {
    const uint8_t pblank[1] = {};
    uint256 result{uint256::Uninitialized};
    CHash256(once)
        .Write(pbegin == pend ? pblank : (const uint8_t *)&pbegin[0],
               (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize(result.data());
    return result;
}

/** Compute the 256-bit SINGLE hash of an object. This was added by Calin to work with ElectrumX */
template <typename T1> inline uint256 HashOnce(const T1 pbegin, const T1 pend) {
    return Hash(pbegin, pend, true);
}

inline uint256 Hash(Span<const uint8_t> sp) { return Hash(sp.begin(), sp.end()); }
inline uint256 HashOnce(Span<const uint8_t> sp) { return Hash(sp.begin(), sp.end(), true); }

/** Compute the 256-bit hash of the concatenation of two objects. */
template <typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end, const T2 p2begin,
                    const T2 p2end) {
    const uint8_t pblank[1] = {};
    uint256 result{uint256::Uninitialized};
    CHash256()
        .Write(p1begin == p1end ? pblank : (const uint8_t *)&p1begin[0],
               (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const uint8_t *)&p2begin[0],
               (p2end - p2begin) * sizeof(p2begin[0]))
        .Finalize(result.data());
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template <typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end, const T2 p2begin,
                    const T2 p2end, const T3 p3begin, const T3 p3end) {
    const uint8_t pblank[1] = {};
    uint256 result{uint256::Uninitialized};
    CHash256()
        .Write(p1begin == p1end ? pblank : (const uint8_t *)&p1begin[0],
               (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const uint8_t *)&p2begin[0],
               (p2end - p2begin) * sizeof(p2begin[0]))
        .Write(p3begin == p3end ? pblank : (const uint8_t *)&p3begin[0],
               (p3end - p3begin) * sizeof(p3begin[0]))
        .Finalize(result.data());
    return result;
}

/** Compute the 160-bit hash an object. */
template <typename T1> inline uint160 Hash160(const T1 pbegin, const T1 pend) {
    const uint8_t pblank[1] = {};
    uint160 result{uint160::Uninitialized};
    CHash160()
        .Write(pbegin == pend ? pblank : (const uint8_t *)&pbegin[0],
               (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize(result.data());
    return result;
}

/** Compute the 160-bit hash of a vector-like object. */
inline uint160 Hash160(Span<const uint8_t> sp) {
    return Hash160(sp.begin(), sp.end());
}

/** A writer stream (for serialization) that computes a 256-bit hash. */

class CHashWriter {
private:
    CHash256 ctx;

    const int nType;
    const int nVersion;

public:
    CHashWriter(int nTypeIn, int nVersionIn, bool once = false)
        : ctx(once), nType(nTypeIn), nVersion(nVersionIn) {}

    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void write(const char *pch, size_t size) {
        ctx.Write((const uint8_t *)pch, size);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result{uint256::Uninitialized};
        ctx.Finalize(result.data());
        return result;
    }

    void GetHashInPlace(uint8_t buf[CHash256::OUTPUT_SIZE]) { ctx.Finalize(buf); }

    template <typename T> CHashWriter &operator<<(const T &obj) {
        // Serialize to this stream
        bitcoin::Serialize(*this, obj);
        return *this;
    }
};

/**
 * Reads data from an underlying stream, while hashing the read data.
 */

template <typename Source> class CHashVerifier : public CHashWriter {
private:
    Source *source;

public:
    explicit CHashVerifier(Source *source_)
        : CHashWriter(source_->GetType(), source_->GetVersion()),
          source(source_) {}

    void read(char *pch, size_t nSize) {
        source->read(pch, nSize);
        this->write(pch, nSize);
    }

    void ignore(size_t nSize) {
        char data[1024];
        while (nSize > 0) {
            size_t now = std::min<size_t>(nSize, 1024);
            read(data, now);
            nSize -= now;
        }
    }

    template <typename T> CHashVerifier<Source> &operator>>(T &obj) {
        // Unserialize from this stream
        bitcoin::Unserialize(*this, obj);
        return *this;
    }
};

/** Compute the 256-bit hash of an object's serialization. */

template <typename T>
uint256 SerializeHash(const T &obj, int nType = SER_GETHASH,
                      int nVersion = PROTOCOL_VERSION, bool once = false) {
    CHashWriter ss(nType, nVersion, once);
    ss << obj;
    return ss.GetHash();
}

/** Added by Calin to support hashing to QByteArray in-place */
template <typename ByteT, typename T>
std::enable_if_t<std::is_same_v<ByteT, char> || std::is_same_v<ByteT, uint8_t> || std::is_same_v<ByteT, std::byte>>
/* void */ SerializeHashInPlace(ByteT hash[CHash256::OUTPUT_SIZE], const T &obj,
                                int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION, bool once = false) {
    CHashWriter ss(nType, nVersion, once);
    ss << obj;
    ss.GetHashInPlace(reinterpret_cast<uint8_t *>(hash));
}

// MurmurHash3: ultra-fast hash suitable for hash tables but not cryptographically secure
uint32_t MurmurHash3(uint32_t nHashSeed,
                     const uint8_t *pDataToHash, size_t nDataLen /* bytes */);
inline uint32_t MurmurHash3(uint32_t nHashSeed,
                            const std::vector<uint8_t> &vDataToHash) {
    return MurmurHash3(nHashSeed, vDataToHash.data(), vDataToHash.size());
}

void BIP32Hash(const ChainCode &chainCode, uint32_t nChild, uint8_t header,
               const uint8_t data[32], uint8_t output[64]);

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
