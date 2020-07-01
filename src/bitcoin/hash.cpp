// Copyright (c) 2013-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hash.h"

#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

namespace bitcoin {

inline uint32_t ROTL32(uint32_t x, int8_t r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t MurmurHash3(uint32_t nHashSeed,
                     const uint8_t *pDataToHash, size_t nDataLen) {

    // The following is MurmurHash3 (x86_32), see
    // http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    uint32_t h1 = nHashSeed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = nDataLen / 4;

    //----------
    // body
    const uint8_t *const blocks = pDataToHash;

    for (int i = 0; i < nblocks; ++i) {
        uint32_t k1 = ReadLE32(blocks + i * 4);

        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail
    const uint8_t *tail = blocks + nblocks * 4;

    uint32_t k1 = 0;

    switch (nDataLen & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        [[fallthrough]];
        // FALLTHROUGH
        case 2:
            k1 ^= tail[1] << 8;
        [[fallthrough]];
        // FALLTHROUGH
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = ROTL32(k1, 15);
            k1 *= c2;
            h1 ^= k1;
    }

    //----------
    // finalization
    h1 ^= nDataLen;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}


void BIP32Hash(const ChainCode &chainCode, uint32_t nChild, uint8_t header,
               const uint8_t data[32], uint8_t output[64]) {
    uint8_t num[4];
    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >> 8) & 0xFF;
    num[3] = (nChild >> 0) & 0xFF;
    CHMAC_SHA512(chainCode.begin(), chainCode.size())
        .Write(&header, 1)
        .Write(data, 32)
        .Write(num, 4)
        .Finalize(output);
}


} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
