// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "crypto/blake2b.h"
#include "crypto/common.h"
#include "hash.h"
#include "streams.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <cstring>

namespace bitcoin {

namespace {
/// BIP340-style tagged hasher, as Bitcoin Core's TaggedHash. Single-SHA256, seeded with sha256(tag) twice.
CHashWriter TaggedHash(const char *tag) {
    CHashWriter ret(SER_GETHASH, PROTOCOL_VERSION, /* once = */ true);
    uint256 tagHash;
    CSHA256().Write(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag)).Finalize(tagHash.data());
    ret.write(tagHash.data(), tagHash.size());
    ret.write(tagHash.data(), tagHash.size());
    return ret;
}

uint256 Blake2b256(const CDataStream &ss) {
    uint256 ret{uint256::Uninitialized};
    if (0 != blake2b_nokey(ret.data(), ret.size(), ss.data(), ss.size()))
        throw std::runtime_error("blake2b_nokey failed");
    return ret;
}
} // namespace

uint256 CBlockHeader::GetHash() const {
    if (!m_header_v2) {
        // Historical algorithm and common case: SHA256d over the 80 bytes.
        return SerializeHash(*this);
    }

    static const uint128 zeros;

    // The pooling miner only learns m_xor_key once it finds a block, so the header commits to the key's hash.
    auto xorKeyHash = TaggedHash("Bitcoin block hash PoW XOR key");
    xorKeyHash << m_xor_key;

    uint256 xorKeyMask;
    if (!m_xor_key.IsNull()) {
        auto w = TaggedHash("Bitcoin block hash PoW XOR mask");
        w << m_xor_key;
        xorKeyMask = w.GetHash();
        // m_xor_key_mask_clear_bits is a uint8_t, so clearBytes is at most 31 and this stays in bounds.
        const unsigned clearBytes = m_xor_key_mask_clear_bits / 8u;
        std::fill_n(xorKeyMask.begin(), clearBytes, uint8_t{0});
        xorKeyMask.begin()[clearBytes] &= uint8_t(0xffu >> (m_xor_key_mask_clear_bits % 8u));
    }

    uint256 prevBlockOrdered;
    std::reverse_copy(hashPrevBlock.begin(), hashPrevBlock.end(), prevBlockOrdered.begin());

    uint256 prevBlockHidden;
    {
        auto w = TaggedHash("Bitcoin prevblock header, hashed");
        w << prevBlockOrdered;
        prevBlockHidden = w.GetHash();
    }

    // These fields are invisible to the mining machine, so the hasher cannot brick itself at some future
    // block version, time or difficulty.
    auto h1 = TaggedHash("Bitcoin block header 1");
    h1 << GetCompleteVersion();
    h1 << prevBlockOrdered;
    h1 << m_height;
    h1 << hashMerkleRoot;
    h1 << GetTimeOnWire();
    h1 << uint8_t{0}; // reserved for extended 40-bit time
    h1 << nBits;
    h1 << uint32_t(m_txcount);
    h1 << m_flags;
    h1 << m_xor_key_mask_clear_bits;
    h1 << xorKeyHash.GetHash();

    auto h2 = TaggedHash("Merge-mining hook");
    h2 << h1.GetHash();
    h2 << zeros << zeros;
    h2 << m_mm_rhs;
    const uint256 h2Hash = h2.GetHash();

    // These fields get sent to mining machines over Stratum v1.
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << uint32_t{0}; // final 3 bytes are part of Sv1 "coinb1"
    ss << h2Hash;      // remainder of Sv1 "coinb1"
    ss << m_extranonce;
    uint256 hash = Blake2b256(ss);

    // Presumably the actual mining ASIC hardware sees these.
    ss.clear();
    switch (m_flags & 3) {
    case 3:
        ss << zeros << zeros;
        [[fallthrough]];
    case 2:
        ss << zeros << zeros << zeros;
        ss << h2Hash << nNonce << m_nonce2 << m_time_offset << m_nonce3 << hash;
        break;
    case 0:
        std::fill_n(prevBlockHidden.begin(), 6, uint8_t{0});
        ss << prevBlockHidden << nNonce << m_nonce2 << m_time_offset << m_nonce3 << hash;
        break;
    case 1:
        ss << nNonce << m_nonce2 << m_nonce3 << m_time_offset << hash << h2Hash;
        break;
    }
    hash = Blake2b256(ss);

    uint256 ret;
    auto *out = ret.end();
    for (size_t i = 0; i < hash.size(); ++i)
        *--out = hash.begin()[i] ^ xorKeyMask.begin()[i];
    return ret;
}

std::string CBlock::ToString(bool fVerbose) const {
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, "
                   "hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, "
                   "vtx=%u)\n",
                   GetHash().ToString(), GetCompleteVersion(), hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString(fVerbose) << "\n";
    }
    return s.str();
}

} // end namespace bitcoin
