// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "transaction.h"
#include "serialize.h"
#include "uint256.h"

#include <utility>

namespace bitcoin {
/**
 * Nodes collect new transactions into a block, hash them into a hash tree, and
 * scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block to
 * everyone and the block is added to the block chain. The first transaction in
 * the block is a special one that creates a new coin owned by the creator of
 * the block.
 */
namespace BlockHeaderFlag {
    inline constexpr uint8_t UseTimeOffset = 4;
}

class CBlockHeader {
public:
    /// Set in the on-wire version field to indicate the extended (BLAKE2b) header.
    static constexpr uint32_t VERSION_HEADER_V2_FLAG = 0x80000000u;
    /// Serialized size of a legacy (SHA256d) header.
    static constexpr size_t V1_SIZE = 80;
    /// Serialized size of an extended (BLAKE2b) header.
    static constexpr size_t V2_SIZE = 164;

    // header
    int32_t nVersion; ///< excludes VERSION_HEADER_V2_FLAG; see GetCompleteVersion()
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime; ///< for v2 headers this is not what appears on the wire; see GetTimeOnWire()
    uint32_t nBits;
    uint32_t nNonce;

    // extended (BLAKE2b) header fields -- all 0/null unless m_header_v2
    bool m_header_v2;
    uint32_t m_nonce2, m_nonce3; ///< additional PoW/ASIC grinding nonces
    uint128 m_extranonce; ///< Stratum v1 extranonce
    uint32_t m_time_offset;
    uint16_t m_txcount; ///< transaction count commitment (the fix for CVE-2017-12842)
    uint8_t m_flags;
    uint8_t m_xor_key_mask_clear_bits;
    uint128 m_xor_key;
    int32_t m_height; ///< block height committed to by the header itself
    uint256 m_mm_rhs; ///< merge-mining hook

    CBlockHeader() noexcept { SetNull(); }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        uint32_t v, timeOnWire;
        SER_WRITE(obj, v = obj.GetCompleteVersion());
        SER_WRITE(obj, timeOnWire = obj.GetTimeOnWire());
        READWRITE(v, obj.hashPrevBlock, obj.hashMerkleRoot, timeOnWire, obj.nBits, obj.nNonce);
        SER_READ(obj, obj.m_header_v2 = v & VERSION_HEADER_V2_FLAG);
        SER_READ(obj, obj.nVersion = int32_t(v & ~VERSION_HEADER_V2_FLAG));
        if (obj.m_header_v2) {
            READWRITE(obj.m_nonce2, obj.m_nonce3, obj.m_extranonce, obj.m_time_offset, obj.m_txcount,
                      obj.m_flags, obj.m_xor_key_mask_clear_bits, obj.m_xor_key, obj.m_height, obj.m_mm_rhs);
        } else {
            SER_READ(obj, obj.SetV2FieldsNull());
        }
        SER_READ(obj, obj.nTime = timeOnWire
                                  + ((obj.m_flags & BlockHeaderFlag::UseTimeOffset) ? obj.m_time_offset : 0u));
    }

    void SetV2FieldsNull() noexcept {
        m_header_v2 = false;
        m_nonce2 = m_nonce3 = 0u;
        m_extranonce.SetNull();
        m_time_offset = 0u;
        m_txcount = 0u;
        m_flags = 0u;
        m_xor_key_mask_clear_bits = 0u;
        m_xor_key.SetNull();
        m_height = 0;
        m_mm_rhs.SetNull();
    }

    void SetNull() noexcept {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0u;
        nBits = 0u;
        nNonce = 0u;
        SetV2FieldsNull();
    }

    bool IsNull() const noexcept { return nBits == 0; }

    /// The version as it appears on the wire, including the extended-header flag.
    uint32_t GetCompleteVersion() const noexcept {
        return (m_header_v2 ? VERSION_HEADER_V2_FLAG : 0u) | (uint32_t(nVersion) & ~VERSION_HEADER_V2_FLAG);
    }

    /// The block time as it appears on the wire, which a v2 header may carry offset by m_time_offset.
    uint32_t GetTimeOnWire() const noexcept {
        if (!(m_flags & BlockHeaderFlag::UseTimeOffset)) return nTime;
        return nTime - m_time_offset;
    }

    /// The serialized size of this header.
    size_t GetSerializedSize() const noexcept { return m_header_v2 ? V2_SIZE : V1_SIZE; }

    uint256 GetHash() const;

    int64_t GetBlockTime() const noexcept { return int64_t(nTime); }
};

class CBlock : public CBlockHeader {
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    /// Litecoin only
    litecoin_bits::MimbleBlobPtr mw_blob;

    // memory only
    mutable bool fChecked;

    CBlock() noexcept { SetNull(); }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj) {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        // Litecoin only -- Deserialize the mimble-wimble blob at the end under certain conditions (post-activation).
        if constexpr (ser_action.ForRead()) obj.mw_blob.reset();
        if (s.GetVersion() & SERIALIZE_TRANSACTION_USE_MWEB && obj.vtx.size() >= 2 && obj.vtx.back()->IsHogEx()) {
            if constexpr (ser_action.ForRead()) {
                obj.mw_blob = litecoin_bits::EatBlockMimbleBlob(s);
            } else {
                if (obj.mw_blob) {
                    s.write(reinterpret_cast<const char *>(std::as_const(*obj.mw_blob).data()), obj.mw_blob->size());
                }
            }
        }
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        mw_blob.reset();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const { return *this; }

    std::string ToString(bool fVerbose = false) const;
};

/**
 * Describes a place in the block chain to another node such that if the other
 * node doesn't have the same branch, it can find a recent common trunk.  The
 * further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<uint256> vHave;

    constexpr CBlockLocator() noexcept {}

    explicit CBlockLocator(const std::vector<uint256> &vHaveIn)
        : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};

} // end namespace bitcoin
