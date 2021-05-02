// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <array>
#include "blockhash.h"
#include "transaction.h"
#include "serialize.h"
#include "uint256.h"

typedef std::array<uint8_t, 6> block_time_t;
typedef std::array<uint8_t, 7> block_size_t;

constexpr int32_t EPOCH_NUM_BLOCKS = 5040; // one week
namespace bitcoin {
/**
 * Nodes collect new transactions into a block, hash them into a hash tree, and
 * scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements. When they solve the proof-of-work, they broadcast the block to
 * everyone and the block is added to the block chain. The first transaction in
 * the block is a special one that creates a new coin owned by the creator of
 * the block.
 */
class CBlockHeader {
public:
    /** Hash of block this block is extending, or all zeros for genesis block */
    BlockHash hashPrevBlock;
    /** Target blockhash should meet encoded compactly */
    uint32_t nBits;
    /** Block time of the block encoded little endian */
    block_time_t vTime;
    /** Reserved bytes for future use, all 0 for now */
    uint16_t nReserved;
    /** Nonce for miners to tweak the blockhash */
    uint64_t nNonce;
    /** Version of the bytes that follow; always 0x01 for now */
    uint8_t nHeaderVersion;
    /** Size of the block encoded little endian */
    block_size_t vSize;
    /** Height of the block; length of the chain from genesis */
    int32_t nHeight;
    /**
     * Epochs are 5040 blocks long; each block points to the prev block of the
     * first block within an epoch
     */
    uint256 hashEpochBlock;
    /** Merkle root of the txs in the block */
    uint256 hashMerkleRoot;
    /** Hash of the extended metadata of the block */
    uint256 hashExtendedMetadata;

    CBlockHeader() { SetNull(); }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(hashPrevBlock);
        READWRITE(nBits);
        READWRITE(vTime);
        READWRITE(nReserved);
        READWRITE(nNonce);
        READWRITE(nHeaderVersion);
        READWRITE(vSize);
        READWRITE(nHeight);
        READWRITE(hashEpochBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashExtendedMetadata);
    }

    void SetNull() {
        hashPrevBlock = BlockHash();
        nBits = 0;
        vTime.fill(0);
        nReserved = 0;
        nNonce = 0;
        nHeaderVersion = 0;
        vSize.fill(0);
        nHeight = 0;
        hashEpochBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashExtendedMetadata.SetNull();
    }

    bool IsNull() const { return (nBits == 0); }

    BlockHash GetHash() const;

    /**
     * Block time as advertised in the block header.
     * Might not correspond to actual mined or received time.
     */
    int64_t GetBlockTime() const {
        return uint64_t(vTime[0]) | (uint64_t(vTime[1]) << 8) |
               (uint64_t(vTime[2]) << 16) | (uint64_t(vTime[3]) << 24) |
               (uint64_t(vTime[4]) << 32) | (uint64_t(vTime[5]) << 40);
    }

    /** Set the block time as advertised in the block header. */
    void SetBlockTime(uint64_t nTime) {
        vTime = {{
            uint8_t((nTime & 0x0000000000ff)),
            uint8_t((nTime & 0x00000000ff00) >> 8),
            uint8_t((nTime & 0x000000ff0000) >> 16),
            uint8_t((nTime & 0x0000ff000000) >> 24),
            uint8_t((nTime & 0x00ff00000000) >> 32),
            uint8_t((nTime & 0xff0000000000) >> 40),
        }};
    }

    /**
     * Block size, with full encoding, including header, metadata and txs.
     * This doesn't measure anything, so could diverge from the actual size of
     * an encoded CBlock.
     */
    uint64_t GetSize() const {
        return uint64_t(vSize[0]) | (uint64_t(vSize[1]) << 8) |
               (uint64_t(vSize[2]) << 16) | (uint64_t(vSize[3]) << 24) |
               (uint64_t(vSize[4]) << 32) | (uint64_t(vSize[5]) << 40) |
               (uint64_t(vSize[6]) << 48);
    }

    /** Set the advertised block size in the block header. */
    void SetSize(uint64_t nSize) {
        vSize = {{
            uint8_t((nSize & 0x000000000000ff)),
            uint8_t((nSize & 0x0000000000ff00) >> 8),
            uint8_t((nSize & 0x00000000ff0000) >> 16),
            uint8_t((nSize & 0x000000ff000000) >> 24),
            uint8_t((nSize & 0x0000ff00000000) >> 32),
            uint8_t((nSize & 0x00ff0000000000) >> 40),
            uint8_t((nSize & 0xff000000000000) >> 48),
        }};
    }
};

class CBlockMetadataField {
public:
    uint32_t nFieldId;
    std::vector<uint8_t> vData;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
       inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(nFieldId);
        READWRITE(vData);
    }
};

class CBlock : public CBlockHeader {
public:
    // both for network and disk
    /** Extended metadata for the block as key-value array */
    std::vector<CBlockMetadataField> vMetadata;
    /** Transactions in the block */
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock() { SetNull(); }

    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader *>(this)) = header;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
        inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vMetadata);
        READWRITE(vtx);
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
        vMetadata.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const {
        CBlockHeader header;
        header.hashPrevBlock = hashPrevBlock;
        header.nBits = nBits;
        header.vTime = vTime;
        header.nReserved = nReserved;
        header.nNonce = nNonce;
        header.nHeaderVersion = nHeaderVersion;
        header.vSize = vSize;
        header.nHeight = nHeight;
        header.hashEpochBlock = hashEpochBlock;
        header.hashMerkleRoot = hashMerkleRoot;
        header.hashExtendedMetadata = hashExtendedMetadata;
        return header;
    }

    std::string ToString() const;
};

/**
 * Describes a place in the block chain to another node such that if the other
 * node doesn't have the same branch, it can find a recent common trunk.  The
 * further back it is, the further before the fork it may be.
 */
struct CBlockLocator {
    std::vector<BlockHash> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<BlockHash> &vHaveIn)
        : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(nVersion);
        }
        READWRITE(vHave);
    }

    void SetNull() { vHave.clear(); }

    bool IsNull() const { return vHave.empty(); }
};
}
#endif // BITCOIN_PRIMITIVES_BLOCK_H
