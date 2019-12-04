#ifndef MY_BLOCKPROC_H
#define MY_BLOCKPROC_H

#include "BTC.h"
#include "HashX.h"
#include "TXO.h"

#include "bitcoin/amount.h"
#include "bitcoin/block.h"

#include <QByteArray>

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_set>
#include <vector>

using TxNum = std::uint64_t;
using BlockHeight = std::uint32_t;
using IONum = std::uint16_t;
using TxHash = QByteArray;

struct PreProcessedBlock;
using PreProcessedBlockPtr = std::shared_ptr<PreProcessedBlock>;  ///< For clarity/convenience

using HashHasher = BTC::QByteArrayHashHasher;

namespace BlockProcStatics
{
    extern const TxHash nullhash;
};

/// Note all hashes below are in *reversed* order from bitcoind's internal memory order.
/// The reason for that is so that we have this PreProcessedBlock ready with the right format for putting into the db
/// for later serving up to EX clients.
struct PreProcessedBlock
{
    BlockHeight height = 0; ///< the height (block number) of the block
    size_t sizeBytes = 0; ///< the size of the original serialized block in bytes (not the size of this data structure which is significantly smaller)
    size_t estimatedThisSizeBytes = 0; ///< the estimated size of this data structure -- may be off by a bit but is useful for rough estimation of memory costs of block processing
    /// deserialized header as came in from bitcoind
    bitcoin::CBlockHeader header;

    struct TxInfo {
        TxHash hash; ///< 32 byte txid. These txid's are *reversed* from bitcoind's internal memory order. (so as to be closer to the final hex encoded format).
        IONum nInputs = 0, nOutputs = 0; ///< the number of inputs and outputs in the tx -- all tx's are guaranteed to have <=65535 inputs or outputs currently and for the foreseeable future. If that changes, fixme.
        std::optional<unsigned> input0Index, output0Index; ///< if either of these have a value, they point into the `inputs` and `outputs` arrays below, respectively
    };

    /// The info for all the tx's in the block, in the order in which they appeared in the block.
    std::vector<TxInfo> txInfos;

    struct InputPt {
        unsigned txIdx; ///< index into the `txInfos` vector above for the tx where this input appears
        TxHash prevoutHash; ///< 32-byte prevoutHash.  In *reversed* memory order (hex-encoding ready!) (May be a shallow copy of a byte array in `txInfos` if the prevout tx was in this block.). May be empty if coinbase
        IONum prevoutN; ///< the index in the prevout tx for this input (again, tx's can't have more than 65535 inputs -- if that changes, fixme!)
        std::optional<unsigned> parentTxOutIdx; ///< if the input's prevout was in this block, the index into the `outputs` array declared below, otherwise undefined.
    };

    struct OutPt {
        unsigned txIdx;  ///< this is an index into the `txInfos` vector declared above
        IONum outN; ///< this is an index into the tx's vout vector (*NOT* this class's `outputs`!) (again, tx's can't have more than 65535 inputs -- if that changes, fixme!)
        bitcoin::Amount amount;
    };

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!
    std::vector<OutPt> outputs; ///< all the outpoints for *all* the tx's in this block, in the order they were encountered!

    struct HashXAggregated {
        /// The 32-byte hashX -- in "hex-encode-ready" memory order (that is, reversed).
        HashX hashX;
        /// collection of all outputs in this block that are *TO* this HashX (data items are indices into the `outputs`
        /// array above)
        std::vector<unsigned> outs;
        /// collection of all inputs in this block that are *FROM* this HashX (data items are indices into the `inputs`
        /// arrays above). Note this will only include inputs that were from prevout tx's also in this block.  More
        /// processing is needed by the block processor to fill this array in completely for inputs outside this block.
        std::vector<unsigned> ins;
    };

    /// scriptHashes appearing in all of the outputs (and possibly inputs) in the txs in this block
    std::vector<HashXAggregated> hashXAggregated;

    /*
    // If we decide to track OpReturn:
    struct OpReturn {
        unsigned outIdx; // index into the `outputs` vector declared above
        bitcoin::CScript script;
    };
    std::vector<OpReturn> opreturns;
    */
    // /OpReturn
    // -- /End Data

    // -- Methods:

    // c'tors, etc... note this class is trivially copyable, move constructible, etc etc
    PreProcessedBlock() = default;
    PreProcessedBlock(BlockHeight blockHeight, size_t sizeBytes, const bitcoin::CBlock &b) { fill(blockHeight, sizeBytes, b); }
    /// reset this to empty
    inline void clear() { *this = PreProcessedBlock(); }
    /// fill this block with data from bitcoin's CBlock
    void fill(BlockHeight blockHeight, size_t sizeBytes, const bitcoin::CBlock &b);

    /// convenience factory static method: given a block, return a shard_ptr instance of this struct
    PreProcessedBlockPtr static makeShared(unsigned height, size_t sizeBytes, const bitcoin::CBlock &block);

    // misc helpers --

    /// returns the input# as the input appeared in its tx, given a particular `inputs` array index
    /// We do it this way rather than store this information in the InputPt struct to save on memory
    inline std::optional<IONum> numForInputIdx(unsigned inputIdx) const {
        std::optional<IONum> ret;
        if (inputIdx < inputs.size()) {
            if (const auto & opt = txInfos[inputs[inputIdx].txIdx].input0Index;
                    opt.has_value() && inputIdx >= opt.value()) {
                const unsigned val = inputIdx - opt.value();
                assert(val <= UINT16_MAX); // this should never happen -- all tx's are guaranteed to have <=65535 inputs or outputs currently and for the foreseeable future. If that changes, fixme.
                ret.emplace( IONum(val) );
            }
        }
        return ret;
    }
    /// returns the txHash given an index into the `inputs` array (or a null QByteArray if index is out of range).
    inline const TxHash &txHashForInputIdx(unsigned inputIdx) const {
        if (inputIdx < inputs.size()) {
            if (const auto txIdx = inputs[inputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return BlockProcStatics::nullhash;
    }
    /// returns the txHash given an index into the `outputs` array (or a null QByteArray if index is out of range).
    inline const TxHash &txHashForOutputIdx(unsigned outputIdx) const {
        if (outputIdx < outputs.size()) {
            if (const auto txIdx = outputs[outputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return BlockProcStatics::nullhash;
    }

    /// Given an index into the `outputs` array, return a bool as to whether the output is a coinbase tx
    inline bool isCoinbase(unsigned outputIdx) {
        // since the outputs array is in blockchain order, just check the output is in the first tx. if it is, we
        // know it's coinbase.
        return outputIdx < outputs.size() && !txInfos.empty() && outputIdx < txInfos.front().nOutputs;
    }

    /// debug string
    QString toDebugString() const;
};

struct ProcessedBlock;
using ProcessedBlockPtr = std::shared_ptr<ProcessedBlock>;  ///< For clarity/convenience

/// Similar to PreProcessedBlock above but with txNum and other indicesresolved to map to the global txNum
/// global txOutputNum, global txInputNum, etc
/// Note all hashes below are in *reversed* order from bitcoind's internal memory order.
struct ProcessedBlock
{
    BlockHeight height = 0; ///< the height (block number) of the block
    size_t sizeBytes = 0; ///< the size of the original serialized block in bytes (not the size of this data structure which is significantly smaller)
    size_t estimatedThisSizeBytes = 0; ///< the estimated size of this data structure -- may be off by a bit but is useful for rough estimation of memory costs of block processing
    /// deserialized header as came in from bitcoind
    bitcoin::CBlockHeader header;

    TxNum txNum0 = 0;  ///< the global txNum for the first tx in this block.

    struct TxInfo {
        TxHash hash; ///< 32 byte txid. These txid's are *reversed* from bitcoind's internal memory order. (so as to be closer to the final hex encoded format).
        IONum nInputs = 0, nOutputs = 0; ///< the number of inputs and outputs in the tx -- all tx's are guaranteed to have <=65535 inputs or outputs currently and for the foreseeable future. If that changes, fixme.
        std::optional<unsigned> input0Index, output0Index; ///< if either of these have a value, they point into the `inputs` and `outputs` arrays below, respectively
    };

    /// The info for all the tx's in the block, in the order in which they appeared in the block.
    std::vector<TxInfo> txInfos;

    /// convert to/from an index into the txInfos array above to a global txNum.
    TxNum txIdx2Num(unsigned txIdx) const { return txNum0 + txIdx; }
    unsigned txNum2Idx(TxNum n) const {
        assert(n >= txNum0);
        return unsigned(n - txNum0);
    }

    struct InputPt {
        unsigned txIdx; ///< index into the `txInfos` vector above for the tx where this input appears
        TXO prevOut; //< prevoutTxNum:N, basically
        TxNum prevTxNum; ///< the input's prevout txNum.. may be a tx in this block or in a previous block.
        // Note we don't store the resolved HashX here.. see hashXAggregated below for that
    };

    struct OutPt {
        unsigned txIdx;  ///< this is an index into the `txInfos` vector declared above
        uint16_t outN; ///< this is an index into the tx's vout vector (*NOT* this class's `outputs`!) (again, tx's can't have more than 65535 inputs -- if that changes, fixme!)
        bitcoin::Amount amount;
        // note we don't store the HashX here.. see hashXAggregated below for that
    };

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!
    std::vector<OutPt> outputs; ///< all the outpoints for *all* the tx's in this block, in the order they were encountered!

    struct HashXAggregated {
        /// The 32-byte hashX -- in "hex-encode-ready" memory order (that is, reversed).
        HashX hashX;
        /// collection of all outputs in this block that are *TO* this HashX (data items are indices into the `outputs`
        /// array above)
        std::vector<unsigned> outs;
        /// collection of all inputs in this block that are *FROM* this HashX (data items are indices into the `inputs`
        /// arrays above). (all inputs are resolved)
        std::vector<unsigned> ins;
    };

    /// scriptHashes appearing in all of the outputs (and possibly inputs) in the txs in this block
    std::vector<HashXAggregated> hashXAggregated;

    /*
    // If we decide to track OpReturn:
    struct OpReturn {
        unsigned outIdx; // index into the `outputs` vector declared above
        bitcoin::CScript script;
    };
    std::vector<OpReturn> opreturns;
    */
    // /OpReturn
    // -- /End Data

    // -- Methods:

    // c'tors, etc... note this class is trivially copyable, move constructible, etc etc
    ProcessedBlock() = default;
    ProcessedBlock(const PreProcessedBlock &ppb, const UTXOSet &uset, TxNum txBaseNum) {
        fill(ppb, uset, txBaseNum);
    }
    /// reset this to empty
    inline void clear() { *this = ProcessedBlock(); }
    /// fill this block with data from a pre-processed block plus the UTXO set and other data
    void fill(const PreProcessedBlock &ppb, const UTXOSet &uset, TxNum txBaseNum);

    /// convenience factory static method: given a block, return a shard_ptr instance of this struct
    ProcessedBlockPtr static makeShared(const PreProcessedBlock &ppb, const UTXOSet &uset, TxNum txBaseNum);



    /// WIP: Return a set of scripthashes (HashXs) for each txid. The size of this returned array is the same as
    /// this->txInfos, and each position corresponds to the HashX's touched by that tx.
    std::vector<std::unordered_set<HashX, HashHasher>> hashXTouchedByTx() const;

    /// debug string
    QString toDebugString() const;
};

#endif // MY_BLOCKPROC_H
