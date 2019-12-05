#ifndef MY_BLOCKPROC_H
#define MY_BLOCKPROC_H

#include "BTC.h"
#include "BlockProcTypes.h"
#include "Common.h"
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


/// Note all hashes below are in *reversed* order from bitcoind's internal memory order.
/// The reason for that is so that we have this PreProcessedBlock ready with the right format for putting into the db
/// for later serving up to EX clients.
struct BlockProcBase
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

    struct OutPt {
        unsigned txIdx = 0;  ///< this is an index into the `txInfos` vector declared above
        IONum outN = 0; ///< this is an index into the tx's vout vector (*NOT* this class's `outputs`!) (again, tx's can't have more than 65535 inputs -- if that changes, fixme!)
        bitcoin::Amount amount;
    };

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

    unsigned nOpReturns = 0; ///< just keep a count of the number of opreturn outputs encountered in the block (used by sanity checkers)

    // -- Methods:

    // misc helpers --

    /// returns the txHash given an index into the `outputs` array (or a null QByteArray if index is out of range).
    const TxHash &txHashForOutputIdx(unsigned outputIdx) const {
        if (outputIdx < outputs.size()) {
            if (const auto txIdx = outputs[outputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return nullhash;
    }

    /// Given an index into the `outputs` array, return a bool as to whether the output is a coinbase tx
    bool isCoinbase(unsigned outputIdx) {
        // since the outputs array is in blockchain order, just check the output is in the first tx. if it is, we
        // know it's coinbase.
        return outputIdx < outputs.size() && !txInfos.empty() && outputIdx < txInfos.front().nOutputs;
    }

    /// returns the input# as the input appeared in its tx, given a particular `inputs` array index
    /// We do it this way rather than store this information in the InputPt struct to save on memory
    template <typename InputPt>
    std::optional<IONum> numForInputIdx(const std::vector<InputPt> & inputs, unsigned inputIdx) const {
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
    template <typename InputPt>
    const TxHash &txHashForInputIdx(const std::vector<InputPt> & inputs, unsigned inputIdx) const {
        if (inputIdx < inputs.size()) {
            if (const auto txIdx = inputs[inputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return nullhash;
    }

    template <typename InputPt>
    void sortHashXAggregated(const std::vector<InputPt> & inputs) {
        // sort hashXAggregated by min(output_txid, input_txid) (basically earliest first)
        std::sort(hashXAggregated.begin(), hashXAggregated.end(), [this, &inputs](const HashXAggregated &a, const HashXAggregated &b) -> bool {
            if (a.hashX == b.hashX) return false;
            unsigned a_outTxid0 = a.outs.empty() ? UINT_MAX : outputs[a.outs.front()].txIdx,
                     b_outTxid0 = b.outs.empty() ? UINT_MAX : outputs[b.outs.front()].txIdx,
                     a_inTxid0 = a.ins.empty() ? UINT_MAX : inputs[a.ins.front()].txIdx,
                     b_inTxid0 = b.ins.empty() ? UINT_MAX : inputs[b.ins.front()].txIdx;
            return std::min(a_outTxid0, a_inTxid0) < std::min(b_outTxid0, b_inTxid0);
        });
    }
protected:
    BlockProcBase() = default;
    static const TxHash nullhash;
};


struct PreProcessedBlock;
using PreProcessedBlockPtr = std::shared_ptr<PreProcessedBlock>;  ///< For clarity/convenience

struct PreProcessedBlock : public BlockProcBase
{
    struct InputPt {
        unsigned txIdx = 0; ///< index into the `txInfos` vector above for the tx where this input appears
        TxHash prevoutHash; ///< 32-byte prevoutHash.  In *reversed* memory order (hex-encoding ready!) (May be a shallow copy of a byte array in `txInfos` if the prevout tx was in this block.). May be empty if coinbase
        IONum prevoutN = 0; ///< the index in the prevout tx for this input (again, tx's can't have more than 65535 inputs -- if that changes, fixme!)
        std::optional<unsigned> parentTxOutIdx; ///< if the input's prevout was in this block, the index into the `outputs` array declared in BlockProcBase, otherwise undefined.
    };

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!

    // -- Methods:

    // c'tors, etc... note this class is trivially copyable, move constructible, etc etc
    PreProcessedBlock() = default;
    PreProcessedBlock(BlockHeight bheight, size_t rawBlockSizeBytes, const bitcoin::CBlock &b) { fill(bheight, rawBlockSizeBytes, b); }
    /// reset this to empty
    inline void clear() { *this = PreProcessedBlock(); }
    /// fill this block with data from bitcoin's CBlock
    void fill(BlockHeight blockHeight, size_t rawSizeBytes, const bitcoin::CBlock &b);

    /// convenience factory static method: given a block, return a shard_ptr instance of this struct
    static PreProcessedBlockPtr makeShared(unsigned height, size_t sizeBytes, const bitcoin::CBlock &block);

    /// debug string
    QString toDebugString() const;
};


struct ProcessedBlock;
using ProcessedBlockPtr = std::shared_ptr<ProcessedBlock>;  ///< For clarity/convenience

/// Similar to PreProcessedBlock above but with txNum added as a member as well as all inputs having
/// their prevTxNum resolved to a 'TxNum' either in this block or in a previous block.
/// Constructing an instance of this class requires the UTXOSet, a txHash -> txNum resolver, as well as a TxNum for tx0.
struct ProcessedBlock : public BlockProcBase
{
    struct InputPt {
        unsigned txIdx = 0; ///< index into the `txInfos` vector above for the tx where this input appears
        TXO prevOut; //< prevoutTxNum:N, basically -- note prevoutTxNum may or may not be in this block!
        // Note we don't store the resolved HashX here.. see hashXAggregated member for that information
    };

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!

    TxNum txNum0 = 0;  ///< the global txNum for the first tx in this block.

    /// convert to/from an index into the txInfos array above to a global txNum.
    inline TxNum txIdx2Num(unsigned txIdx) const { return txNum0 + txIdx; }
    inline unsigned txNum2Idx(TxNum n) const { assert(n >= txNum0); return unsigned(n - txNum0); }

    /// -- Exception thrown by constructor if it cannot resolve inputs given the passed-in utxo set
    struct CannotResolveInputError : public Exception { using Exception::Exception; ~CannotResolveInputError(); };
    // -- Methods:

    /// the only c'tor -- note this may throw CannotResolveInputError
    ProcessedBlock(TxNum txBaseNum,
                   const PreProcessedBlock &ppb,
                   const TxHash2NumResolver &resolverFunc,
                   const UTXOSet &uset) noexcept(false);

    /// convenience factory static method: given a block, return a shard_ptr instance of this struct -- may throw CannotResolveInputError
    static
    ProcessedBlockPtr makeShared(TxNum txBaseNum,
                                 const PreProcessedBlock &ppb,
                                 const TxHash2NumResolver &resolverFunc,
                                 const UTXOSet &uset) noexcept(false); // may throw

    /// WIP: Return a set of scripthashes (HashXs) for each txid. The size of this returned array is the same as
    /// this->txInfos, and each position corresponds to the HashX's touched by that tx.
    std::vector<std::unordered_set<HashX, HashHasher>> hashXTouchedByTx() const;

    /// debug string
    QString toDebugString(const Num2TxHashResolver &, const UTXOSet &uset) const;
};

#endif // MY_BLOCKPROC_H
