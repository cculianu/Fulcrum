#ifndef MY_BLOCKPROC_H
#define MY_BLOCKPROC_H

#include "HashX.h"

#include "bitcoin/amount.h"
#include "bitcoin/block.h"

#include <QByteArray>

#include <cassert>
#include <optional>
#include <vector>


/// Note all hashes below are in *reversed* order from bitcoind's internal memory order.
/// The reason for that is so that we have this PreProcessedBlock ready with the right format for putting into the db
/// for later serving up to EX clients.
struct PreProcessedBlock
{
    unsigned height = 0; ///< the height (block nunber) where this block appears
    /// deserialized header as came in from bitcoind
    bitcoin::CBlockHeader header;

    struct TxInfo {
        QByteArray hash; ///< 32 byte txid. These txid's are *reversed* from bitcoind's internal memory order. (so as to be closer to the final hex encoded format).
        unsigned nInputs = 0, nOutputs = 0; ///< the number of inputs and outputs in the tx
        std::optional<unsigned> input0Index, output0Index; ///< if either of these have a value, they point into the `inputs` and `outputs` arrays below, respectively
    };

    /// The txids (32 bytes each) of all tx's in the block, in the order in which they appeared in the block.
    /// These txid's are in bitcoind's internal memory order (non-reversed) (copied from the tx's own GetHash())
    std::vector<TxInfo> txInfos;

    struct InputPt {
        unsigned txIdx; ///< index into the `txInfos` vector above for the tx where this input appears
        QByteArray prevoutHash; ///< 32-byte prevoutHash.  In *reversed* memory order (hex-encoding ready!) (May be a shallow copy of a byte array in `txInfos` if the prevout tx was in this block.). May be empty if coinbase
        unsigned prevoutN; ///< the index in the prevout tx for this input
        std::optional<unsigned> parentTxOutIdx; ///< if the input's prevout was in this block, the index into the `outputs` array declared below, otherwise undefined.
    };

    struct OutPt {
        unsigned txIdx;  ///< this is an index into the `txInfos` vector declared above
        unsigned outN; ///< this is an index into the tx's vout vector (*NOT* this class's `outputs`!)
        bitcoin::Amount amount;
    };

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!
    std::vector<OutPt> outputs; ///< all the outpoints for *all* the tx's in this block, in the order they were encountered!

    struct HashXAggregated {
        HashX hashX;
        /// collection of all outputs in this block that are *TO* this HashX (data items are indices into the `outputs`
        /// array above)
        std::vector<unsigned> outs;
        /// collection of all inputs in this block that are *FROM* this HashX (data items are indices into the `inputs`
        /// arrays above). Note this will only include inputs that were from prevout tx's also in this block.  More
        /// processing is needed by the block processor to fill this array in completely for inputs outside this block.
        std::vector<unsigned> ins;
    };

    /// The 32-byte hashX's of all scriptHashes appearing in all of the outputs in the txs in this block
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
    PreProcessedBlock(unsigned blockHeight, const bitcoin::CBlock &b) { fill(blockHeight, b); }
    /// reset this to empty
    inline void clear() { *this = PreProcessedBlock(); }
    /// fill this block with data from bitcoin's CBlock
    void fill(unsigned blockHeight, const bitcoin::CBlock &b);

    // misc helpers --

    /// returns the input# as the input appeared in its tx, given a particular `inputs` array index
    /// We do it this way rather than store this information in the InputPt struct to save on memory
    inline std::optional<unsigned> numForInputIdx(unsigned inputIdx) const {
        std::optional<unsigned> ret;
        if (inputIdx < inputs.size()) {
            if (const auto & opt = txInfos[inputs[inputIdx].txIdx].input0Index;
                    opt.has_value() && inputIdx >= opt.value())
                ret = inputIdx - opt.value();
        }
        return ret;
    }
    /// returns the txHash given an index into the `inputs` array (or a null QByteArray if index is out of range).
    inline const QByteArray &txHashForInputIdx(unsigned inputIdx) const {
        if (inputIdx < inputs.size()) {
            if (const auto txIdx = inputs[inputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return staticnull;
    }
    /// returns the txHash given an index into the `outputs` array (or a null QByteArray if index is out of range).
    inline const QByteArray &txHashForOutputIdx(unsigned outputIdx) const {
        if (outputIdx < outputs.size()) {
            if (const auto txIdx = outputs[outputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return staticnull;
    }

    /// Given an index into the `outputs` array, return a bool as to whether the output is a coinbase tx
    inline bool isCoinbase(unsigned outputIdx) {
        // since the outputs array is in blockchain order, just check the output is in the first tx. if it is, we
        // know it's coinbase.
        return outputIdx < outputs.size() && !txInfos.empty() && outputIdx < txInfos.front().nOutputs;
    }

    /// debug string
    QString toDebugString() const;
private:
    static const QByteArray staticnull;
};

using PreProcessedBlockPtr = std::shared_ptr<PreProcessedBlock>;  ///< For clarity/convenience

#endif // MY_BLOCKPROC_H
