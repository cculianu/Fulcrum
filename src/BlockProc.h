//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

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
#include <unordered_map>
#include <unordered_set>
#include <vector>


struct PreProcessedBlock;
using PreProcessedBlockPtr = std::shared_ptr<PreProcessedBlock>;  ///< For clarity/convenience

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
        IONum nInputs = 0, nOutputs = 0; ///< the number of inputs and outputs in the tx -- all tx's are guaranteed to have <= ~111k inputs or outputs currently and for the foreseeable future. If that changes, fixme.
        std::optional<unsigned> input0Index, output0Index; ///< if either of these have a value, they point into the `inputs` and `outputs` arrays below, respectively
    };

    /// The info for all the tx's in the block, in the order in which they appeared in the block.
    std::vector<TxInfo> txInfos;

    struct OutPt {
        unsigned txIdx = 0;  ///< this is an index into the `txInfos` vector declared above
        IONum outN = 0; ///< this is an index into the tx's vout vector (*NOT* this class's `outputs`!) (again, tx's can't have more than ~111k inputs -- if that changes, fixme!)
        bitcoin::Amount amount;
        std::optional<unsigned> spentInInputIndex; ///< if has_value, the output was spent this block in input index (index into the `inputs` array)
        bitcoin::token::OutputDataPtr tokenDataPtr;
    };

    struct InputPt {
        unsigned txIdx = 0; ///< index into the `txInfos` vector above for the tx where this input appears
        TxHash prevoutHash; ///< 32-byte prevoutHash.  In *reversed* memory order (hex-encoding ready!) (May be a shallow copy of a byte array in `txInfos` if the prevout tx was in this block.). May be empty if coinbase
        IONum prevoutN = 0; ///< the index in the prevout tx for this input (again, tx's can't have more than ~111k inputs -- if that changes, fixme!)
        std::optional<unsigned> parentTxOutIdx; ///< if the input's prevout was in this block, the index into the `outputs` array declared in BlockProcBase, otherwise undefined.
    };

    std::vector<OutPt> outputs; ///< all the outpoints for *all* the tx's in this block, in the order they were encountered!

    std::vector<InputPt> inputs; ///< all the inputs for *all* the tx's in this block, in the order they were encountered!

    /// 'Value' type for the hashXAggregated map below. Contains 2 lists of output and input indices into the `outputs`
    /// and `inputs` arrays present in concrete subclasses.
    struct AggregatedOutsIns {
        /// collection of all outputs in this block that are *TO* a particular HashX (data items are indices into the
        /// `outputs`array above)
        std::vector<unsigned> outs;
        /// collection of all inputs in this block that are *FROM* a particular HashX (data items are indices into the
        /// `inputs` arrays above). Note this will only include inputs that were from prevout tx's also in this block
        /// for PreProcessedBlock instances before final processing (full resolution requires a utxo set).
        std::vector<unsigned> ins;

        /// Tx indices, always sorted. Initially it's just a list of txIdx into the txInfos array but gets transformed
        /// down the block processing pipeline (in addBlock) to be a list of globally-mapped TxNums involving this
        /// HashX.
        std::vector<TxNum> txNumsInvolvingHashX;
    };

    /// Node map preferable here. Even though a flat map uses move construction, it would still have to move ~72
    /// bytes around (3 pointers per std::vector * 3 vectors * 8 bytes per pointer), so the Node* of the node map is
    /// preferred here.
    std::unordered_map<HashX, AggregatedOutsIns, HashHasher> hashXAggregated;

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
    /// Note the coinbase INPUT would just be inputIdx==0 for any particular block. This function just tells you which
    /// *outputs* are coinbase reward OUTPUTS.
    bool isCoinbase(unsigned outputIdx) {
        // since the outputs array is in blockchain order, just check the output is in the first tx. if it is, we
        // know it's coinbase.
        return outputIdx < outputs.size() && !txInfos.empty() && outputIdx < txInfos.front().nOutputs;
    }

    /// returns the input# as the input appeared in its tx, given a particular `inputs` array index
    /// We do it this way rather than store this information in the InputPt struct to save on memory
    std::optional<IONum> numForInputIdx(unsigned inputIdx) const {
        std::optional<IONum> ret;
        if (inputIdx < inputs.size()) {
            if (const auto & opt = txInfos[inputs[inputIdx].txIdx].input0Index;
                    opt.has_value() && inputIdx >= *opt) {
                const unsigned val = inputIdx - opt.value();
                assert(val <= UINT16_MAX); // this should never happen -- all tx's are guaranteed to have <=65535 inputs or outputs currently and for the foreseeable future. If that changes, fixme.
                ret.emplace( IONum(val) );
            }
        }
        return ret;
    }
    /// returns the txHash given an index into the `inputs` array (or a null QByteArray if index is out of range).
    const TxHash &txHashForInputIdx(unsigned inputIdx) const {
        if (inputIdx < inputs.size()) {
            if (const auto txIdx = inputs[inputIdx].txIdx; txIdx < txInfos.size())
                return txInfos[txIdx].hash;
        }
        return nullhash;
    }

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

    /// This is not totally complete until this class has consulted the UTXO set to fill in all inputs.
    std::vector<std::unordered_set<HashX, HashHasher>> hashXsByTx() const;

protected:
    static const TxHash nullhash;
};
