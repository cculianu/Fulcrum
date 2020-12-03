//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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

#include "BlockProcTypes.h"
#include "TXO.h"

#include "bitcoin/amount.h"
#include "robin_hood/robin_hood.h"

#include <QVariantMap>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>


/// Models the mempool
struct Mempool
{

    /// This info, with the exception of `hashXs` comes from bitcoind via the "getrawmempool false" RPC call.
    struct Tx
    {
        TxHash hash; ///< in reverse bitcoind order (ready for hex encode), fixed value.
        unsigned sizeBytes = 0;
        bitcoin::Amount fee{bitcoin::Amount::zero()}; ///< we calculate this fee ourselves since in the past I noticed we get a funny value sometimes that's off by 1 or 2 sats --  which I suspect is due limitations of doubles, perhaps?
        bool hasUnconfirmedParentTx = false; ///< If true, this tx depends on another tx in the mempool. This is fixed once calculated properly by the SynchMempoolTask in Controller.cpp

        /// These are all the txos in this tx. Once set-up, this doesn't change (unlike IOInfo.utxo).
        /// Note that this vector is always sized to the number of txouts in the tx. It may, however, contain !isValid
        /// txo entries if an entry was an OP_RETURN (and thus was not indexed with a scripthash).  Code using this
        /// vector should check if txos[i].isValid().
        std::vector<TXOInfo> txos;

        struct IOInfo {
            /// spends. .confirmedSpends here affects get_balance. We use unordered_map here because it wastes less space than robin_hood on fixed-sized maps
            std::unordered_map<TXO, TXOInfo>
                /// Spends of txo's from the db (confirmed) utxoset.
                /// - Items here get _subtracted_ from the "unconfirmed" in RPC get_balance.
                /// - Items appearing here also suppress confirmed utxo items from appearing in RPC listunspent (since they are spent in mempool).
                confirmedSpends,
                /// spends of mempool ancestor txos. Items appearing here will not appear in the ancestor's
                /// IOInfo::utxo map (their insertion here accompanies a deletion of those ancestor items).
                unconfirmedSpends;
            /// UNSPENT outs, this is used to modify listunspent and get_balance. This map may get items deleted as
            /// the mempool evolves if new descendants appear that spend these txos (those descendants will list the
            /// item that gets deleted from here in their own IOInfo::unconfirmedSpends map).
            /// + Items here get _added_ to the "unconfirmed" balance in RPC get_balance.
            std::unordered_set<IONum> utxo; ///< IONums which are indices into the txos vector declared above. We use an unordered_set here because it's more efficient than a regular set, and we don't care about order anyway.
        };

        bool operator<(const Tx &o) const {
            // paranoia -- bools may sometimes not always be 1 or 0 in pathological circumstances.
            const uint8_t nParentMe = hasUnconfirmedParentTx ? 1 : 0,
                          nParentOther = o.hasUnconfirmedParentTx ? 1 : 0;
            // always sort the unconf. parent tx's *after* the regular (confirmed parent-only) tx's.
            if (nParentMe != nParentOther)
                return nParentMe < nParentOther;
            return hash < o.hash;
        }

        /// This should always contain all the HashX's involved in this tx. Note the use of unordered_map which can
        /// save space vs. robin_hood for immutable maps (which this is, once built)
        std::unordered_map<HashX, IOInfo, HashHasher> hashXs;
    };

    using TxRef = std::shared_ptr<Tx>;
    /// master mapping of TxHash -> TxRef
    using TxMap = robin_hood::unordered_flat_map<TxHash, TxRef, HashHasher>;
    /// ensures an ordering of TxRefs for the set below that are from fewest ancestors -> most ancestors
    struct TxRefOrdering {
        bool operator()(const TxRef &a, const TxRef &b) const {
            if (a && b) {
                if (UNLIKELY(a == b))
                    return false;
                return *a < *b;
            }
            else if (!a && b)
                return true;
            return false;
        }
    };
    /// Note: The TxRefs here here point to the same object as the mapped_type in the TxMap above
    /// Note that while the mapped_type is a vector, it is guaranteed to contain unique TxRefs, ordered by
    /// TxRefOrdering above.  This invariant is maintained in Controller.cpp, SynchMempoolTask::processResults().
    using HashXTxMap = robin_hood::unordered_node_map<HashX, std::vector<TxRef>, HashHasher>;


    // -- Data members of struct Mempool --
    TxMap txs;
    HashXTxMap hashXTxs;

protected:
    // disallow clears from external code. Client code should always just use dropTxs.
    inline void clear() {
        // Enforce a little hysteresis about what sizes we may need in the future; reserve 75% of the last size we saw.
        // This means if mempool was full with thousands of txs, we do indeed maintain a largeish hash table for a
        // few blocks, decaying memory usage over time.  We do it this way to eventually recover memory, but to also
        // leave space in case we are in a situation where many tx's are coming in quickly.
        // Note that the default implementation of robin_hood clear() never shrinks its hashtables, and requires
        // explicit calles to reserve() even after a clear().
        const auto txsSize = txs.size(), hxSize = hashXTxs.size();
        txs.clear();
        hashXTxs.clear();
        txs.reserve(size_t(txsSize*0.75));
        hashXTxs.reserve(size_t(hxSize*0.75));
    }
public:

    // -- Add to mempool

    /// Used by addNewTxs
    using NewTxsMap = robin_hood::unordered_flat_map<TxHash, std::pair<Mempool::TxRef, bitcoin::CTransactionRef>, HashHasher>;
    /// The scriptHashes that were affected by this refresh/synch cycle. Used for notifications.
    using ScriptHashesAffectedSet = std::unordered_set<HashX, HashHasher>;
    /// DB getter -- called to retrieve a utxo's scripthash & amount data from the DB. May throw.
    using GetTXOInfoFromDBFunc = std::function<std::optional<TXOInfo>(const TXO &)>;

    /// Results of add or drop -- some statustics for caller.
    struct Stats {
        std::size_t oldSize = 0, newSize = 0;
        std::size_t oldNumAddresses = 0, newNumAddresses = 0;
    };

    /// Add a batch of tx's that are new (downloaded from bitcoind) and were not previously in this mempool structure
    /// Note that all the txs in txsNew *must* be new (must not already exist in this mempool instance).
    /// scriptHashesAffected is updated for all of the new tx's added.
    /// This is called by the SynchMempoolTask in Controller.cpp.
    Stats addNewTxs(ScriptHashesAffectedSet & scriptHashesAffected, // will add to this set
                    const NewTxsMap & txsNew, // txs to add
                    const GetTXOInfoFromDBFunc & getTXOInfo, // callback to get DB confirmed utxos
                    bool TRACE = false);


    // -- Drop from mempool

    using TxHashSet = std::unordered_set<TxHash, HashHasher>;
    /// Drop a bunch of tx's, deleting them from this data structure and reversing the effects of their spends
    /// in the mempool. This is called by the SynchMempoolTask whenever the bitcoind mempool has droped tx's.
    /// Note that this function executes much faster if the caller is not dropping any tx's in the middle of an
    /// unconfirmed chain.  For unconfirmed chains, child tx's in the chain that are not in the specified
    /// txids set will also be dropped (since they are spending txs that no longer are in the mempool).
    Stats dropTxs(ScriptHashesAffectedSet & scriptHashesAffected, const TxHashSet & txids, bool TRACE = false);


    // -- Fee histogram support (used by mempool.get_fee_histogram RPC) --

    struct FeeHistogramItem {
        unsigned feeRate = 0; // in sats/B, quotient truncated to uint.
        unsigned cumulativeSize = 0; // bin size, cumulative bytes
    };
    using FeeHistogramVec = std::vector<FeeHistogramItem>;
    /// This function is potentially going to take a couple of ms at worst on very large mempools.  Even a 1.5k tx
    /// mempool takes under 1 ms on average hardware, so it's very fast. Storage calls this in refreshMempoolHistogram
    /// from a periodic background task kicked off in Controller.
    FeeHistogramVec calcCompactFeeHistogram(double binSize = 1e5 /* binSize in bytes */) const;

    // -- Dump (for JSONesque debug support)

    /// Dump to QVariantMap (used by Controller::debug(), see Controller.cpp)
    QVariantMap dump() const;
};
