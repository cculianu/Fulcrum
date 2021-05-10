//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "DSProof.h"
#include "TXO.h"

#include "bitcoin/amount.h"

#include <QVariantMap>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <type_traits>
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

        bitcoin::Amount fee{bitcoin::Amount::zero()}; ///< we calculate this fee ourselves since in the past I noticed we get a funny value sometimes that's off by 1 or 2 sats --  which I suspect is due limitations of doubles, perhaps?
        unsigned sizeBytes = 0;
        bool hasUnconfirmedParentTx = false; ///< If true, this tx depends on another tx in the mempool. This is not always fixed (confirmedInBlock may change this)
        bool allInputsSpendP2PKH = false; ///< If true, all of the coins this tx spends are p2pkh (used for DSProof subsystem to calculate confidence score)

        /// These are all the txos in this tx. Once set-up, this doesn't change (unlike IOInfo.utxo).
        /// Note that this vector is always sized to the number of txouts in the tx. It may, however, contain !isValid
        /// txo entries if an entry was an OP_RETURN (and thus was not indexed with a scripthash).  Code using this
        /// vector should check if txos[i].isValid().
        std::vector<TXOInfo> txos;

        struct IOInfo {
            /// spends. .confirmedSpends here affects get_balance.
            /// We use std::map here because it wastes less space than robin_hood or unordered_map (and may even be faster than hashing on TXO for small maps)
            std::map<TXO, TXOInfo>
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
            std::set<IONum> utxo; ///< IONums which are indices into the txos vector declared above. We use a set here because it may be faster and use less memory than a hashtable variant.

            bool operator==(const IOInfo &o) const noexcept {
                return     std::tie(  confirmedSpends,   unconfirmedSpends,   utxo)
                        == std::tie(o.confirmedSpends, o.unconfirmedSpends, o.utxo);
            }
            bool operator!=(const IOInfo &o) const noexcept { return !(*this == o); }
        };

        /// This should always contain all the HashX's involved in this tx. Note the use of unordered_map which can
        /// save space vs. robin_hood for immutable maps (which this is, once built)
        std::unordered_map<HashX, IOInfo, HashHasher> hashXs;


        bool operator<(const Tx &o) const noexcept {
            // paranoia -- bools may sometimes not always be 1 or 0 in pathological circumstances.
            const uint8_t nParentMe    =   hasUnconfirmedParentTx ? 1 : 0,
                          nParentOther = o.hasUnconfirmedParentTx ? 1 : 0;
            // always sort the unconf. parent tx's *after* the regular (confirmed parent-only) tx's.
            return std::tie(nParentMe, hash) < std::tie(nParentOther, o.hash);
        }

        bool operator==(const Tx &o) const noexcept {
            return     std::tie(  hash,   sizeBytes,   fee,   hasUnconfirmedParentTx,   txos,   hashXs)
                    == std::tie(o.hash, o.sizeBytes, o.fee, o.hasUnconfirmedParentTx, o.txos, o.hashXs);
        }
        bool operator!=(const Tx &o) const noexcept { return !(*this == o); }

    };

    using TxRef = std::shared_ptr<Tx>;
    /// master mapping of TxHash -> TxRef
    using TxMap = std::unordered_map<TxHash, TxRef, HashHasher>;
    /// ensures an ordering of TxRefs for the set below that are from fewest ancestors -> most ancestors
    struct TxRefOrdering {
        bool operator()(const TxRef &a, const TxRef &b) const {
            if (LIKELY(a && b)) {
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
    /// TxRefOrdering above.  This invariant is maintained in addTxs() as well as confirmedInBlock().
    using HashXTxMap = std::unordered_map<HashX, std::vector<TxRef>, HashHasher>;


    // -- Data members of struct Mempool --
    TxMap txs;
    HashXTxMap hashXTxs;
    DSPs dsps;


    // -- Add to mempool

    /// Used by addNewTxs
    using NewTxsMap = std::unordered_map<TxHash, std::pair<Mempool::TxRef, bitcoin::CTransactionRef>, HashHasher>;
    /// The scriptHashes that were affected by this refresh/synch cycle. Used for notifications.
    using ScriptHashesAffectedSet = std::unordered_set<HashX, HashHasher>;
    /// DB getter -- called to retrieve a utxo's scripthash & amount data from the DB. May throw.
    using GetTXOInfoFromDBFunc = std::function<std::optional<TXOInfo>(const TXO &)>;

    using TxHashSet = std::unordered_set<TxHash, HashHasher>; ///< Used below by Stats & dropTxs()

    /// Results of add or drop -- some statistics for caller.
    struct Stats {
        std::size_t oldSize = 0, newSize = 0;
        std::size_t oldNumAddresses = 0, newNumAddresses = 0;
        std::size_t dspRmCt = 0, dspTxRmCt = 0; // dsp stats: number of dsproofs removed, number of dsp <-> tx links removed (dropTxs, confirmedInBlock updates these)
        TxHashSet dspTxsAffected; // populated by addNewTxs(), dropTxs(), & confirmedInBlock() -- used ultimately bu DSProofSubsMgr to notify linked txs.
        double elapsedMsec = 0.;
    };

    /// Add a batch of tx's that are new (downloaded from bitcoind) and were not previously in this mempool structure.
    ///
    /// Note that all the txs in txsNew *must* be new (must not already exist in this mempool instance).
    /// scriptHashesAffected is updated for all of the new tx's added.
    /// This is called by the SynchMempoolTask in Controller.cpp.
    Stats addNewTxs(ScriptHashesAffectedSet & scriptHashesAffected, // will add to this set
                    const NewTxsMap & txsNew, // txs to add
                    const GetTXOInfoFromDBFunc & getTXOInfo, // callback to get DB confirmed utxos
                    bool TRACE = false);


    // -- Drop from mempool

    /// Drop a bunch of tx's, deleting them from this data structure and reversing the effects of their spends
    /// in the mempool.
    ///
    /// This is called by the SynchMempoolTask whenever the bitcoind mempool has droped tx's. Note that this function
    /// executes much faster if the caller is not dropping any tx's in the middle of an unconfirmed chain.  This is
    /// because descendant txs not in `txids` but that spend from txs in `txids` will also be removed, and they must be
    /// searched for recursively.  Normally when this is called, it's for RBF or full mempool eviction, and such tx's
    /// always drop out as an entire set if in a chain (so this aforementioned perf. penralty is not normally paid).
    ///
    /// Why the penalty?  This is because descendant tx's not appearing in `txids` must be removed since they are
    /// txs that no longer are spending valid inputs (as far as this Mempool instance is aware of, at least).
    ///
    /// `scriptHashesAffected` is modified to add any additional scripthashes not in the set already.
    ///
    /// This function modifies its `txids` argument to expand it to the set of all descendants of txids as well.
    /// (The caller may use this information to know precisely which txids are now gone).
    Stats dropTxs(ScriptHashesAffectedSet & scriptHashesAffected, TxHashSet & txids, bool TRACE = false,
                  std::optional<float> rehashMaxLoadFactor = {});

    /// Convenient alias for the above function which accepts a TxHashSet && temporary.
    Stats dropTxs(ScriptHashesAffectedSet & scriptHashesAffected, TxHashSet && txids, bool TRACE = false,
                  std::optional<float> rehashMaxLoadFactor = {}) {
        return dropTxs(scriptHashesAffected, txids, TRACE, rehashMaxLoadFactor);
    }
    /// Convenient alias for the above function which accepts a const TxHashSet & instead. (But does incur the cost of a copy).
    Stats dropTxs(ScriptHashesAffectedSet & scriptHashesAffected, const TxHashSet & txids, bool TRACE = false,
                  std::optional<float> rehashMaxLoadFactor = {}) {
        return dropTxs(scriptHashesAffected, TxHashSet{txids}, TRACE, rehashMaxLoadFactor);
    }

    using TxHashNumMap = std::unordered_map<TxHash, TxNum, HashHasher>; ///< Used below by confirmedInBlock()

    /// Called by Storage::addBlock -- removes the txids in question, and also reassigns any txs spending them to
    /// "confirmed spends".
    ///
    /// Note this is like dropTxs but doesn't drop child txs, just reassigns their spends. *Only* call this during
    /// block processing when you know for a fact that the txids in `txids` are now confirmed!
    Stats confirmedInBlock(ScriptHashesAffectedSet & scriptHashesAffected,
                           const TxHashNumMap & txidMap, BlockHeight confirmedHeight,
                           bool TRACE = false, std::optional<float> rehashMaxLoadFactor = {});

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


    // -- Misc. utility

    /// Note: clearing the mempool is only done on block undo. Client code should in general just use dropTxs() and/or
    /// confirmedInBlock().
    void clear();


    //  -- Dsp utility

    enum class DspEligibility : uint8_t {
        Unknown = 0, ///< returned if the tx in question is not known to this mempool instance

        Eligible, ///< this tx and all unconfirmed ancestors (if any) support dsproof, but have no extant dsproofs
        HasDSroof, ///< this tx or one of its unconfirmed ancestors has an extant dsproof
        IneligibleThis, ///< this tx does not support dsproof (spends non-P2PKH)
        IneligibleUnconfirmedAncestor, ///< while this tx is eligible, one its unconfirmed ancestors is ineligible (spends non-P2PKH)
        /// the complexity limit for this tx's DAG was hit when walking back to calculate eligibility;
        /// of the ancestors examined, every tx is ok, but some deep ancestor may not be
        LimitHit,
    };
    struct CDEStats {
        size_t maxStage{};
        size_t iters{};
        size_t seenTxs{};
    };
    // may also return "Unknown" aside from the other 5 values
    DspEligibility calculateDspEligibility(const TxHash &, CDEStats *statsOut = nullptr) const;
    // `it` must be a valid iterator in the txs map, returns one of the known 5 members of the above enum
    DspEligibility calculateDspEligibility(TxMap::const_iterator it, CDEStats *statsOut = nullptr) const;

private:
    /// Given a set of txids in this Mempool, grow the set to encompass all descendant tx's that spend
    /// from the initial set.  Will keep iterating until it cannot grow the set any longer.
    /// dropTxs() implicitly calls this.
    std::size_t growTxHashSetToIncludeDescendants(TxHashSet &txids, bool TRACE = false) const;

    /// Actual implementation of same-named function
    std::size_t growTxHashSetToIncludeDescendants(const char *const logprefix, TxHashSet &txids, bool TRACE) const;

    /// Internal use; called by dropTxs and confirmedInBlock to do some book-keeping; returns number of txs removed.
    template <typename SetLike>
    std::enable_if_t<std::is_same_v<SetLike, TxHashSet> || std::is_same_v<SetLike, TxHashNumMap>, std::size_t>
    /*std::size_t*/ rmTxsInHashXTxs_impl(const SetLike &txids, const ScriptHashesAffectedSet &scriptHashesAffected,
                                         bool TRACE, const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort);

    /// Convenient alias for above, accepts a TxHashSet as first-arg
    std::size_t rmTxsInHashXTxs(const TxHashSet &txids, const ScriptHashesAffectedSet &scriptHashesAffected, bool TRACE,
                                const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort = {});

    /// Convenient alias for above, accepts a TxHashNumMap as first-arg
    std::size_t rmTxsInHashXTxs(const TxHashNumMap &txidMap, const ScriptHashesAffectedSet &scriptHashesAffected,
                                bool TRACE, const std::optional<ScriptHashesAffectedSet> &hashXsNeedingSort = {});

    /// Internal: called by dump()
    static QVariantMap dumpTx(const TxRef &tx);

#ifdef ENABLE_TESTS
public:
    /// Returns true if this compares equal to `other`, does a deep compare of the underlying
    /// Tx objects (and not the TxRef shared_ptrs -- but the actual underlying Tx data).
    ///
    /// This is very slow -- used only in the mempool bench.
    bool deepCompareEqual(const Mempool &other, QString *differenceExplanation = nullptr) const;
#endif
};
