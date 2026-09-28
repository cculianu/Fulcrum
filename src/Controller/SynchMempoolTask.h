//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Controller.h"
#include "Mempool.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_set>

class Storage;

/// Task managed by the Controller class, responsible for synching the mempool from the bitcoin daemon.
struct SynchMempoolTask final : public CtlTask
{
    /// How the task finds out what changed in the bitcoind mempool.
    enum class Mode : uint8_t {
        /// `getrawmempool false`, then diff the txid list against our mempool. This is the classic poll.
        Snapshot,
        /// Like Snapshot, but uses `getrawmempool false true`, which also returns bitcoind's mempool sequence number
        /// (see ZmqSequence.h). The Controller uses this to (re)establish the baseline for ZMQ "sequence" mirroring.
        SnapshotWithSeq,
        /// No `getrawmempool` at all: apply the adds and drops the Controller derived from ZMQ "sequence" events. If
        /// the task must redo (e.g. on a mempool consistency error), it falls back to SnapshotWithSeq.
        Delta,
    };
    struct Plan {
        Mode mode = Mode::Snapshot;
        Mempool::TxHashSet adds, drops; ///< Delta only (see ZmqSequence::Delta for the semantics)
        bool recordDiff = false; ///< SnapshotWithSeq only: record snapshotAppeared & snapshotVanished (see below)
    };

    SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag,
                     const std::unordered_set<TxHash, HashHasher> & ignoreTxns, Plan plan);
    ~SynchMempoolTask() override;
    void process() override;

    // -- Results. The Controller reads these (from its own thread) after success() is emitted.

    /// Set iff this task processed a SnapshotWithSeq reply: the mempool sequence number of the first mempool event not
    /// reflected in the snapshot (and thus now not reflected in our mempool).
    std::optional<uint64_t> snapshotMempoolSeq;
    /// Only populated if plan.recordDiff: the txids that were in the snapshot but not in our mempool, and vice-versa.
    Mempool::TxHashSet snapshotAppeared, snapshotVanished;
    /// Delta only: the number of added txids that were already in our mempool without a preceding removal. This should
    /// never happen if our mirror is exact, so the Controller treats a non-zero value as a reason to resynch.
    std::size_t deltaAnomalies = 0;
    /// The number of txs that could not be downloaded because they left the bitcoind mempool in the meantime (or
    /// because they spend from such a tx).
    std::size_t nFailedDownloads() const { return txsFailedDownload.size(); }
    /// The number of times this task had to start over (see redoFromStart()).
    int nRedos() const { return redoCt; }

protected:
    void stop() override;

private:
    const std::shared_ptr<Storage> storage;
    const std::atomic_bool & notifyFlag;
    Plan plan;
    const size_t maxDLBacklogSize = std::clamp(std::thread::hardware_concurrency(), 2u, 16u /* cap at default work queue limit */);
    Mempool::TxMap txsNeedingDownload, txsWaitingForResponse;
    Mempool::NewTxsMap txsDownloaded;
    std::unordered_set<TxHash, HashHasher> txsFailedDownload, ///< set of tx's dropped due to RBF and/or mempool pressure as we were downloading
                                           txsIgnored; ///< Litecoin only -- MWEB-only txns we are completely ignoring.
    const std::unordered_set<TxHash, HashHasher> txnIgnoreSet; ///< Litecoin only -- comes from Controller::mempoolIgnoreTxns
    unsigned expectedNumTxsDownloaded = 0;
    static constexpr int kRedoCtMax = 5; // if we have to retry this many times, error out.
    static constexpr unsigned kFailedDownloadMax = 50; // if we have more than this many consecutive failures on getrawtransaction, and no successes, abort with error.
    int redoCt = 0;
    const bool TRACE = Trace::isEnabled(); // set this to true to print more debug
    const bool isSegWit; ///< initted in c'tor. If true, deserialize tx's using the optional segwit extensons to the tx format.
    const bool isMimble; ///< initted in c'tor. If true, deserialize tx's using the optional mimble-wimble extensons to the tx format.
    const bool isCashTokens; ///< initted in c'tor. True for BCH, false otherwise. Controls Deserialize rules for txns and blocks.

    /// The scriptHashes that were affected by this refresh/synch cycle. Used for notifications.
    std::unordered_set<HashX, HashHasher> scriptHashesAffected;
    /// The txids in the adds or drops that also have dsproofs associated with them (cumulative across retries, like scriptHashesAffected)
    Mempool::TxHashSet dspTxsAffected;
    /// The txids either added or dropped -- for the txSubsMgr
    std::unordered_set<TxHash, HashHasher> txidsAffected;

    enum class State : uint8_t {
        Start = 0u, AwaitingGrmp, DlTxs, FinishedDlTxs, ProcessingResults
    };
    State state = State::Start;

    void clear();

    /// Called when getrawtransaction errors out or when we dropTxs() and the result is too many txs so we must
    /// do getrawmempool again.  Increments redoCt. Note that if redoCt > kRedoCtMax, will implicitly error out.
    /// Implicitly calls AGAIN().
    void redoFromStart();

    void doGetRawMempool();
    /// Diffs the txid list from `getrawmempool` against our mempool, drops what is gone and queues downloads of what is
    /// new. `mempoolSeq` is the reply's mempool sequence number (SnapshotWithSeq only).
    void processSnapshot(const QVariantList &txidList, std::optional<uint64_t> mempoolSeq, const QString &method,
                         const Tic &tReply);
    /// Delta mode: applies plan.drops and queues downloads of plan.adds, without calling `getrawmempool`.
    void applyDelta();
    /// Queues a new (not yet in our mempool) tx for download.
    void queueNewTx(const TxHash &hash);
    /// Drops `droppedTxs` (all of which must be in our mempool) plus their in-mempool descendants, which are added to
    /// the set. If `exactCount`, dropping more than the requested count is treated as an inconsistency. Returns the
    /// number of txs dropped, or std::nullopt if a redo was scheduled (in which case the caller must return at once).
    std::optional<std::size_t> dropTxsFromMempool(Mempool::TxHashSet &droppedTxs, bool exactCount);
    /// Moves on to the download phase for the txs queued in txsNeedingDownload.
    void beginDownloads(size_t newCt, Mempool::TxHashSet tentativeMempoolTxHashesForPrecacher, bool precacheChecksMempool);
    void doDLNextTx();
    void processResults();

    /// Update the lastProgress stat for /stats endpoint
    void updateLastProgress(std::optional<double> val = std::nullopt);

    // Parallel pre-cacher of confirmed utxo spends
    struct Precache;
    friend struct SynchMempoolTask::Precache;
    std::unique_ptr<Precache> precache;
};
