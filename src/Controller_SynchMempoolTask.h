//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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
    SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag,
                     const std::unordered_set<TxHash, HashHasher> & ignoreTxns);
    ~SynchMempoolTask() override;
    void process() override;

protected:
    void stop() override;

private:
    const std::shared_ptr<Storage> storage;
    const std::atomic_bool & notifyFlag;
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
    void doDLNextTx();
    void processResults();

    /// Update the lastProgress stat for /stats endpoint
    void updateLastProgress(std::optional<double> val = std::nullopt);

    // Parallel pre-cacher of confirmed utxo spends
    struct Precache;
    friend struct SynchMempoolTask::Precache;
    std::unique_ptr<Precache> precache;
};
