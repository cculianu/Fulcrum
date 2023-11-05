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
#include "Controller_SynchMempoolTask.h"

#include "BTC.h"
#include "Storage.h"
#include "SubsMgr.h"
#include "TXO.h"
#include "Util.h"

#include "bitcoin/rpc/protocol.h" // for RPC_INVALID_ADDRESS_OR_KEY
#include "bitcoin/transaction.h"

#include <QString>
#include <QThread>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>


/// --- Pre-Cache thread mechanism ---
/// Precache the confirmed spends with the mempool lock held in shared mode, for concurrency during mempool synch.
struct SynchMempoolTask::Precache {
    Precache(SynchMempoolTask &parent_) : parent{parent_} {}
    ~Precache() { stopThread(); /* paranoia */ }
    SynchMempoolTask &parent;

    using ConfirmedSpendCache = std::unordered_map<TXO, std::optional<TXOInfo>>;
    ConfirmedSpendCache cache; ///< written-to by the precache thread, when done, read by parent object in processResults()
    std::condition_variable cond;
    std::mutex mut;
    std::vector<bitcoin::CTransactionRef> workQueue; ///< guarded by mut, signaled by cond
    std::atomic_bool stopFlag = false, doneSubmittingWorkFlag = false, threadIsRunning = false;
    std::thread thread;

    void startThread(size_t reserve, Mempool::TxHashSet tentativeMempoolTxHashes);
    void waitUntilDone();
    void stopThread();
    void submitWork(const bitcoin::CTransactionRef &tx);
    void threadFunc(size_t reserve, Mempool::TxHashSet tentativeMempoolTxHashes);
};

SynchMempoolTask::SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag,
                                   const std::unordered_set<TxHash, HashHasher> & ignoreTxns)
    : CtlTask(ctl_, "SynchMempool"), storage(storage), notifyFlag(notifyFlag),
      txnIgnoreSet(ignoreTxns), isSegWit(ctl_->isSegWitCoin()), isMimble(ctl_->isMimbleWimbleCoin()),
      isCashTokens(ctl_->isBCHCoin()), precache{std::make_unique<Precache>(*this)}
{
    scriptHashesAffected.reserve(SubsMgr::kRecommendedPendingNotificationsReserveSize);
    txidsAffected.reserve(SubsMgr::kRecommendedPendingNotificationsReserveSize);
}

SynchMempoolTask::~SynchMempoolTask()
{
    stop(); // cleanup
    if (notifyFlag.load()) { // this is false until Controller enables the servers that listen for connections
        if (!scriptHashesAffected.empty()) {
            // notify status change for affected sh's, regardless of how this task exited (this catches corner cases
            // where we queued up some notifications and then we died on a retry due to errors from bitcoind)
            storage->subs()->enqueueNotifications(std::move(scriptHashesAffected));
        }
        if (!dspTxsAffected.empty()) {
            DebugM(objectName(), ": dspTxsAffected: ", dspTxsAffected.size());
            storage->dspSubs()->enqueueNotifications(std::move(dspTxsAffected));
        }
        if (!txidsAffected.empty()) {
            storage->txSubs()->enqueueNotifications(std::move(txidsAffected));
        }
    }

    if (elapsed.secs() >= 1.0) {
        // if total runtime for task >1s, log for debug
        DebugM(objectName(), " elapsed total: ", elapsed.secsStr(), " secs");
    }
}

void SynchMempoolTask::clear() {
    state = State::Start;
    txsNeedingDownload.clear(); txsWaitingForResponse.clear(); txsDownloaded.clear(); txsFailedDownload.clear();
    txsIgnored.clear();
    expectedNumTxsDownloaded = 0;
    lastProgress = 0.;
    precache->stopThread();
    // Note: we don't clear "scriptHashesAffected" intentionally in case we are retrying. We want to accumulate
    // all the droppedTx scripthashes for each retry, so we never clear the set.
    // Note 2: we also never clear the redoCt since that counter needs to maintain state to abort too many redos.
    // Note 3: we also never clear dspTxsAffected
    // Note 4: we never clear txidsAffected
}

void SynchMempoolTask::Precache::startThread(const size_t reserve, Mempool::TxHashSet tentativeMempoolTxHashes)
{
    stopThread();
    threadIsRunning = true;
    thread = std::thread([this, reserve, txHashes = std::move(tentativeMempoolTxHashes)]() mutable {
        Defer d([this]{ threadIsRunning = false; });
        threadFunc(reserve, std::move(txHashes));
    });
}

void SynchMempoolTask::Precache::stopThread()
{
    if (thread.joinable()) {
        stopFlag = true;
        cond.notify_all();
        thread.join();
    }
    std::unique_lock g(mut); // keep TSAN happy
    doneSubmittingWorkFlag = stopFlag = threadIsRunning = false;
    workQueue.clear();
}

void SynchMempoolTask::Precache::waitUntilDone()
{
    if (thread.joinable()) {
        Tic t0;
        doneSubmittingWorkFlag = true;
        cond.notify_all();
        thread.join();
        if (const double el = t0.msec<double>(); el >= 500.)
            DebugM("Waited ", QString::number(el, 'f', 3), " msec for precache thread to finish");
    }
}

void SynchMempoolTask::Precache::submitWork(const bitcoin::CTransactionRef &tx)
{
    assert(threadIsRunning);
    {
        std::unique_lock g(mut);
        workQueue.emplace_back(tx);
    }
    cond.notify_one();
}

void SynchMempoolTask::Precache::threadFunc(const size_t reserve, const Mempool::TxHashSet tentativeMempoolTxHashes)
{
    if (QThread *t = QThread::currentThread(); t && t != parent.thread() && t != qApp->thread()) {
        t->setObjectName("SyncMempoolPreCache");
    } else {
        Fatal() << __func__ << ": Expected this function to run in its own thread!";
        return;
    }
    DebugM("Thread started");
    size_t tot = 0u, ctr = 0u;
    Tic t0;
    double tProc = 0.;
    Defer d([&ctr, &tot, &t0, &tProc] {
        DebugM("Precached ", ctr, "/" , tot, " inputs in ", t0.msecStr(), " msec, of which ",
               QString::number(tProc, 'f', 3), " msec was spent processing, thread exiting.");
    });
    if (reserve && reserve < cache.bucket_count()) cache.reserve(reserve);
    auto pred = [this] { return !workQueue.empty() || stopFlag.load() || doneSubmittingWorkFlag.load(); };
    std::vector<bitcoin::CTransactionRef> txns;
    while (!stopFlag) {
        txns.clear();
        {
            std::unique_lock g(mut);
            cond.wait(g, pred);
            txns.swap(workQueue);
            if (stopFlag) return;
        }
        // If finished processing work, exit thread.
        if (doneSubmittingWorkFlag && txns.empty()) return;
        // Otherwise process enqueued precache lookups
        Tic t1;
        for (const auto & tx : txns) {
            for (const auto & in : tx->vin) {
                const TXO txo{BTC::Hash2ByteArrayRev(in.prevout.GetTxId()), IONum(in.prevout.GetN())};
                ++tot;
                if (tentativeMempoolTxHashes.find(txo.txHash) != tentativeMempoolTxHashes.end())
                    continue; // unconfirmed spend, we don't pre-cache this, continue
                // if doesn't appear to be in mempool, look it up in the db and cache the resulting answer
                // may throw on very low level db error; returns nullopt if not found (may be not found for mempool txn)
                try {
                    // we intentionally use unordered_map::operator[] here to overwrite existing (if any)
                    const auto & opt = cache[txo] = parent.storage->utxoGetFromDB(txo, false);
                    if (!opt.has_value()) {
                        // Potential race-condition with bitcoind confirming blocks before we realized it,
                        // and then a mempool txn appearing refering to a txn that was block-only.
                        // Signal error and on retry things should settle ok.
                        Warning() << __func__ << ": Unable to find prevout " << txo.toString()
                                  << " in DB for tx " << tx->GetId().ToString()
                                  << " (possibly a block arrived while synching mempool, will retry)";
                        emit parent.errored();
                        return;
                    }
                    ++ctr;
                } catch (const std::exception & e) {
                    Error() << __func__ << ": Got low-level DB error retrieving " << txo.toString() << ": " << e.what();
                    emit parent.errored();
                    return;
                }
            }
        }
        tProc += t1.msec<double>();
    }
}

void SynchMempoolTask::stop()
{
    precache->stopThread();
    CtlTask::stop(); // call superclass
}

void SynchMempoolTask::updateLastProgress(std::optional<double> val)
{
    double p;
    if (val) p = *val;
    else p = 0.5 * (txsDownloaded.size() + txsFailedDownload.size() + txsIgnored.size()) / std::max(double(expectedNumTxsDownloaded), 1.0);
    lastProgress = std::clamp(p, 0.0, 1.0);
}

void SynchMempoolTask::redoFromStart()
{
    clear();
    if (++redoCt > kRedoCtMax) {
        Error() << "SyncMempoolTask redo count exceeded (" << redoCt << "), aborting task (elapsed: " <<  elapsed.secsStr() << " secs)";
        emit errored();
        return;
    }
    AGAIN();
}

void SynchMempoolTask::process()
{
    if (ctl->isStopping())
        return; // short-circuit early return if controller is stopping
    if (state == State::Start) {
        state = State::AwaitingGrmp;
        doGetRawMempool();
    } else if (state == State::DlTxs) {
        updateLastProgress();
        if (!txsNeedingDownload.empty())
            doDLNextTx();
        else if (txsWaitingForResponse.empty()) {
            state = State::FinishedDlTxs;
            process(); // direct-call to self again for perf, to take the last if condition
            return;
        }
    } else if (state == State::FinishedDlTxs) {
        state = State::ProcessingResults;
        try {
            processResults();
        } catch (const std::exception & e) {
            Error() << "Caught exception when processing mempool tx's: " << e.what();
            emit errored();
        }
    }
}

void SynchMempoolTask::doGetRawMempool()
{
    /// We use the "getrawmempool false" (nonverbose) call to get the initial list of mempool tx's.  This is the
    /// most efficient.  With full mempools bitcoind CPU usage could spike to 100% if we use the verbose mode.
    /// It turns out we don't need that verbose data anyway (such as a full ancestor count) -- it's enough to have a bool
    /// flag for "has unconfirmed parent tx", and be done with it.  Everything else we can calculate.
    submitRequest("getrawmempool", {false}, [this, t0 = Tic()](const RPC::Message & resp) mutable {
        t0.fin();
        const Tic t1;
        std::size_t newCt = 0, droppedCt = 0, ignoredCt = 0;
        const QVariantList txidList = resp.result().toList();
        Mempool::TxHashSet droppedTxs, tentativeMempoolTxHashesForPrecacher;
        {
            // Grab the mempool data struct and lock it *shared*.  This improves performance vs. an exclusive lock here.
            // Since we aren't modifying it.. this is fine.  We are the only subsystem that ever modifies it anyway, so
            // invariants will hold even if we release the lock early, regardless.
            auto [mempool, lock] = storage->mempool();
            droppedTxs = tentativeMempoolTxHashesForPrecacher = Util::keySet<Mempool::TxHashSet>(mempool.txs);
        }
        for (const auto & var : txidList) {
            const auto txidHex = var.toString().trimmed().toLower();
            const TxHash hash = Util::ParseHexFast(txidHex.toUtf8());
            if (hash.length() != HashLen) {
                Error() << resp.method << ": got an invalid tx hash: " << txidHex;
                emit errored();
                return;
            }
            if (auto it = droppedTxs.find(hash); it != droppedTxs.end()) {
                droppedTxs.erase(it); // mark this tx as "not dropped" since it was in the mempool before and is in the mempool now.
                if (TRACE) Debug() << "Existing mempool tx: " << hash.toHex();
            } else {
                if (txnIgnoreSet.find(hash) != txnIgnoreSet.end()) {
                    // suppressed txn (in ignore set)
                    if (TRACE) Debug() << "Ignored mempool tx: " << hash.toHex();
                    ++ignoredCt;
                } else {
                    // new txn
                    if (TRACE) Debug() << "New mempool tx: " << hash.toHex();
                    tentativeMempoolTxHashesForPrecacher.emplace(hash);
                    ++newCt;
                    const auto & [it2, inserted] = txsNeedingDownload.try_emplace(hash, std::make_shared<Mempool::Tx>());
                    Mempool::TxRef & tx = it2->second;
                    if (UNLIKELY(!inserted)) {
                        // this should never happen
                        Error() << "FIXME: Error inserting tx into txsNeedingDownload map, already there! TxId: " << hash.toHex();
                        assert(bool(tx));
                    }
                    tx->hashXs.max_load_factor(.9); // hopefully this will save some memory by expicitly setting max table size to 90%
                    tx->hash = hash;
                }
            }
        }
        if (!droppedTxs.empty()) {
            const auto expectedDropCt = droppedTxs.size();
            // Some txs were dropped, update mempool with the drops, grabbing the lock exclusively.
            // Note the release and re-acquisition of the lock should be ok since this Controller
            // thread is the only thread that ever modifies the mempool, so a coherent view of the
            // mempool is the case here even after having released and re-acquired the lock.
            Mempool::ScriptHashesAffectedSet affected; affected.reserve(32);
            Mempool::Stats res;
            // exclusively-locked scope, do minimal work here
            {
                auto [mempool, lock] = storage->mutableMempool();
                res = mempool.dropTxs(affected, droppedTxs, TRACE);
            } // release lock

            // update this set too for txSubsMgr
            txidsAffected.insert(droppedTxs.begin(), droppedTxs.end());

            // do bookkeeping, maybe print debug log
            {
                droppedCt = res.oldSize - res.newSize;
                if (Debug::isEnabled()) {
                    Debug d;
                    d << "Dropped " << droppedCt << " txs from mempool (" << affected.size() << " addresses) in "
                      << QString::number(res.elapsedMsec, 'f', 3) << " msec, new mempool size: " << res.newSize
                      << " (" << res.newNumAddresses << " addresses)";
                    if (res.dspRmCt || res.dspTxRmCt)
                        d << " (also dropped dsps: " << res.dspRmCt << " dspTxs: " << res.dspTxRmCt << ")";
                }
                scriptHashesAffected.merge(std::move(affected)); /* update set here with lock not held */
                dspTxsAffected.merge(std::move(res.dspTxsAffected)); /* also update this */
                // . <--- NB: at this point: affected and res.dspsTxsAffected are moved-from
            }
            if (UNLIKELY(droppedCt != expectedDropCt)) { // This invariant is checked to detect bugs.
                Warning() << "Synch mempool expected to drop " << expectedDropCt << ", but in fact dropped "
                          << droppedCt << " -- retrying getrawmempool";
                redoFromStart(); // set state such that the next process() call will do getrawmempool again unless redoCt exceeds kRedoCtMax, in which case errors out
                return;
            }
        }

        if (newCt || droppedCt)
            DebugM(resp.method, ": got reply with ", txidList.size(), " items, ", ignoredCt, " ignored, ",
                   droppedCt, " dropped, ", newCt, " new",
                   " (reply took: ", t0.msecStr(), " msec, processing took: ", t1.msecStr(), " msec)");
        expectedNumTxsDownloaded = unsigned(newCt);
        txsDownloaded.reserve(expectedNumTxsDownloaded);
        txsWaitingForResponse.reserve(expectedNumTxsDownloaded);

        // TX data will be downloaded now, if needed
        state = State::DlTxs;
        if (expectedNumTxsDownloaded) {
            precache->startThread(expectedNumTxsDownloaded, std::move(tentativeMempoolTxHashesForPrecacher));
        }
        process();
    });
}

void SynchMempoolTask::doDLNextTx()
{
    if (txsWaitingForResponse.size() >= maxDLBacklogSize) {
        return;
    }
    const size_t chunkSize = maxDLBacklogSize - txsWaitingForResponse.size();
    const size_t nIters = std::min<size_t>(chunkSize, txsNeedingDownload.size());
    for (size_t i = 0; i < nIters; ++i) {
        Mempool::TxRef tx;
        if (auto it = txsNeedingDownload.begin(); UNLIKELY(it == txsNeedingDownload.end())) {
            Error() << "FIXME -- txsNeedingDownload is empty in " << __func__;
            emit errored();
            return;
        } else {
            tx = it->second;
            it = txsNeedingDownload.erase(it); // pop it off the front
        }
        assert(bool(tx));
        const auto hashHex = Util::ToHexFast(tx->hash);
        txsWaitingForResponse.emplace(tx->hash, tx);
        submitRequest("getrawtransaction", {hashHex, false}, [this, hashHex, tx, t0 = Tic()](const RPC::Message & resp){
            if (TRACE)
                DebugM(resp.method, ": got reply for ", QString::fromLatin1(hashHex).left(8), " in ", t0.msecStr(), " msec",
                       ", needDL: ", txsNeedingDownload.size(), ", waitingForResp: ", txsWaitingForResponse.size());
            QByteArray txdata = resp.result().toByteArray();
            const int expectedLen = txdata.length() / 2;
            txdata = Util::ParseHexFast(txdata);
            if (txdata.length() != expectedLen) {
                Error() << "Received tx data is of the wrong length -- bad hex? FIXME";
                emit errored();
                return;
            }

            // deserialize tx, catching any deser errors
            bitcoin::CMutableTransaction ctx;
            try {
                ctx = BTC::Deserialize<bitcoin::CMutableTransaction>(txdata, 0, isSegWit, isMimble, isCashTokens, true /* nojunk */);
                // Below branch is taken only for Litecoin
                if (isMimble) {
                    if (ctx.mw_blob && ctx.mw_blob->size() > 1) {
                        const auto n = std::min(size_t(60), ctx.mw_blob->size());
                        DebugM("MimbleTxn in mempool:  hash: ", tx->hash.toHex(), ", IsWebOnly: ", int(ctx.IsMWEBOnly()),
                               ", vin,vout sizes: [", ctx.vin.size(), ", ", ctx.vout.size(), "]", ", data_size: ",
                               ctx.mw_blob->size(), ", first ", n, " bytes: ",
                               Util::ToHexFast(QByteArray::fromRawData(reinterpret_cast<const char *>(ctx.mw_blob->data()), n)),
                               ", nLockTime: ", ctx.nLockTime);
                    }
                    // Discard MWEB-only txns (they are useless to us for now)
                    if (/* Note: we would normally check ctx.IsMWEBOnly() here, but if litecoind is using
                           -rpcserialversion=1, then that will return false. So instead we reduce the check to considering
                           MWEB-only as any txn lacking CTxIns and CTxOuts.  (Only mweb-only txns look that way on LTC.) */
                        ctx.vin.empty() && ctx.vout.empty()) {
                        // Ignore MWEB-only txns completely:
                        // - their txid is weird and hard to calculate for us (requires blake3 hasher, which we lack)
                        //   - if remote litecoind is running rpcserialversion=1, then we wouldn't be able to calculate
                        //     their hash anyway since the mweb data is omitted (even though they are listed in mempool
                        //     in that serialization mode anyway -- which makes no sense!!).
                        // - they contain empty vins and vouts, and since Electrum-LTC doesn't grok MWEB, we cannot do anything
                        //   with their spend info anyway.
                        DebugM("Ignoring MWEB-only txn: ", tx->hash.toHex());
                        // mark this as "ignored"
                        emit ctl->ignoreMempoolTxn(tx->hash); // tell Controller in a thread-safe way to remember this across SynchMempoolTask invocations
                        txsIgnored.insert(tx->hash);
                        txsWaitingForResponse.erase(tx->hash);
                        // keep going (do a direct call for better performance, rather than calling AGAIN)
                        process();
                        return;
                    }
                }
            } catch (const std::exception &e) {
                Error() << "Error deserializing tx: " << tx->hash.toHex() << ", exception: " << e.what();
                emit errored();
                return;
            }

            // save size now -- this is needed later to calculate fees and for everything else.
            // note: for btc core with segwit this size is not the same "virtual" size as what bitcoind would report
            tx->sizeBytes = unsigned(expectedLen);

            if (TRACE)
                Debug() << "got reply for tx: " << hashHex << " " << txdata.length() << " bytes";

            // ctx is moved into CTransactionRef below via move construction
            const auto & [it, inserted] = txsDownloaded.try_emplace(tx->hash, tx, bitcoin::MakeTransactionRef(std::move(ctx)));
            const auto & txref = it->second.second;
            if (UNLIKELY(!inserted)) {
                // this should never happen
                Error() << "FIXME: Error inserting tx into txsDownloaded map, already there! TxId: " << tx->hash.toHex();
                emit errored();
                return;
            }

            // Check txdata is sane -- its hash should match the hash we asked for.
            //
            // We do this last because we want to reduce the number of hash operations done by this code -- constructing
            // the CTransaction necessarily causes it to compute its own (segwit-stripped) hash on construction, so we get
            // that hash "for free" here as it were -- and we can use it to ensure sanity that the tx matches what we
            // expected without the need to do BTC::HashRev(txdata) above (which would be redundant).
            if (Util::reversedCopy(txref->GetHashRef()) != tx->hash) {
                txsDownloaded.erase(tx->hash); // remove the object we just inserted
                // WARNING! `txref` is now a dangling reference at this point!
                Error() << "Received tx data appears to not match requested tx for txhash: " << tx->hash.toHex() << "! FIXME!!";
                emit errored();
                return;
            }

            txidsAffected.insert(tx->hash);
            txsWaitingForResponse.erase(tx->hash);
            precache->submitWork(txref);
            // keep going (do a direct call for better performance, rather than calling AGAIN)
            process();
        },
        [this, hashHex, tx](const RPC::Message &resp) {
            if (resp.errorCode() != bitcoin::RPCErrorCode::RPC_INVALID_ADDRESS_OR_KEY) {
                // Probably an unknown bitcoind implementation (not: BCHN, BU, or Core); warn here so I get bug reports
                // about this, hopefully, and we can handle it properly in future versions.
                Warning() << "Unexpected error code from getrawtransaction: " << resp.errorCode();
            }
            // Tolerate missing tx's as we download them -- if we fail to retrieve the transaction then it's possible
            // that there was some RBF action if on BTC, or the tx happened to drop out of mempool due to mempool pressure.
            // Since bitcoind doesn't have the tx -- then it and its children will also fail, which is fine. It's as if
            // it never existed and as if we never got it in the original list from `getrawmempool`!
            const auto *const pre = isSegWit ? "Tx dropped out of mempool (possibly due to RBF)" : "Tx dropped out of mempool";
            Warning() << pre << ": " << QString(hashHex) << " (error response: " << resp.errorMessage()
                      << "), ignoring mempool tx ...";
            txsFailedDownload.insert(tx->hash);
            txsWaitingForResponse.erase(tx->hash);
            if (txsDownloaded.empty() && txsFailedDownload.size() > kFailedDownloadMax) {
                // Too many failures without any successes. Likely some RPC API issue with bitcoind or a new block arrived
                // full of double-spends for previous mempool view (unlikely but possible).  Something is very wrong.
                Warning() << "Too many download failures (" << kFailedDownloadMax << "), aborting task";
                emit errored();
                return;
            }
            // otherwise, keep going (do a direct call for better performance, rather than calling AGAIN)
            process();
        });
    }
}

void SynchMempoolTask::processResults()
{
    if (const auto total = txsDownloaded.size() + txsFailedDownload.size() + txsIgnored.size(); total != expectedNumTxsDownloaded) {
        Error() << __PRETTY_FUNCTION__ << ": Expected to downlaod " << expectedNumTxsDownloaded << ", instead got "
                << total << ". FIXME!";
        emit errored();
        return;
    } else if (total) {
        DebugM("downloaded ", txsDownloaded.size(), " txs (failed: ", txsFailedDownload.size(), ", ignored: ",
               txsIgnored.size(), "), elapsed so far: ", elapsed.secsStr(), " secs");
    }

    updateLastProgress(0.6);

    // precache of the confirmed spends done in another thread, wait for it to complete now
    if (!txsDownloaded.empty()) {
        if (!precache->thread.joinable()) {
            Error() << __PRETTY_FUNCTION__ << " precache->thread should be running -- FIXME!";
            emit errored();
            return;
        }
        precache->waitUntilDone();
    }
    updateLastProgress(0.75);
    auto & cache = precache->cache;

    // At this point we pre-cached all the confirmed spends (we hope). Now ensure that no downloaded children
    // depended on a failed-to-download parent (usually happens on BTC with RBF). If we fail to do this mempool
    // can end up in an inconsistent state and some scripthashes won't get notifications.
    if (!txsFailedDownload.empty() || !txsIgnored.empty()) {
        Tic t0;
        auto hasFailedParent = [this](const bitcoin::CTransaction &ctx) {
            for (const auto &in : ctx.vin) {
                const TxHash prevoutHash = BTC::Hash2ByteArrayRev(in.prevout.GetTxId());
                if (txsFailedDownload.count(prevoutHash) || txsIgnored.count(prevoutHash)) {
                    return true;
                }
            }
            return false;
        };
        const size_t origFailSize = txsFailedDownload.size();
        size_t prevFailsSz, iters = 0;
        // keep looping and growing the failed parent set until it won't grow anymore.
        do {
            prevFailsSz = txsFailedDownload.size();
            auto const end = txsDownloaded.end();
            for (auto it = txsDownloaded.begin(); it != end; /* see below */) {
                const auto & [txHash, item] = *it;
                if (hasFailedParent(*item.second)) {
                    // txn has a failed parent, mark it
                    txsFailedDownload.insert(txHash);
                    it = txsDownloaded.erase(it); // NB: `txHash` and `item` are now invalidated
                } else {
                    ++it;
                }
                ++iters;
            }
        } while (prevFailsSz != txsFailedDownload.size());
        const size_t finalFailSize = txsFailedDownload.size();
        if (finalFailSize > origFailSize || t0.msec<double>() > 250.) {
            DebugM("Removed ", finalFailSize - origFailSize, " txns with failed parents in ", iters,
                   " iters ", t0.msecStr(), " msec");
        }
    }

    auto res = [this, &cache] {
        const auto getFromCache = [&cache](const TXO &prevTXO) -> std::optional<TXOInfo> {
            // This is a callback called from within addNewTxs() below when encountering a confirmed
            // spend.  We just return whatever we precached for this entry.
            //
            // Note that if for some reason the spend is missing we return a null optional which
            // the addTxs() code will throw on, which is what we want (rare but can happen if we
            // are missing the coin due to race conditions with bitcoind on reorg).
            return cache[prevTXO];
        };
        // exclusive lock; held from here until scope end -- we use the cache above to minimize the amount
        // of time we hold this lock -- so we hold it while accessing an in-memory data structure
        // rather than the DB on disk (which would be slow).
        auto [mempool, lock] = storage->mutableMempool(); // grab mempool struct exclusively
        updateLastProgress(0.80);
        return mempool.addNewTxs(scriptHashesAffected, txsDownloaded, getFromCache, TRACE); // may throw
    }();
    dspTxsAffected.merge(std::move(res.dspTxsAffected));
    if ((res.oldSize != res.newSize || res.elapsedMsec > 1e3) && Debug::isEnabled()) {
        Controller::printMempoolStatusToLog(res.newSize, res.newNumAddresses, res.elapsedMsec, true, true);
    }
    updateLastProgress(1.0);
    emit success();
}


