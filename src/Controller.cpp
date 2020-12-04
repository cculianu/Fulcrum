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
#include "App.h"
#include "BlockProc.h"
#include "BTC.h"
#include "Controller.h"
#include "Mempool.h"
#include "Merkle.h"
#include "SubsMgr.h"
#include "ThreadPool.h"
#include "TXO.h"

#include "bitcoin/amount.h"
#include "bitcoin/transaction.h"
#include "robin_hood/robin_hood.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <ios>
#include <iterator>
#include <list>
#include <map>


Controller::Controller(const std::shared_ptr<const Options> &o)
    : Mgr(nullptr), polltimeMS(int(o->pollTimeSecs * 1e3)), options(o)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
}

Controller::~Controller() { DebugM(__func__); cleanup(); }

void Controller::startup()
{
    /// Note: we tried doing this using AsyncOnObject rather than a signal/slot connection, but on Linux at least those
    /// events arrive AFTER the signal/slot events do.  So in order to make sure putBlock arrives BEFORE the
    /// DownloadBlocksTask completes, we have to do this. On Windows and MacOS this was not an issue, just on Linux.
    conns += connect(this, &Controller::putBlock, this, &Controller::on_putBlock);

    stopFlag = false;

    storage = std::make_shared<Storage>(options);
    storage->startup(); // may throw here

    // check that the coin from DB is known and supported
    {
        const auto coin = storage->getCoin();
        const auto ctype = BTC::coinFromName(coin);
        if (!storage->isNewlyInitialized() && ctype == BTC::Coin::Unknown) {
            if (!coin.isEmpty()) {
                // Coin field in DB is unrecognized. Complain.
                throw InternalError(QString("This database was synched to a bitcoind for the coin \"%1\", yet that coin"
                                            " is unknown to this version of %2. Please use the version of %2 that was"
                                            " used to create this database, or specify a different datadir to create"
                                            " a new database.")
                                    .arg(coin).arg(APPNAME));
            } else {
                // this should never happen for not-newly-initialized DBs. Indicates programming error in codebase.
                throw InternalError("Database \"Coin\" field is empty yet the database has data! This should never happen. FIXME!!");
            }
        }
        // set the atomic -- this affects how we parse blocks, etc
        coinType = ctype;
        if (ctype != BTC::Coin::Unknown)
            bitcoin::SetCurrencyUnit(coin.toStdString());
    }


    if (! options->dumpScriptHashes.isEmpty())
        // this may take a long time but normally this branch is not taken
        dumpScriptHashes(options->dumpScriptHashes);

    bitcoindmgr = std::make_shared<BitcoinDMgr>(options->bdNClients, options->bitcoind.first, options->bitcoind.second,
                                                options->rpcuser, options->rpcpassword, options->bitcoindUsesTls);
    {
        auto constexpr waitTimer = "wait4bitcoind", callProcessTimer = "callProcess";
        int constexpr msgPeriod = 10000, // 10sec
                      smallDelay = 100;

        // some setup code that waits for bitcoind to be ready before kicking off our "process" method
        auto waitForBitcoinD = [this] {
            lostConn = true;
            stopTimer(pollTimerName);
            stopTimer(callProcessTimer);
            callOnTimerSoon(msgPeriod, waitTimer, []{ Log("Waiting for bitcoind..."); return true; }, false, Qt::TimerType::VeryCoarseTimer);
        };
        waitForBitcoinD();
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::bitcoinCoreDetection, this, &Controller::on_bitcoinCoreDetection,
                         /* NOTE --> */ Qt::DirectConnection);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, waitForBitcoinD);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::gotFirstGoodConnection, this, [this](quint64 id) {
            // connection to kick off our 'process' method once the first auth is received
            if (lostConn) {
                lostConn = false;
                stopTimer(waitTimer);
                DebugM("Auth recvd from bicoind with id: ", id, ", proceeding with processing ...");
                callOnTimerSoonNoRepeat(smallDelay, callProcessTimer, [this]{process();}, true);
            }
        });
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::inWarmUp, this, [last = -1.0](const QString &msg) mutable {
            // just print a message to the log as to why we keep dropping conn. -- if bitcoind is still warming up
            auto now = Util::getTimeSecs();
            if (now-last >= 1.0) { // throttled to not spam log
                last = now;
                Log() << "bitcoind is still warming up: " << msg;
            }
        });
    }

    bitcoindmgr->startup(); // may throw

    // We defer listening for connections until we hit the "upToDate" state at least once, to prevent problems
    // for clients.
    auto connPtr = std::make_shared<QMetaObject::Connection>();
    *connPtr = connect(this, &Controller::upToDate, this, [this, connPtr] {
        // the below code runs precisely once after the first upToDate signal
        if (connPtr) disconnect(*connPtr);
        if (!srvmgr) {
            if (!origThread) {
                Fatal() << "INTERNAL ERROR: Controller's creation thread is null; cannot start SrvMgr, exiting!";
                return;
            }

            masterNotifySubsFlag = true; // permanently latch this to true. notifications enabled.

            srvmgr = std::make_unique<SrvMgr>(options, storage, bitcoindmgr);
            // this object will live on our creation thread (normally the main thread)
            srvmgr->moveToThread(origThread);
            // now, start it up on our creation thread (normally the main thread)
            Util::VoidFuncOnObjectNoThrow(srvmgr.get(), [this]{
                // creation thread (normally the main thread)
                try {
                    srvmgr->startup(); // may throw Exception, waits for servers to bind
                } catch (const Exception & e) {
                    // exit app on bind/listen failure.
                    Fatal() << e.what();
                }
            }); // wait for srvmgr's thread (usually the main thread)

            // connect the header subscribe signal
            conns += connect(this, &Controller::newHeader, srvmgr.get(), &SrvMgr::newHeader);
        }
    }, Qt::QueuedConnection);

    {
        // logging/stats timers stuff
        constexpr const char * mempoolLogTimer = "mempoolLogTimer";
        constexpr int mempoolLogTimerTimeout = 10000; // 10 secs (the actual printing happens once every 30 seconds if changed)
        // set up the mempool status log timer
        conns += connect(this, &Controller::upToDate, this, [this]{
            callOnTimerSoon(mempoolLogTimerTimeout, mempoolLogTimer, [this]{
                printMempoolStatusToLog();
                return true;
            }, false, Qt::TimerType::VeryCoarseTimer);
        });
        conns += connect(this, &Controller::synchronizing, this, [this]{ stopTimer(mempoolLogTimer);});
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, [this]{ stopTimer(mempoolLogTimer);});
    }

    {
        // set up periodic refresh of mempool fee histogram
        constexpr const char *feeHistogramTimer = "feeHistogramTimer";
        constexpr int feeHistogramTimerInterval = 30 * 1000; // every 30 seconds
        conns += connect(this, &Controller::upToDate, this, [this] {
            callOnTimerSoon(feeHistogramTimerInterval, feeHistogramTimer, [this]{
                storage->refreshMempoolHistogram();
                return true;
            }, false, Qt::TimerType::VeryCoarseTimer);
        });
        // disable the timer if downloading blocks and restart it later when up-to-date
        conns += connect(this, &Controller::synchronizing, this, [this]{ stopTimer(feeHistogramTimer); });
    }

    start();  // start our thread
}

void Controller::on_bitcoinCoreDetection(bool iscore)
{
    const auto ourtype = coinType.load(std::memory_order_relaxed);
    const auto detectedtype = !iscore ? BTC::Coin::BCH : BTC::Coin::BTC;
    if (ourtype == BTC::Coin::Unknown) {
        // We had no coin set in DB, but we just detected the coin, set it now and return.
        // This is the common case with no misconfiguration.
        coinType = detectedtype;
        const auto coinName = BTC::coinToName(detectedtype);
        storage->setCoin(coinName); // thread-safe call to storage, ok to do here.
        bitcoin::SetCurrencyUnit(coinName.toStdString());
        return;
    }
    if (ourtype != detectedtype) {
        // Misconfiguration -- DB says one thing and bitcoind says another. Complain and exit.
        if (detectedtype == BTC::Coin::BTC && ourtype == BTC::Coin::BCH) {
            // bitcoind is Core, yet we are expecting BCH
            Fatal() << "\n\n"

                       "You are connected to a Bitcoin Core (BTC) bitcoind, yet this database was not\n"
                       "synched to a BTC chain.\n\n"

                       "Please either connect to the appropriate bitcoind for this database, or delete\n"
                       "the datadir and resynch to this bitcoind.\n";
        } else if (detectedtype == BTC::Coin::BCH && ourtype == BTC::Coin::BTC){
            // bitcoind is not Core, we are expecting BTC
            Fatal() << "\n\n"
                       "You are connected to a non-Bitcoin Core (BTC) bitcoind, yet this database was\n"
                       "synched to a BTC chain.\n\n"

                       "At the present time, to use BTC, bitcoind must be Bitcoin Core v0.17.0 or above.\n"
                       "Please either connect to the appropriate bitcoind for this database, or delete\n"
                       "the datadir and resynch.\n";
        } else {
            // defensive programming -- should never be reached. This is here in case we
            // add new coin types yet we forget to update this code.
            Fatal() << "INTERNAL ERROR: Unexpected coin combination: ourtype=" << BTC::coinToName(ourtype)
                    << " detectedtype=" <<  BTC::coinToName(detectedtype) << " -- FIXME!";
        }
    }
}

void Controller::cleanup()
{
    stopFlag = true;
    stop();
    tasks.clear(); // deletes all tasks asap
    if (srvmgr) { Log("Stopping SrvMgr ... "); srvmgr->cleanup(); srvmgr.reset(); }
    if (bitcoindmgr) { Log("Stopping BitcoinDMgr ... "); bitcoindmgr->cleanup(); bitcoindmgr.reset(); }
    if (storage) { Log("Closing storage ..."); storage->cleanup(); storage.reset(); }
    sm.reset();
}

/// Encapsulates basically the data returned from bitcoind by the getblockchaininfo RPC method.
/// This has been separated out into its own struct for future use to detect blockchain changes.
struct ChainInfo {
    QString toString() const;

    QString chain = "";
    int blocks = 0, headers = -1;
    QByteArray bestBlockhash; ///< decoded bytes
    double difficulty = 0.0;
    int64_t mtp = 0;
    double verificationProgress = 0.0;
    bool initialBlockDownload = false;
    QByteArray chainWork; ///< decoded bytes
    size_t sizeOnDisk = 0;
    bool pruned = false;
    QString warnings;
};

struct GetChainInfoTask : public CtlTask
{
    GetChainInfoTask(Controller *ctl_) : CtlTask(ctl_, "Task.GetChainInfo") {}
    ~GetChainInfoTask() override { stop(); } // paranoia
    void process() override;

    ChainInfo info;
};

void GetChainInfoTask::process()
{
    submitRequest("getblockchaininfo", QVariantList{}, [this](const RPC::Message & resp){
        const auto Err = [this, id=resp.id.toInt()](const QString &thing) {
            const auto msg = QString("Failed to parse %1").arg(thing);
            errorCode = id;
            errorMessage = msg;
            throw Exception(msg);
        };
        try {
            bool ok = false;
            const auto map = resp.result().toMap();

            if (map.isEmpty()) Err("response; expected map");

            info.blocks = map.value("blocks").toInt(&ok);
            if (!ok || info.blocks < 0) Err("blocks"); // enforce positive blocks number

            info.chain = map.value("chain").toString();
            if (info.chain.isEmpty()) Err("chain");

            info.headers = map.value("headers").toInt(); // error ignored here
            if (info.headers < info.blocks) {
                // This may happen if for some reason bitcoind omits this info or there is a parse error.
                // We rely on this field being >= info.blocks in later code so just enforce that invariant now.
                info.headers = info.blocks;
                DebugM("bitcoind did not return the expected headers field, expected headers >= blocks (headers=",
                       map.value("headers").toString(), ", blocks=", info.blocks, ")");
            }

            info.bestBlockhash = Util::ParseHexFast(map.value("bestblockhash").toByteArray());
            if (info.bestBlockhash.size() != HashLen) Err("bestblockhash");

            info.difficulty = map.value("difficulty").toDouble(); // error ignored here
            info.mtp = map.value("mediantime").toLongLong(); // error ok
            info.verificationProgress = map.value("verificationprogress").toDouble(); // error ok

            if (auto v = map.value("initialblockdownload"); v.canConvert<bool>())
                info.initialBlockDownload = v.toBool();
            else {
                //Err("initialblockdownload");
                // tolerate missing initialblockdownload key since bchd doesn't emit this key
                info.initialBlockDownload = false;
            }

            info.chainWork = Util::ParseHexFast(map.value("chainwork").toByteArray()); // error ok
            info.sizeOnDisk = map.value("size_on_disk").toULongLong(); // error ok
            info.pruned = map.value("pruned").toBool(); // error ok
            info.warnings = map.value("warnings").toString(); // error ok

            TraceM(info.toString());

            emit success();
        } catch (const Exception & e) {
            Error() << "INTERNAL ERROR: " << e.what();
            emit errored();
        }
    });
}

QString ChainInfo::toString() const
{
    QString ret;
    {
        QTextStream ts(&ret, QIODevice::WriteOnly|QIODevice::Truncate);
        ts << "(ChainInfo"
           << " chain: \"" << chain << "\""
           << " blocks: " << blocks
           << " headers: " << headers
           << " bestBlockHash: " << bestBlockhash.toHex()
           << " difficulty: " << QString::number(difficulty, 'f', 9)
           << " mtp: " << mtp
           << " verificationProgress: " << QString::number(verificationProgress, 'f', 6)
           << " ibd: " << initialBlockDownload
           << " chainWork: " << chainWork.toHex()
           << " sizeOnDisk: " << sizeOnDisk
           << " pruned: " << pruned
           << " warnings: \"" << warnings << "\""
           << ")";
    }
    return ret;
}

struct DownloadBlocksTask : public CtlTask
{
    DownloadBlocksTask(unsigned from, unsigned to, unsigned stride, unsigned numBitcoinDClients, Controller *ctl);
    ~DownloadBlocksTask() override { stop(); } // paranoia
    void process() override;


    const unsigned from = 0, to = 0, stride = 1, expectedCt = 1;
    unsigned next = 0;
    std::atomic_uint goodCt = 0;
    bool maybeDone = false;
    const bool TRACE = Trace::isEnabled();

    int q_ct = 0;
    const int max_q; // todo: tune this, for now it is numBitcoinDClients + 1

    static const int HEADER_SIZE;

    std::atomic<size_t> nTx = 0, nIns = 0, nOuts = 0;

    const bool allowSegWit; ///< initted in c'tor. If true, deserialize blocks using the optional segwit extensons to the tx format.

    void do_get(unsigned height);

    // basically computes expectedCt. Use expectedCt member to get the actual expected ct. this is used only by c'tor as a utility function
    static size_t nToDL(unsigned from, unsigned to, unsigned stride)  { return size_t( (((to-from)+1) + stride-1) / qMax(stride, 1U) ); }
    // thread safe, this is a rough estimate and not 100% accurate
    size_t nSoFar(double prog=-1) const { if (prog<0.) prog = lastProgress; return size_t(qRound(expectedCt * prog)); }
    // given a position in the headers array, return the height
    size_t index2Height(size_t index) { return size_t( from + (index * stride) ); }
    // given a block height, return the index into our array
    size_t height2Index(size_t h) { return size_t( ((h-from) + stride-1) / stride ); }
};


/*static*/ const int DownloadBlocksTask::HEADER_SIZE = BTC::GetBlockHeaderSize();

DownloadBlocksTask::DownloadBlocksTask(unsigned from, unsigned to, unsigned stride, unsigned nClients, Controller *ctl_)
    : CtlTask(ctl_, QStringLiteral("Task.DL %1 -> %2").arg(from).arg(to)), from(from), to(to), stride(stride),
      expectedCt(unsigned(nToDL(from, to, stride))), max_q(int(nClients)+1), allowSegWit(ctl_->isCoinBTC())
{
    FatalAssert( (to >= from) && (ctl_) && (stride > 0), "Invalid params to DonloadBlocksTask c'tor, FIXME!");

    next = from;
}

void DownloadBlocksTask::process()
{
    if (next > to) {
        if (maybeDone) {
            if (goodCt >= expectedCt)
                emit success();
            else {
                errorCode = int(expectedCt - goodCt);
                errorMessage = QString("missing %1 blocks").arg(errorCode);
                emit errored();
            }
        }
        return;
    }

    do_get(next);
    next += stride;
}

void DownloadBlocksTask::do_get(unsigned int bnum)
{
    if (ctl->isStopping())  return; // short-circuit early return if controller is stopping
    if (unsigned msec = ctl->downloadTaskRecommendedThrottleTimeMsec(bnum); msec > 0) {
        // Controller told us to back off because it is backlogged.
        // Schedule ourselves to run again soon and return.
        Util::AsyncOnObject(this, [this, bnum]{
            do_get(bnum);
        }, msec, Qt::TimerType::PreciseTimer);
        return;
    }
    submitRequest("getblockhash", {bnum}, [this, bnum](const RPC::Message & resp){
        QVariant var = resp.result();
        const auto hash = Util::ParseHexFast(var.toByteArray());
        if (hash.length() == HashLen) {
            submitRequest("getblock", {var, false}, [this, bnum, hash](const RPC::Message & resp){
                try {
                    QVariant var = resp.result();
                    const auto rawblock = Util::ParseHexFast(var.toByteArray());
                    const auto header = rawblock.left(HEADER_SIZE); // we need a deep copy of this anyway so might as well take it now.
                    QByteArray chkHash;
                    if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                        PreProcessedBlockPtr ppb;
                        try {
                            ppb = PreProcessedBlock::makeShared(bnum, size_t(rawblock.size()),
                                                                BTC::Deserialize<bitcoin::CBlock>(rawblock, 0, allowSegWit));
                        } catch (const std::ios_base::failure &e) {
                            // deserialization error -- check if block is segwit and we are not segwit
                            if (!allowSegWit) {
                                try {
                                    const auto cblock = BTC::DeserializeSegWit<bitcoin::CBlock>(rawblock);
                                    // If we get here the block deserialized ok as segwit but not ok as non-segwit.
                                    // We must assume that there is some misconfiguration e.g. the remote is BTC
                                    // but DB is not expecting BTC. This can happen if user is using non-Satoshi
                                    // bitcoind with BTC.  We only support /Satoshi... as uagent for BTC due to the
                                    // way that our auto-detection works.
                                    if (std::any_of(cblock.vtx.begin(), cblock.vtx.end(),
                                                    [](const auto &tx){ return tx->HasWitness(); }))
                                        throw InternalError("SegWit block encountered for non-SegWit coin."
                                                            " If you wish to use BTC, please delete the datadir and"
                                                            " resynch using Bitcoin Core v0.17.0 or later.");
                                } catch (const std::ios_base::failure &) { /* ignore -- block is bad as segwit too. */}
                            }
                            throw; // outer catch clause will handle printing the message
                        }
                        assert(bool(ppb));

                        if (TRACE) Trace() << "block " << bnum << " size: " << rawblock.size() << " nTx: " << ppb->txInfos.size();
                        // update some stats for /stats endpoint
                        nTx += ppb->txInfos.size();
                        nOuts += ppb->outputs.size();
                        nIns += ppb->inputs.size();

                        const size_t index = height2Index(bnum);
                        ++goodCt;
                        q_ct = qMax(q_ct-1, 0);
                        lastProgress = double(index) / double(expectedCt);
                        if (!(bnum % 1000) && bnum) {
                            emit progress(lastProgress);
                        }
                        if (TRACE) Trace() << resp.method << ": header for height: " << bnum << " len: " << header.length();
                        emit ctl->putBlock(this, ppb); // send the block off to the Controller thread for further processing and for save to db
                        if (goodCt >= expectedCt) {
                            // flag state to maybeDone to do checks when process() called again
                            maybeDone = true;
                            AGAIN();
                            return;
                        }
                        while (goodCt + unsigned(q_ct) < expectedCt && q_ct < max_q) {
                            // queue multiple at once
                            AGAIN();
                            ++q_ct;
                        }
                    } else if (!sizeOk) {
                        Warning() << resp.method << ": at height " << bnum << " header not valid (decoded size: " << header.length() << ")";
                        errorCode = int(bnum);
                        errorMessage = QString("bad size for height %1").arg(bnum);
                        emit errored();
                    } else {
                        Warning() << resp.method << ": at height " << bnum << " header not valid (expected hash: " << hash.toHex() << ", got hash: " << chkHash.toHex() << ")";
                        errorCode = int(bnum);
                        errorMessage = QString("hash mismatch for height %1").arg(bnum);
                        emit errored();
                    }
                } catch (const std::exception &e) {
                    Fatal() << QString("Caught exception processing block %1: %2").arg(bnum).arg(e.what());
                }
            });
        } else {
            Warning() << resp.method << ": at height " << bnum << " hash not valid (decoded size: " << hash.length() << ")";
            errorCode = int(bnum);
            errorMessage = QString("invalid hash for height %1").arg(bnum);
            emit errored();
        }
    });
}


/// We use the "getrawmempool false" (nonverbose) call to get the initial list of mempool tx's.  This is the
/// most efficient.  With fill mempools bitcoind CPU usage could spike to 100% if we use the verbose more.
/// It turns out we don't need that verbose data anyway (such as a full ancestor count) -- it's enough to have a bool
/// flag for "has unconfirmed parent tx", and be done with it.  Everything else we can calculate.
struct SynchMempoolTask : public CtlTask
{
    SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag)
        : CtlTask(ctl_, "SynchMempool"), storage(storage), notifyFlag(notifyFlag), isBTC(ctl_->isCoinBTC())
        { scriptHashesAffected.reserve(SubsMgr::kRecommendedPendingNotificationsReserveSize); }
    ~SynchMempoolTask() override;
    void process() override;

    const std::shared_ptr<Storage> storage;
    const std::atomic_bool & notifyFlag;
    bool isdlingtxs = false;
    Mempool::TxMap txsNeedingDownload, txsWaitingForResponse;
    Mempool::NewTxsMap txsDownloaded;
    unsigned expectedNumTxsDownloaded = 0;
    static constexpr int kRedoCtMax = 5; // if we have to retry this many times, error out.
    int redoCt = 0;
    const bool TRACE = Trace::isEnabled(); // set this to true to print more debug
    const bool isBTC; ///< initted in c'tor. If true, deserialize tx's using the optional segwit extensons to the tx format.

    /// The scriptHashes that were affected by this refresh/synch cycle. Used for notifications.
    std::unordered_set<HashX, HashHasher> scriptHashesAffected;

    void clear() {
        isdlingtxs = false;
        txsNeedingDownload.clear(); txsWaitingForResponse.clear(); txsDownloaded.clear();
        expectedNumTxsDownloaded = 0;
        // Note: we don't clear "scriptHashesAffected" intentionally in case we are retrying. We want to accumulate
        // all the droppedTx scripthashes for each retry, so we never clear the set.
        // Note 2: we also never clear the redoCt since that counter needs to maintain state to abort too many redos.
    }

    /// Called when getrawtransaction errors out or when we dropTxs() and the result is too many txs so we must
    /// do getrawmempool again.  Increments redoCt. Note that if redoCt > kRedoCtMax, will implicitly error out.
    /// Implicitly calls AGAIN().
    void redoFromStart();

    void doGetRawMempool();
    void doDLNextTx();
    void processResults();
};

SynchMempoolTask::~SynchMempoolTask() {
    stop(); // paranoia
    if (!scriptHashesAffected.empty() && notifyFlag.load()) // this is false until Controller enables the servers that listen for connections
        // notify status change for affected sh's, regardless of how this task exited (this catches corner cases
        // where we queued up some notifications and then we died on a retry due to errors from bitcoind)
        storage->subs()->enqueueNotifications(std::move(scriptHashesAffected));

}

void SynchMempoolTask::redoFromStart()
{
    clear();
    if (++redoCt > kRedoCtMax) {
        Error() << "SyncMempoolTask redo count exceeded (" << redoCt << "), aborting task";
        emit errored();
        return;
    }
    AGAIN();
}

void SynchMempoolTask::process()
{
    if (ctl->isStopping())
        return; // short-circuit early return if controller is stopping
    if (!isdlingtxs)
        doGetRawMempool();
    else if (!txsNeedingDownload.empty()) {
        doDLNextTx();
    } else if (txsWaitingForResponse.empty()) {
        try {
            processResults();
        } catch (const std::exception & e) {
            Error() << "Caught exception when processing mempool tx's: " << e.what();
            emit errored();
            return;
        }
    } else {
        Error() << "Unexpected state in " << __PRETTY_FUNCTION__ << ". FIXME!";
        emit errored();
        return;
    }
}


/// takes locks, prints to Log() every 30 seconds if there were changes
void Controller::printMempoolStatusToLog() const
{
    if (storage) {
        size_t newSize, numAddresses;
        {
            auto [mempool, lock] = storage->mempool();
            newSize = mempool.txs.size();
            numAddresses = mempool.hashXTxs.size();
        } // release mempool lock
        printMempoolStatusToLog(newSize, numAddresses, false);
    }
}
// static
void Controller::printMempoolStatusToLog(size_t newSize, size_t numAddresses, bool isDebug, bool force)
{
    static std::atomic_size_t oldSize = 0, oldNumAddresses = 0;
    static std::atomic<double> lastTS = 0.;
    static std::mutex mut;
    constexpr double interval = 60.; // print once per minute if changed. (TODO: make this configurable?)
    double now = Util::getTimeSecs();
    std::lock_guard g(mut);
    if (force || (newSize > 0 && (oldSize != newSize || oldNumAddresses != numAddresses) && now - lastTS >= interval)) {
        std::unique_ptr<Log> logger(isDebug ? new Debug : new Log);
        Log & log(*logger);
        log << newSize << Util::Pluralize(" mempool tx", newSize) << " involving " << numAddresses
            << Util::Pluralize(" address", numAddresses);
        if (!force) {
            oldSize = newSize;
            oldNumAddresses = numAddresses;
            lastTS = now;
        }
    }
}


void SynchMempoolTask::processResults()
{
    if (txsDownloaded.size() != expectedNumTxsDownloaded) {
        Error() << __PRETTY_FUNCTION__ << ": Expected to downlaod " << expectedNumTxsDownloaded << ", instead got " << txsDownloaded.size() << ". FIXME!";
        emit errored();
        return;
    }
    const auto [oldSize, newSize, oldNumAddresses, newNumAddresses] = [this] {
        const auto getFromDB = [this](const TXO &prevTXO) -> std::optional<TXOInfo> {
            // this is a callback called from within addNewTxs() below when encountering
            // a confirmed spend.
            return storage->utxoGetFromDB(prevTXO, false); // this may throw on low-level db error
        };
        // exclusive lock; held from here until scope end
        auto [mempool, lock] = storage->mutableMempool(); // grab mempool struct exclusively
        return mempool.addNewTxs(scriptHashesAffected, txsDownloaded, getFromDB, TRACE); // may throw
    }();
    if (oldSize != newSize && Debug::isEnabled()) {
        Controller::printMempoolStatusToLog(newSize, newNumAddresses, true, true);
    }
    emit success();
}

void SynchMempoolTask::doDLNextTx()
{
    Mempool::TxRef tx;
    if (auto it = txsNeedingDownload.begin(); it == txsNeedingDownload.end()) {
        Error() << "FIXME -- txsNeedingDownload is empty in " << __func__;
        emit errored();
        return;
    } else {
        tx = it->second;
        it = txsNeedingDownload.erase(it); // pop it off the front
    }
    assert(bool(tx));
    const auto hashHex = Util::ToHexFast(tx->hash);
    txsWaitingForResponse[tx->hash] = tx;
    submitRequest("getrawtransaction", {hashHex, false}, [this, hashHex, tx](const RPC::Message & resp){
        QByteArray txdata = resp.result().toString().toUtf8();
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
            ctx = BTC::Deserialize<bitcoin::CMutableTransaction>(txdata, 0, isBTC);
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
        const auto & [_, txref] = txsDownloaded[tx->hash] = {tx, bitcoin::MakeTransactionRef(std::move(ctx)) };

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

        txsWaitingForResponse.erase(tx->hash);
        AGAIN();
    },
    [this, hashHex, tx](const RPC::Message &resp) {
        // Retry on error -- if we fail to retrieve the transaction then it's possible that there was some RBF action
        // if on BTC, or the tx happened to drop out of mempool for some other reason. We must retry to ensure a
        // consistent view of bitcoind's mempool.
        const auto *const pre = isBTC ? "Tx dropped out of mempool (possibly due to RBF)" : "Tx dropped out of mempool";
        Warning() << pre << ": " << QString(hashHex) << " (error response: " << resp.errorMessage()
                  << "), retrying getrawmempool ...";
        redoFromStart(); // proceed to getrawmempool unless redoCt exceeds kRedoCtMax, in which case errors out
    });
}

void SynchMempoolTask::doGetRawMempool()
{
    submitRequest("getrawmempool", {false}, [this](const RPC::Message & resp){
        std::size_t newCt = 0, droppedCt = 0;
        const QVariantList txidList = resp.result().toList();
        Mempool::TxHashSet droppedTxs;
        {
            // Grab the mempool data struct and lock it *shared*.  This improves performance vs. an exclusive lock here.
            // Since we aren't modifying it.. this is fine.  We are the only subsystem that ever modifies it anyway, so
            // invariants will hold even if we release the lock early, regardless.
            auto [mempool, lock] = storage->mempool();
            droppedTxs = Util::keySet<Mempool::TxHashSet>(mempool.txs);
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
                if (TRACE) Debug() << "New mempool tx: " << hash.toHex();
                ++newCt;
                Mempool::TxRef tx = std::make_shared<Mempool::Tx>();
                tx->hashXs.max_load_factor(.9); // hopefully this will save some memory by expicitly setting max table size to 90%
                tx->hash = hash;
                // Note: we end up calculating the fee ourselves since I don't trust doubles here. I wish bitcoind would have returned sats.. :(
                txsNeedingDownload[hash] = tx;
            }
        }
        if (!droppedTxs.empty()) {
            // Some txs were dropped, update mempool with the drops, grabbing the lock exclusively.
            // Note the release and re-acquisition of the lock should be ok since this Controller
            // thread is the only thread that ever modifies the mempool, so a coherent view of the
            // mempool is the case here even after having released and re-acquired the lock.
            {
                auto [mempool, lock] = storage->mutableMempool();
                const auto res = mempool.dropTxs(scriptHashesAffected /* will upate set */, droppedTxs, TRACE);
                droppedCt = res.oldSize - res.newSize;
                DebugM("Dropped ", droppedCt, " txs from mempool (", res.oldNumAddresses-res.newNumAddresses,
                       " addresses), new mempool size: ", res.newSize, " (", res.newNumAddresses, " addresses)");
            } // release lock
            if (UNLIKELY(droppedCt != droppedTxs.size())) {
                Warning() << "Synch mempool expected to drop " << droppedTxs.size() << ", but in fact dropped "
                          << droppedCt << " -- retrying getrawmempool";
                redoFromStart(); // set state such that the next process() call will do getrawmempool again unless redoCt exceeds kRedoCtMax, in which case errors out
                return;
            }
        }

        if (newCt || droppedCt)
            DebugM(resp.method, ": got reply with ", txidList.size(), " items, ", droppedCt, " dropped, ", newCt, " new");
        isdlingtxs = true;
        expectedNumTxsDownloaded = unsigned(newCt);
        txsDownloaded.reserve(expectedNumTxsDownloaded);
        txsWaitingForResponse.reserve(expectedNumTxsDownloaded);

        // TX data will be downloaded now, if needed
        AGAIN();
    });
}

struct Controller::StateMachine
{
    enum State : uint8_t {
        Begin=0, WaitingForChainInfo, GetBlocks, DownloadingBlocks, FinishedDL, End, Failure, BitcoinDIsInHeaderDL,
        Retry, RetryInIBD, SynchMempool, SynchingMempool, SynchMempoolFinished
    };
    State state = Begin;
    bool suppressSaveUndo = false; ///< true if bitcoind is in IBD, in which case we don't save undo info.
    int ht = -1; ///< the latest height bitcoind told us this run
    int nHeaders = -1; ///< the number of headers our bitcoind has, in the chain we are synching
    BTC::Net net = BTC::Net::Invalid;  ///< This gets set by calls to getblockchaininfo by parsing the "chain" in the resulting dict

    robin_hood::unordered_flat_map<unsigned, PreProcessedBlockPtr> ppBlocks; // mapping of height -> PreProcessedBlock (we use an unordered_flat_map because it's faster for frequent updates)
    unsigned startheight = 0, ///< the height we started at
             endHeight = 0; ///< the final (inclusive) block height we expect to receive to pronounce the synch done

    std::atomic<unsigned> ppBlkHtNext = 0;  ///< the next unprocessed block height we need to process in series

    // todo: tune this
    const size_t DL_CONCURRENCY = qMax(Util::getNPhysicalProcessors()-1, 1U);

    size_t nTx = 0, nIns = 0, nOuts = 0, nSH = 0;

    const char * stateStr() const {
        static constexpr const char *stateStrings[] = { "Begin", "WaitingForChainInfo", "GetBlocks", "DownloadingBlocks",
                                                        "FinishedDL", "End",
                                                        "Failure", "BitcoinDIsInHeaderDL", "Retry", "RetryInIBD",
                                                        "SynchMempool", "SynchingMempool", "SynchMempoolFinished",
                                                        "Unknown" /* this should always be last */ };
        auto idx = qMin(size_t(state), std::size(stateStrings)-1);
        return stateStrings[idx];
    }

    static constexpr unsigned progressIntervalBlocks = 1000;
    size_t nProgBlocks = 0, nProgIOs = 0, nProgTx = 0, nProgSH = 0;
    double lastProgTs = 0., startedTs = 0.;
    static constexpr double simpleTaskTookTooLongSecs = 30.;

    /// this pointer should *not* be dereferenced (which is why it's void *), but rather is just used to filter out
    /// old/stale GetChainInfoTask responses in Controller::process()
    void * mostRecentGetChainInfoTask = nullptr;
};

unsigned Controller::downloadTaskRecommendedThrottleTimeMsec(unsigned bnum) const
{
    std::shared_lock g(smLock); // this lock guarantees that 'sm' won't be deleted from underneath us
    if (sm) {
        int maxBackLog = 1000; // <--- TODO: have this be a more dynamic value based on current average blocksize.
        if (sm->net == BTC::Net::MainNet) {
            // mainnet
            if (bnum > 150'000) // beyond this height the blocks are starting to be big enough that we want to not eat memory.
                maxBackLog = 250;
            else if (bnum > 550'000) // beyond this height we may start to see 32MB blocks in the future
                maxBackLog = 100;
        } else if (sm->net == BTC::ScaleNet) {
            if (bnum > 10'000)
                maxBackLog = 100; // on ScaleNet, after block 10,000 -- we may start to hit big blocks.
        } else if (sm->net == BTC::TestNet4) {
            // nothing, use 1000 always, testnet4 has has 2MB blocks.
        } else {
            // testnet
            if (bnum > 1'300'000) // beyond this height 32MB blocks may be common, esp. in the future
                maxBackLog = 100;
        }

        const int diff = int(bnum) - int(sm->ppBlkHtNext.load()); // note: ppBlkHtNext is not guarded by the lock but it is an atomic value, so that's fine.
        if ( diff > maxBackLog ) {
            // Make the backoff time be from 10ms to 50ms, depending on how far in the future this block height is from
            // what we are processing.  The hope is that this enforces some order on future block arrivals and also
            // prevents excessive polling for blocks that are too far ahead of us.
            return std::min(10u + 5*unsigned(diff - maxBackLog - 1), 50u); // TODO: also have this be tuneable.
        }

    }
    return 0u;
}

void Controller::rmTask(CtlTask *t)
{
    if (auto it = tasks.find(t); it != tasks.end()) {
        tasks.erase(it); // will delete object immediately
        return;
    }
    Error() << __func__ << ": Task '" << t->objectName() << "' not found! FIXME!";
}

bool Controller::isTaskDeleted(CtlTask *t) const { return tasks.count(t) == 0; }

void Controller::add_DLHeaderTask(unsigned int from, unsigned int to, size_t nTasks)
{
    DownloadBlocksTask *t = newTask<DownloadBlocksTask>(false, unsigned(from), unsigned(to), unsigned(nTasks), options->bdNClients, this);
    connect(t, &CtlTask::success, this, [t, this]{
        // NOTE: this callback is sometimes delivered after the sm has been reset(), so we don't check or use it here.
        if (UNLIKELY(isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        DebugM( "Got all blocks from: ", t->objectName(), " blockCt: ",  t->goodCt,
                " nTx,nInp,nOutp: ", t->nTx, ",", t->nIns, ",", t->nOuts);
    });
    connect(t, &CtlTask::errored, this, [t, this]{
        if (UNLIKELY(!sm || isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        if (sm->state == StateMachine::State::Failure) return; // silently ignore if we are already in failure
        Error() << "Task errored: " << t->objectName() << ", error: " << t->errorMessage;
        genericTaskErrored();
    });
}

void Controller::genericTaskErrored()
{
    if (sm && sm->state != StateMachine::State::Failure) {
        sm->state = StateMachine::State::Failure;
        AGAIN();
    }
}

template <typename CtlTaskT, typename ...Args, typename /* enable_if... */>
CtlTaskT *Controller::newTask(bool connectErroredSignal, Args && ...args)
{
    CtlTaskT *task = new CtlTaskT(std::forward<Args>(args)...);
    tasks.emplace(task, task);
    if (connectErroredSignal)
        connect(task, &CtlTask::errored, this, &Controller::genericTaskErrored);
    connect(task, &CtlTask::retryRecommended, this, [this]{  // only the SynchMempoolTask ever emits this.
        if (LIKELY(sm))
            sm->state = StateMachine::State::Retry;
        AGAIN();
    });
    Util::AsyncOnObject(this, [task, this] { // schedule start when we return to our event loop
        if (!isTaskDeleted(task))
            task->start();
    });
    return task;
}

void Controller::process(bool beSilentIfUpToDate)
{
    if (stopFlag) return;
    bool enablePollTimer = false;
    auto polltimeout = polltimeMS;
    stopTimer(pollTimerName);
    //DebugM("Process called...");
    if (!sm) {
        std::lock_guard g(smLock);
        sm = std::make_unique<StateMachine>();
    }
    using State = StateMachine::State;
    if (sm->state == State::Begin) {
        auto task = newTask<GetChainInfoTask>(true, this);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress debug prints here unless we are in trace mode
        sm->mostRecentGetChainInfoTask = task; // reentrancy defense mechanism for ignoring all but the most recent getchaininfo reply from bitcoind
        sm->startedTs = Util::getTimeSecs();
        sm->state = State::WaitingForChainInfo; // more reentrancy prevention paranoia -- in case we get a spurious call to process() in the future
        connect(task, &CtlTask::success, this, [this, task, beSilentIfUpToDate]{
            if (UNLIKELY(!sm || task != sm->mostRecentGetChainInfoTask || isTaskDeleted(task) || sm->state != State::WaitingForChainInfo))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            sm->mostRecentGetChainInfoTask = nullptr;
            if (task->info.blocks < 1 && task->info.initialBlockDownload) {
                // we assume if height is still below 1, and if the ibd flag is set, that we are still synching initial
                // headers, so we mark the state as "BitcoinDIsInHeaderDL", which will retry in 5 seconds
                sm->state = State::BitcoinDIsInHeaderDL;
                AGAIN();
                return;
            }
            const auto & chain = task->info.chain;
            const auto normalizedChain = BTC::NetNameNormalize(chain);
            const auto net = BTC::NetFromName(chain);
            if (const auto dbchain = storage->getChain();
                    dbchain.isEmpty() && !chain.isEmpty() && !normalizedChain.isEmpty() && net != BTC::Net::Invalid) {
                // save the normalized chain to the db, if we were able to grok it. Older versions of Fulcrum
                // will expect to see it in the DB since they use it to check sanity.  Newer versions >= 1.2.7
                // instead query bitcoind for its genesish hash and compare it to db.
                storage->setChain(normalizedChain);
            }

            if (const auto hashDaemon = bitcoindmgr->getBitcoinDGenesisHash(), hashDb = storage->genesisHash();
                    !hashDb.isEmpty() && !hashDaemon.isEmpty() && hashDb != hashDaemon) {
                Fatal() << "Bitcoind reports genesis hash: \"" << hashDaemon.toHex() << "\", which differs from our "
                        << "database: \"" << hashDb.toHex() << "\". You may have connected to the wrong bitcoind. "
                        << "To fix this issue either connect to a different bitcoind or delete this program's datadir "
                        << "to resynch.";
                return;
            }
            sm->net = net;
            if (UNLIKELY(sm->net == BTC::Net::Invalid)) {
                // Unknown chain name. This shouldn't happen but it if does, warn the user since it will make all of
                // the blockchain.address.* methods not work. This warning will spam the log so hopefully it will not
                // go unnoticed. I doubt anyone anytime soon will rename "main" or "test" or "regtest", but it pays
                // to be safe.
                Warning() << "Warning: Bitcoind reports chain: \"" << chain << "\", which is unknown to this software. "
                          << "Some protocol methods such as \"blockchain.address.*\" will not work correctly. "
                          << "Please update your software and/or report this to the developers.";
            }
            QByteArray tipHeader;
            const auto [tip, tipHash] = storage->latestTip(&tipHeader);
            sm->ht = task->info.blocks;
            sm->nHeaders = task->info.headers;
            if (tip == sm->ht) {
                if (task->info.bestBlockhash == tipHash) { // no reorg
                    if (!task->info.initialBlockDownload) {
                        // bitcoind is not in IBD -- proceed to next phase of emitting signals, synching
                        // mempool, turning on the network, etc.
                        if (!beSilentIfUpToDate) {
                            storage->updateMerkleCache(unsigned(tip));
                            Log() << "Block height " << tip << ", up-to-date";
                            emit upToDate();
                            emit newHeader(unsigned(tip), tipHeader);
                        }
                        sm->state = State::SynchMempool; // now, move on to synch mempool
                    } else {
                        // bitcoind is in IBD (we will keep polling to see if it made progress)
                        sm->state = State::RetryInIBD;
                    }
                } else {
                    // height ok, but best block hash mismatch.. reorg
                    Warning() << "We have bestBlock " << tipHash.toHex() << ", but bitcoind reports bestBlock " << task->info.bestBlockhash.toHex() << "."
                              << " Possible reorg, will rewind back 1 block and try again ...";
                    process_DoUndoAndRetry(); // attempt to undo 1 block and try again.
                    return;
                }
            } else if (tip > sm->ht) {
                Warning() << "We have height " << tip << ", but bitcoind reports height " << sm->ht << "."
                          << " Possible reorg, will rewind back 1 block and try again ...";
                process_DoUndoAndRetry(); // attempt to undo 1 block and try again.
                return;
            } else {
                Log() << "Block height " << sm->ht << ", downloading new blocks ...";
                emit synchronizing();
                sm->state = State::GetBlocks;
                // In order to not waste disk I/O on undo info we don't need, as a performance optimization we suppress
                // saving undo (reorg) info if the following is true:
                // - bitcoind has the `initialblockdownload` flag set
                // - the current chain tip is way beyond the current height (so a reorg affecting the blocks we dl now
                //   is not likely)
                // - we have *no* undo info in the db right now (if we did we would need to save undo since the way that
                //   old undo is deleted is only when new undo is added -- hard to explain why in this comment but read
                //   the `process_VerifyAndAddBlock` code in this file to see why this last bullet point
                //   invariant must be satisfied).
                if (task->info.initialBlockDownload && !storage->hasUndo()) {
                    sm->suppressSaveUndo = sm->nHeaders > 0 && sm->ht > 0 && sm->nHeaders >= sm->ht
                                           && unsigned(sm->nHeaders - sm->ht) > storage->configuredUndoDepth();
                }
            }
            AGAIN();
        });
    } else if (sm->state == State::WaitingForChainInfo) {
        // This branch very unlikely -- I couldn't get it to happen in normal testing, but is here in case there are
        // suprious calls to process(), or in case bitcoind goes out to lunch and our process() timer fires while it
        // does so.
        if (Util::getTimeSecs() - sm->startedTs > sm->simpleTaskTookTooLongSecs) {
            // this is very unlikely but is here in case bitcoind goes out to lunch so we can reset things and try again.
            Warning() << "GetChainInfo task took longer than " << sm->simpleTaskTookTooLongSecs << " seconds to return a response. Trying again ...";
            genericTaskErrored();
        } else { DebugM("Spurious Controller::process() call while waiting for the chain info task to complete, ignoring"); }
    } else if (sm->state == State::GetBlocks) {
        FatalAssert(sm->ht >= 0, "Inconsistent state -- sm->ht cannot be negative in State::GetBlocks! FIXME!"); // paranoia
        const size_t base = size_t(storage->latestTip().first+1);
        const size_t num = size_t(sm->ht+1) - base;
        FatalAssert(num > 0, "Cannot download 0 blocks! FIXME!"); // more paranoia
        const size_t nTasks = qMin(num, sm->DL_CONCURRENCY);
        sm->lastProgTs = Util::getTimeSecs();
        sm->ppBlkHtNext = sm->startheight = unsigned(base);
        sm->endHeight = unsigned(sm->ht);
        for (size_t i = 0; i < nTasks; ++i) {
            add_DLHeaderTask(unsigned(base + i), unsigned(sm->ht), nTasks);
        }
        sm->state = State::DownloadingBlocks; // advance state now. we will be called back by download task in on_putBlock()
    } else if (sm->state == State::DownloadingBlocks) {
        process_DownloadingBlocks();
    } else if (sm->state == State::FinishedDL) {
        size_t N = sm->endHeight - sm->startheight + 1;
        Log() << "Processed " << N << " new " << Util::Pluralize("block", N) << " with " << sm->nTx << " " << Util::Pluralize("tx", sm->nTx)
              << " (" << sm->nIns << " " << Util::Pluralize("input", sm->nIns) << ", " << sm->nOuts << " " << Util::Pluralize("output", sm->nOuts)
              << ", " << sm->nSH << Util::Pluralize(" address", sm->nSH) << ")"
              << ", verified ok.";
        {
            std::lock_guard g(smLock);
            sm.reset(); // go back to "Begin" state to check if any new headers arrived in the meantime
        }
        AGAIN();
    } else if (sm->state == State::Retry) {
        // normally the result of Rewinding due to reorg, retry right away.
        DebugM("Retrying download again ...");
        {
            std::lock_guard g(smLock);
            sm.reset();
        }
        AGAIN();
    } else if (sm->state == State::RetryInIBD) {
        constexpr double tooFastThresh = 1.0; // seconds
        const bool tooFast = Util::getTimeSecs() - sm->startedTs < tooFastThresh;
        // in either case reset the state machine
        {
            std::lock_guard g(smLock);
            sm.reset();
        }
        if (tooFast) {
            // the task was too quick -- we need to cool off and let bitcoind get more blocks before proceeding
            DebugM("bitcoind is in IBD, cooldown for ", tooFastThresh, " ", Util::Pluralize("second", tooFastThresh),
                   " to allow it to get more blocks ...");
            enablePollTimer = true;
            polltimeout = int(tooFastThresh * 1000);
        } else {
            DebugM("bitcoind is in IBD, continuing to fetch blocks ...");
            AGAIN();
        }
    } else if (sm->state == State::Failure) {
        // We will try again later via the pollTimer
        Error() << "Failed to synch blocks and/or mempool";
        {
            std::lock_guard g(smLock);
            sm.reset();
        }
        enablePollTimer = true;
        emit synchFailure();
    } else if (sm->state == State::End) {
        {
            std::lock_guard g(smLock);
            sm.reset();  // great success!
        }
        enablePollTimer = true;
    } else if (sm->state == State::BitcoinDIsInHeaderDL) {
        {
            std::lock_guard g(smLock);
            sm.reset();  // great success!
        }
        enablePollTimer = true;
        Warning() << "bitcoind is still downloading headers, will try again in 5 seconds";
        polltimeout = 5 * 1000; // try again every 5 seconds
        emit synchFailure();
    } else if (sm->state == State::SynchMempool) {
        // ...
        auto task = newTask<SynchMempoolTask>(true, this, storage, masterNotifySubsFlag);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress verbose lifecycle prints unless trace mode
        connect(task, &CtlTask::success, this, [this, task]{
            if (UNLIKELY(!sm || isTaskDeleted(task) || sm->state != State::SynchingMempool))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            sm->state = State::SynchMempoolFinished;
            AGAIN();
        });
        sm->state = State::SynchingMempool;
    } else if (sm->state == State::SynchingMempool) {
        // ... nothing..
    } else if (sm->state == State::SynchMempoolFinished) {
        // ...
        sm->state = State::End;
        AGAIN();
    }

    if (enablePollTimer)
        callOnTimerSoonNoRepeat(polltimeout, pollTimerName, [this]{if (!sm) process(true);});
}

// runs in our thread as the slot for putBlock
void Controller::on_putBlock(CtlTask *task, PreProcessedBlockPtr p)
{
    if (!sm || isTaskDeleted(task) || sm->state == StateMachine::State::Failure || stopFlag) {
        DebugM("Ignoring block ", p->height, " for now-defunct task");
        return;
    } else if (sm->state != StateMachine::State::DownloadingBlocks) {
        DebugM("Ignoring putBlocks request for block ", p->height, " -- state is not \"DownloadingBlocks\" but rather is: \"", sm->stateStr(), "\"");
        return;
    }
    sm->ppBlocks[p->height] = p;
    process_DownloadingBlocks();
}

void Controller::process_PrintProgress(unsigned height, size_t nTx, size_t nIns, size_t nOuts, size_t nSH)
{
    if (UNLIKELY(!sm)) return; // paranoia
    sm->nProgBlocks++;

    sm->nTx += nTx;
    sm->nIns += nIns;
    sm->nOuts += nOuts;
    sm->nSH += nSH;

    sm->nProgTx += nTx;
    sm->nProgIOs += nIns + nOuts;
    sm->nProgSH += nSH;
    if (UNLIKELY(height && !(height % sm->progressIntervalBlocks))) {
        static const auto formatRate = [](double rate, const QString & thing, bool addComma = true) {
            QString unit = QStringLiteral("sec");
            if (rate < 1.0 && rate > 0.0) {
                rate *= 60.0;
                unit = QStringLiteral("min");
            }
            if (rate < 1.0 && rate > 0.0) {
                rate *= 60.0;
                unit = QStringLiteral("hour");
            }
            static const auto format = [](double rate) { return QString::number(rate, 'f', rate < 10. ? (rate < 1.0 ? 3 : 2) : 1); };
            return rate > 0.0 ? QStringLiteral("%1%2 %3/%4").arg(addComma ? ", " : "").arg(format(rate)).arg(thing).arg(unit) : QString();
        };
        const double now = Util::getTimeSecs();
        const double elapsed = std::max(now - sm->lastProgTs, 0.00001); // ensure no division by zero
        QString pctDisplay = QString::number((height*1e2) / std::max(std::max(int(sm->endHeight), sm->nHeaders), 1), 'f', 1) + "%";
        const double rateBlocks = sm->nProgBlocks / elapsed;
        const double rateTx = sm->nProgTx / elapsed;
        const double rateSH = sm->nProgSH / elapsed;
        Log() << "Processed height: " << height << ", " << pctDisplay << formatRate(rateBlocks, QStringLiteral("blocks"))
              << formatRate(rateTx, QStringLiteral("txs"))  << formatRate(rateSH, QStringLiteral("addrs"));
        // update/reset ts and counters
        sm->lastProgTs = now;
        sm->nProgBlocks = sm->nProgTx = sm->nProgIOs = sm->nProgSH = 0;
    }
}

void Controller::process_DownloadingBlocks()
{
    unsigned ct = 0;

    for (auto it = sm->ppBlocks.find(sm->ppBlkHtNext); it != sm->ppBlocks.end() && !stopFlag; it = sm->ppBlocks.find(sm->ppBlkHtNext)) {
        auto ppb = it->second;
        assert(ppb->height == sm->ppBlkHtNext); // paranoia -- should never happen
        ++ct;

        ++sm->ppBlkHtNext;
        sm->ppBlocks.erase(it); // remove immediately from q

        // process & add it if it's good
        if ( ! process_VerifyAndAddBlock(ppb) )
            // error encountered.. abort!
            return;

        process_PrintProgress(ppb->height, ppb->txInfos.size(), ppb->inputs.size(), ppb->outputs.size(), ppb->hashXAggregated.size());

        if (sm->ppBlkHtNext > sm->endHeight) {
            sm->state = StateMachine::State::FinishedDL;
            AGAIN();
            return;
        }

    }

    // testing debug
    //if (auto backlog = sm->ppBlocks.size(); backlog < 100 || ct > 100) {
    //    DebugM("ppblk - processed: ", ct, ", backlog: ", backlog);
    //}
}

namespace {
    const QString inconsistentStateSorry("\n\nThe database is now likely in an inconsistent state. "
                                         "To recover, you will need to delete the datadir and do a full resynch. "
                                         "Sorry!\n");
}

bool Controller::process_VerifyAndAddBlock(PreProcessedBlockPtr ppb)
{
    assert(sm);

    try {
        const auto nLeft = qMax(sm->endHeight - (sm->ppBlkHtNext-1), 0U);
        const bool saveUndoInfo = !sm->suppressSaveUndo && int(ppb->height) > (sm->ht - int(storage->configuredUndoDepth()));

        storage->addBlock(ppb, saveUndoInfo, nLeft, masterNotifySubsFlag);

    } catch (const HeaderVerificationFailure & e) {
        DebugM("addBlock exception: ", e.what());
        Log() << "Possible reorg detected at height " << ppb->height << ", rewinding 1 block and trying again ...";
        process_DoUndoAndRetry();
        return false;
    } catch (const std::exception & e) {
        // TODO: see about more graceful error and not a fatal exit. (although if we do get an error here it's pretty non-recoverable!)
        Fatal() << e.what() << inconsistentStateSorry;
        sm->state = StateMachine::State::Failure;
        // app will shut down after return to event loop.
        return false;
    }

    return true;
}

void Controller::process_DoUndoAndRetry()
{
    assert(sm);
    try {
        storage->undoLatestBlock(masterNotifySubsFlag);
        // . <-- If we get here, rollback was successful.
        // We flag the state to retry, which retries the full download right away
        // (Note: this may eventually lead us to roll back again and again until we reorg to the sufficient depth).
        sm->state = StateMachine::State::Retry;
        AGAIN(); // schedule us again to do cleanup
    } catch (const std::exception & e) {
        Fatal() << "Failed to rewind: " << e.what() << inconsistentStateSorry;
        sm->state = StateMachine::State::Failure;
        // upon return to event loop, will shut down
    }
}

// -- CtlTask
CtlTask::CtlTask(Controller *ctl, const QString &name)
    : QObject(nullptr), ctl(ctl), reqTimeout(ctl->options->bdTimeoutMS)
{
    setObjectName(name);
    _thread.setObjectName(name);
}

CtlTask::~CtlTask() {
    if (isLifecyclePrint()) DebugM(__func__, " (", objectName(), ")");
    stop();
}

void CtlTask::on_started()
{
    ThreadObjectMixin::on_started();
    conns += connect(this, &CtlTask::success, ctl, [this]{stop();});
    conns += connect(this, &CtlTask::errored, ctl, [this]{stop();});
    conns += connect(this, &CtlTask::retryRecommended, ctl, [this]{stop();});
    conns += connect(this, &CtlTask::finished, ctl, [this]{ctl->rmTask(this);});
    process();
    emit started();
}

void CtlTask::on_finished()
{
    ThreadObjectMixin::on_finished();
    emit finished();
}

void CtlTask::on_error(const RPC::Message &resp)
{
    Warning() << resp.method << ": error response: " << resp.toJsonUtf8();
    errorCode = resp.errorCode();
    errorMessage = resp.errorMessage();
    emit errored();
}
void CtlTask::on_error_retry(const RPC::Message &resp, const char *msg)
{
    Log() << resp.method << ": " << msg << ", retrying ...";
    emit retryRecommended();
}
void CtlTask::on_failure(const RPC::Message::Id &id, const QString &msg)
{
    Warning() << id << ": FAIL: " << msg;
    errorCode = id.toInt();
    errorMessage = msg;
    emit errored();
}
quint64 CtlTask::submitRequest(const QString &method, const QVariantList &params, const ResultsF &resultsFunc,
                               const ErrorF &errorFunc)
{
    quint64 id = IdMixin::newId();
    using ErrorF = BitcoinDMgr::ErrorF;
    using MsgCRef = const RPC::Message &;
    ctl->bitcoindmgr->submitRequest(this, id, method, params,
                                    resultsFunc,
                                    !errorFunc
                                        ? ErrorF([this](MsgCRef m){ on_error(m); }) // more common case, just emit error on RPC error reply
                                        : errorFunc,
                                    [this](const RPC::Message::Id &id, const QString &msg){ on_failure(id, msg); },
                                    reqTimeout);
    return id;
}



// --- Controller stats
auto Controller::stats() const -> Stats
{
    // "Servers"
    auto st = QVariantMap{{ "Server Manager", srvmgr ? srvmgr->statsSafe() : QVariant() }};

    // "BitcoinD's"
    st["Bitcoin Daemon"] = bitcoindmgr->statsSafe();

    // "Controller" (self)
    QVariantMap m;
    const auto tipInfo = storage->latestTip();
    m["Header count"] = tipInfo.first+1;
    m["Chain"] = storage->getChain();
    m["Coin"] = storage->getCoin();
    m["Chain tip"] = tipInfo.second.toHex();
    m["UTXO set"] = qlonglong(storage->utxoSetSize());
    m["UTXO set bytes"] = QString::number(storage->utxoSetSizeMB(), 'f', 3) + " MB";
    const auto txnum = qlonglong(storage->getTxNum());
    m["TxNum"] = txnum;
    m["TxNum -> TxHash (latest)"] = txnum ? storage->hashForTxNum(TxNum(txnum-1), false, nullptr, true).value_or("").toHex() : QVariant();
    if (sm) {
        QVariantMap m2;
        m2["State"] = sm->stateStr();
        m2["Height"] = sm->ht;
        if (const auto nDL = nBlocksDownloadedSoFar(); nDL > 0)
            m2["Blocks downloaded this run"] = qlonglong(nDL);
        if (const auto [ntx, nin, nout] = nTxInOutSoFar(); ntx > 0) {
            m2["Txs seen this run"] = QVariantMap({
                { "nTx" , qlonglong(ntx) },
                { "nIns", qlonglong(nin) },
                { "nOut", qlonglong(nout) }
            });
        }
        const size_t backlogBlocks = sm->ppBlocks.size();
        if (backlogBlocks) {
            QVariantMap m3;
            m3["numBlocks"] = qulonglong(backlogBlocks);
            size_t backlogBytes = 0, backlogTxs = 0, backlogInMemoryBytes = 0;
            for (const auto & [height, ppb] : sm->ppBlocks) {
                backlogBytes += ppb->sizeBytes;
                backlogTxs += ppb->txInfos.size();
                backlogInMemoryBytes += ppb->estimatedThisSizeBytes;
            }
            m3["in-memory (est.)"] = QString("%1 MB").arg(QString::number(double(backlogInMemoryBytes) / 1e6, 'f', 3));
            m3["block bytes"] = QString("%1 MB").arg(QString::number(double(backlogBytes) / 1e6, 'f', 3));
            m3["numTxs"] = qulonglong(backlogTxs);
            m2["BackLog"] = m3;
        } else {
            m2["BackLog"] = QVariant(); // null
        }
        m["StateMachine"] = m2;
    } else
        m["StateMachine"] = QVariant(); // null
    m["activeTimers"] = activeTimerMapForStats();
    QVariantList l;
    { // task list
        const auto now = Util::getTime();
        for (const auto & [task, ign] : tasks) {
            Q_UNUSED(ign)
            l.push_back(QVariantMap{{ task->objectName(), QVariantMap{
                {"age", QString("%1 sec").arg(double((now-task->ts)/1e3))} ,
                {"progress" , QString("%1%").arg(QString::number(task->lastProgress*100.0, 'f', 1)) }}
            }});
        }
        Util::updateMap(m, QVariantMap{{"tasks" , l}});
    }
    st["Controller"] = m;
    st["Storage"] = storage->statsSafe();
    QVariantMap misc;
    misc["Job Queue (Thread Pool)"] = ::AppThreadPool()->stats();
    st["Misc"] = misc;
    st["SubsMgr"] = storage->subs()->statsSafe(kDefaultTimeout/2);
    // Config (Options) map
    st["Config"] = options->toMap();
    { // Process memory usage
        const auto mu = Util::getProcessMemoryUsage();
        st["Memory Usage"] = QVariantMap{
            { "physical kB", std::round((mu.phys / 1024.0) * 100.0) / 100.0 },
            { "virtual kB", std::round((mu.virt / 1024.0) * 100.0) / 100.0 },
        };
    }

    // grab jemalloc stats, if any
    st["Jemalloc"] = App::jemallocStats();

    // grab simdjson stats, if any
    st["simdjson"] = App::simdJsonStats();

    return st;
}

auto Controller::debug(const StatsParams &p) const -> Stats // from StatsMixin
{
    QVariantMap ret;
    bool ok;
    const auto t0 = Util::getTimeNS();
    if (const auto txnum = p.value("txnum").toULong(&ok); ok) {
        QVariantMap m;
        auto hash = storage->hashForTxNum(txnum).value_or(QByteArray());
        auto opt = storage->heightForTxNum(txnum);
        m["tx_hash"] = Util::ToHexFast(hash);
        m["height"] = opt.has_value() ? int(*opt) : -1;
        ret["txnum_debug"] = m;
    }
    if (const auto sh = QByteArray::fromHex(p.value("sh").toLatin1()); sh.length() == HashLen) {
        QVariantList l;

        auto items = storage->getHistory(sh, true, true);
        for (const auto & item : items) {
            QVariantMap m;
            m["tx_hash"] = Util::ToHexFast(item.hash);
            m["height"] = item.height;
            if (item.fee.has_value())
                m["fee"] = qlonglong(*item.fee / item.fee->satoshi());
            l.push_back(m);
        }
        ret["sh_debug"] = l;
    }
    if (const auto hashx = QByteArray::fromHex(p.value("unspent").toLatin1()); hashx.length() == HashLen) {
        QVariantList l;

        auto items = storage->listUnspent(hashx);
        for (const auto & item : items) {
            QVariantMap m;
            m["tx_hash"] = Util::ToHexFast(item.hash);
            m["height"] = item.height;
            m["tx_pos"] = item.tx_pos;
            m["value"] = qlonglong(item.value / item.value.satoshi());
            l.push_back(m);
        }
        ret["unspent_debug"] = l;
    }
    if (p.contains("mempool")) {
        auto [mempool, lock] = storage->mempool();
        ret["mempool_debug"] = mempool.dump();
    }
    if (p.contains("subs")) {
        const auto timeLeft = kDefaultTimeout - (Util::getTime() - t0/1000000) - 50;
        ret["subscriptions"] = storage->subs()->debugSafe(p, std::max(5, int(timeLeft)));
    }
    const auto elapsed = Util::getTimeNS() - t0;
    ret["elapsed"] = QString::number(elapsed/1e6, 'f', 6) + " msec";
    return ret;
}

size_t Controller::nBlocksDownloadedSoFar() const
{
    size_t ret = 0;
    for (const auto & [task, ign] : tasks) {
        Q_UNUSED(ign)
        auto t = dynamic_cast<DownloadBlocksTask *>(task);
        if (t)
            ret += t->nSoFar();
    }
    return ret;
}

std::tuple<size_t, size_t, size_t> Controller::nTxInOutSoFar() const
{
    size_t nTx = 0, nIn = 0, nOut = 0;
    for (const auto & [task, ign] : tasks) {
        Q_UNUSED(ign)
        auto t = dynamic_cast<DownloadBlocksTask *>(task);
        if (t) {
            nTx += t->nTx;
            nIn += t->nIns;
            nOut += t->nOuts;
        }
    }
    return {nTx, nIn, nOut};
}

// --- Debug dump support
void Controller::dumpScriptHashes(const QString &fileName) const
{
    if (!storage)
        throw InternalError("Dump: Storage is not started");
    QFile outFile(fileName);
    if (!outFile.open(QIODevice::WriteOnly|QIODevice::Text|QIODevice::Truncate))
        throw BadArgs(QString("Dump: Output file \"%1\" could not be opened for writing").arg(fileName));
    Log() << "Dump: " << "writing all known script hashes from db to \"" << fileName << "\" (this may take some time) ...";
    const auto t0 = Util::getTimeSecs();
    const auto count = storage->dumpAllScriptHashes(&outFile, 2, 0, [](size_t ctr){
        const QString text(QString("Dump: wrote %1 scripthashes so far ...").arg(ctr));
        if (ctr && !(ctr % 1000000))
            Log() << text;
        else
            DebugM(text);
    });
    outFile.flush();
    outFile.close();
    Log() << "Dump: wrote " << count << Util::Pluralize(" script hash", count) << " to \"" << fileName << "\""
          << " in " << QString::number(Util::getTimeSecs() - t0, 'f', 1) << " seconds"
          <<" (" << QString::number(outFile.size()/1e6, 'f', 3) << " MB)";
    emit dumpScriptHashesComplete();
}
