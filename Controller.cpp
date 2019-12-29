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
#include "BlockProc.h"
#include "BTC.h"
#include "Controller.h"
#include "Mempool.h"
#include "Merkle.h"
#include "TXO.h"

#include "bitcoin/transaction.h"
#include "robin_hood/robin_hood.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <list>
#include <map>

Controller::Controller(const std::shared_ptr<Options> &o)
    : Mgr(nullptr), polltimeMS(int(o->pollTimeSecs * 1000)), options(o)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
}

Controller::~Controller() { Debug("%s", __FUNCTION__); cleanup(); }

void Controller::startup()
{
    stopFlag = false;

    storage = std::make_shared<Storage>(options);
    storage->startup(); // may throw here

    bitcoindmgr = std::make_shared<BitcoinDMgr>(options->bitcoind.first, options->bitcoind.second, options->rpcuser, options->rpcpassword);
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
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, waitForBitcoinD);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::gotFirstGoodConnection, this, [this](quint64 id) {
            // connection to kick off our 'process' method once the first auth is received
            if (lostConn) {
                lostConn = false;
                stopTimer(waitTimer);
                Debug() << "Auth recvd from bicoind with id: " << id << ", proceeding with processing ...";
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
            }, Qt::TimerType::VeryCoarseTimer);
        });
        conns += connect(this, &Controller::synchronizing, this, [this]{ stopTimer(mempoolLogTimer);});
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, [this]{ stopTimer(mempoolLogTimer);});
    }

    start();  // start our thread
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
/// TODO: Refactor this out to storage, etc to detect when blockchain changed.
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
    submitRequest("getblockchaininfo", {}, [this](const RPC::Message & resp){
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

            info.bestBlockhash = Util::ParseHexFast(map.value("bestblockhash").toByteArray());
            if (info.bestBlockhash.size() != HashLen) Err("bestblockhash");

            info.difficulty = map.value("difficulty").toDouble(); // error ignored here
            info.mtp = map.value("mediantime").toLongLong(); // error ok
            info.verificationProgress = map.value("verificationprogress").toDouble(); // error ok

            if (auto v = map.value("initialblockdownload"); v.canConvert<bool>())
                info.initialBlockDownload = v.toBool();
            else
                Err("initialblockdownload");

            info.chainWork = Util::ParseHexFast(map.value("chainwork").toByteArray()); // error ok
            info.sizeOnDisk = map.value("size_on_disk").toULongLong(); // error ok
            info.pruned = map.value("pruned").toBool(); // error ok
            info.warnings = map.value("warnings").toString(); // error ok

            if (Trace::isEnabled()) Trace() << info.toString();

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
    DownloadBlocksTask(unsigned from, unsigned to, unsigned stride, Controller *ctl);
    ~DownloadBlocksTask() override { stop(); } // paranoia
    void process() override;


    const unsigned from = 0, to = 0, stride = 1, expectedCt = 1;
    unsigned next = 0;
    std::atomic_uint goodCt = 0;
    bool maybeDone = false;

    int q_ct = 0;
    static constexpr int max_q = /*16;*/BitcoinDMgr::N_CLIENTS+1; // todo: tune this

    static const int HEADER_SIZE;

    std::atomic<size_t> nTx = 0, nIns = 0, nOuts = 0;

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

DownloadBlocksTask::DownloadBlocksTask(unsigned from, unsigned to, unsigned stride, Controller *ctl_)
    : CtlTask(ctl_, QString("Task.DL %1 -> %2").arg(from).arg(to)), from(from), to(to), stride(stride), expectedCt(unsigned(nToDL(from, to, stride)))
{
    FatalAssert( (to >= from) && (ctl_) && (stride > 0)) << "Invalid params to DonloadBlocksTask c'tor, FIXME!";

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
                QVariant var = resp.result();
                const auto rawblock = Util::ParseHexFast(var.toByteArray());
                const auto header = rawblock.left(HEADER_SIZE); // we need a deep copy of this anyway so might as well take it now.
                QByteArray chkHash;
                if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                    auto ppb = PreProcessedBlock::makeShared(bnum, size_t(rawblock.size()), BTC::Deserialize<bitcoin::CBlock>(rawblock)); // this is here to test performance
                    // TESTING --
                    //if (bnum == 60000) Debug() << ppb->toDebugString();

                    if (Trace::isEnabled()) Trace() << "block " << bnum << " size: " << rawblock.size() << " nTx: " << ppb->txInfos.size();
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
                    if (Trace::isEnabled()) Trace() << resp.method << ": header for height: " << bnum << " len: " << header.length();
                    ctl->putBlock(this, ppb); // send the block off to the Controller thread for further processing and for save to db
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
            });
        } else {
            Warning() << resp.method << ": at height " << bnum << " hash not valid (decoded size: " << hash.length() << ")";
            errorCode = int(bnum);
            errorMessage = QString("invalid hash for height %1").arg(bnum);
            emit errored();
        }
    });
}

struct SynchMempoolTask : public CtlTask
{
    SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage)
        : CtlTask(ctl_, "SynchMempool"), storage(storage) {}
    ~SynchMempoolTask() override;
    void process() override;

    std::shared_ptr<Storage> storage;
    bool isdlingtxs = false;
    Mempool::TxMap txsNeedingDownload, txsWaitingForResponse;
    using DldTxsMap = robin_hood::unordered_flat_map<TxHash, std::pair<Mempool::TxRef, bitcoin::CTransactionRef>, HashHasher>;
    DldTxsMap txsDownloaded;
    unsigned expectedNumTxsDownloaded = 0;

    void clear() {
        isdlingtxs = false;
        txsNeedingDownload.clear(); txsWaitingForResponse.clear();
        txsDownloaded.clear();
        expectedNumTxsDownloaded = 0;
    }

    void doGetRawMempool();
    void doDLNextTx();
    void processResults();
};

SynchMempoolTask::~SynchMempoolTask() { stop(); } // paranoia

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
    static size_t oldSize = 0;
    static double lastTS = 0.;
    static std::mutex mut;
    constexpr double interval = 30.;
    double now = Util::getTimeSecs();
    std::lock_guard g(mut);
    if (force || (newSize > 0 && oldSize != newSize && now - lastTS >= interval)) {
        std::unique_ptr<Log> logger(isDebug ? new Debug : new Log);
        Log & log(*logger);
        log << newSize << Util::Pluralize(" mempool tx", newSize) << " involving " << numAddresses
            << Util::Pluralize(" address", numAddresses);
        if (!force) {
            oldSize = newSize;
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
    auto [mempool, lock] = storage->mutableMempool(); // grab mempool struct exclusively
    const auto oldSize = mempool.txs.size();
    // first, do new outputs for all tx's, and put the new tx's in the mempool struct
    for (auto & [hash, pair] : txsDownloaded) {
        auto & [tx, ctx] = pair;
        assert(hash == tx->hash);
        mempool.txs[tx->hash] = tx; // save tx right away
        IONum n = 0;
        for (const auto & out : ctx->vout) {
            const auto & script = out.scriptPubKey;
            if (!BTC::IsOpReturn(script)) {
                // UTXO only if it's not OP_RETURN -- can't do 'continue' here as that would throw off the 'n' counter
                HashX sh = BTC::HashXFromCScript(out.scriptPubKey);
                TXOInfo info{out.nValue, sh, {}, {}};
                tx->txos[n] = info;
                tx->hashXs[sh].utxo.insert(n);
                mempool.hashXTxs[sh].insert(tx); // save tx to hashx -> tx set
            }
            ++n;
        }
    }
    // next, do new inputs for all tx's, debiting/crediting either a mempool tx or querying db for the relevant utxo
    for (auto & [hash, pair] : txsDownloaded) {
        auto & [tx, ctx] = pair;
        assert(hash == tx->hash);
        IONum inNum = 0;
        for (const auto & in : ctx->vin) {
            const IONum prevN = IONum(in.prevout.GetN());
            const TxHash prevTxId = BTC::Hash2ByteArrayRev(in.prevout.GetTxId());
            const TXO prevTXO{prevTxId, prevN};
            TXOInfo prevInfo;
            QByteArray sh; // shallow copy of prevInfo.hashX
            if (tx->depends.count(prevTxId)) {
                // prev is a mempool tx
                auto it = mempool.txs.find(prevTxId);
                if (it == mempool.txs.end())
                    throw InternalError(QString("FAILED TO FIND PREVIOUS TX IN MEMPOOL! Fixme! TxHash: %1").arg(QString(prevTxId.toHex())));
                auto prevTxRef = it->second;
                assert(bool(prevTxRef));
                auto it2 = prevTxRef->txos.find(prevN);
                if (it2 == prevTxRef->txos.end())
                    throw InternalError(QString("FAILED TO FIND PREVIOUS TXOUTN %1 IN MEMPOOL for TxHash: %2").arg(prevN).arg(QString(prevTxId.toHex())));
                prevInfo = it2->second;
                sh = prevInfo.hashX;
                tx->hashXs[sh].unconfirmedSpends[prevTXO] = prevInfo;
                prevTxRef->hashXs[sh].utxo.erase(prevN); // remove this spend from utxo set for prevTx in mempool
                Debug() << hash.toHex() << " unconfirmed spend: " << prevTXO.toString() << " " << prevInfo.amount.ToString().c_str();
            } else {
                // prev is a confirmed tx
                prevInfo = storage->utxoGetFromDB(prevTXO, true).value(); // will throw if missing
                sh = prevInfo.hashX;
                tx->hashXs[sh].confirmedSpends[prevTXO] = prevInfo;
                Debug() << hash.toHex() << " confirmed spend: " << prevTXO.toString() << " " << prevInfo.amount.ToString().c_str();
            }
            assert(sh == prevInfo.hashX);
            mempool.hashXTxs[sh].insert(tx); // mark this hashX as having been "touched" because of this input
            ++inNum;
        }
    }
    const auto newSize = mempool.txs.size();
    if (oldSize != newSize && Debug::isEnabled()) {
        const auto numAddresses = mempool.hashXTxs.size();
        Controller::printMempoolStatusToLog(newSize, numAddresses, true, true);
    }
    // TODO here: notify on status change
    emit success();
}

void SynchMempoolTask::doDLNextTx()
{
    Mempool::TxRef tx;
    if (auto it = txsNeedingDownload.begin(); it == txsNeedingDownload.end()) {
        Error() << "FIXME -- txsNeedingDownload is empty in " << __FUNCTION__;
        emit errored();
        return;
    } else {
        tx = it->second;
        txsNeedingDownload.erase(it); // pop it off the front
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
        } else if (BTC::HashRev(txdata) != tx->hash) {
            Error() << "Received tx data appears to not match requested tx! FIXME!!";
            emit errored();
            return;
        }
        Debug() << "got reply for tx: " << hashHex << " " << txdata.length() << " bytes";
        {
            // tmp mutable object will be moved into CTransactionRef below via a move constructor
            bitcoin::CMutableTransaction ctx = BTC::Deserialize<bitcoin::CMutableTransaction>(txdata);
            txsDownloaded[tx->hash] = {tx, bitcoin::MakeTransactionRef(std::move(ctx)) };
        }
        txsWaitingForResponse.erase(tx->hash);
        AGAIN();
    });
}

void SynchMempoolTask::doGetRawMempool()
{
    submitRequest("getrawmempool", {true}, [this](const RPC::Message & resp){
        const int tipHeight = storage->latestTip().first;
        int newCt = 0;
        const QVariantMap vm = resp.result().toMap();
        auto [mempool, lock] = storage->mutableMempool(); // grab the mempool data struct and lock it exclusively
        const auto oldCt = mempool.txs.size();
        auto droppedTxs = Util::keySet<std::unordered_set<TxHash, HashHasher>>(mempool.txs);
        for (auto it = vm.begin(); it != vm.end(); ++it) {
            const TxHash hash = Util::ParseHexFast(it.key().toUtf8());
            if (hash.length() != HashLen) {
                Error() << resp.method << ": got an empty tx hash";
                emit errored();
                return;
            }
            droppedTxs.erase(hash); // mark this tx as "not dropped"
            const QVariantMap m = it.value().toMap();
            if (m.isEmpty()) {
                Error() << resp.method << ": got an empty dict for tx hash " << hash.toHex();
                emit errored();
                return;
            }
            Mempool::TxRef tx;
            static const QVariantList EmptyList; // avoid constructng this for each iteration
            if (auto it = mempool.txs.find(hash); it != mempool.txs.end()) {
                tx = it->second;
                if (Trace::isEnabled())
                    Debug() << "Existing mempool tx: " << hash.toHex();
            } else {
                Debug() << "New mempool tx: " << hash.toHex();
                ++newCt;
                tx = std::make_shared<Mempool::Tx>();
                tx->hash = hash;
                tx->ordinal = mempool.nextOrdinal++;
                tx->sizeBytes = m.value("size", 0).toUInt();
                tx->fee = int64_t(m.value("fee", 0.0).toDouble() * (bitcoin::COIN / bitcoin::Amount::satoshi())) * bitcoin::Amount::satoshi();
                tx->time = int64_t(m.value("time", 0).toULongLong());
                tx->height = m.value("height", 0).toUInt();
                // Note mempool tx's may have any height in the past because they may not confirm when new blocks arrive...
                if (tx->height > unsigned(tipHeight)) {
                    Debug() << resp.method << ": tx height " << tx->height << " > current height " <<  tipHeight << ", assuming a new block has arrived, aborting mempool synch ...";
                    mempool.clear();
                    emit retryRecommended(); // this is an exit point for this task
                    return;
                }
                // save ancestor count exactly once. this should never change unless there is a reorg, at which point
                // our in-mempory mempool is wiped anyway.
                tx->ancestorCount = m.value("ancestorcount", 0).toUInt();
                if (!tx->ancestorCount) {
                    Error() << resp.method << ": failed to parse ancestor count for tx " << hash.toHex();
                    emit errored();
                    return;
                }
                // we only build the depends list once per tx instantiation
                const auto depends = m.value("depends", EmptyList).toList();
                for (const auto & var : depends) {
                    TxHash deptx = Util::ParseHexFast(var.toString().toUtf8());
                    if (deptx.length() != HashLen) {
                        Error() << "Error parsing depend `" << var.toString() << "` for mempool tx " << hash.toHex();
                        emit errored();
                        return;
                    }
                    auto res = tx->depends.insert(deptx);
                    if (res.second) {
                        Debug() << "new dep: " << deptx.toHex() << " for tx: " << hash.toHex();
                    }
                }
                txsNeedingDownload[hash] = tx;
            }
            // at this point we have a valid tx ptr
            // update descendantCount since it may change as new tx's appear in mempool
            tx->descendantCount = m.value("descendantcount", 0).toUInt();
            if (!tx->descendantCount) {
                Error() << resp.method << ": failed to parse descendant count for tx " << hash.toHex();
                emit errored();
                return;
            }
            const auto spentby = m.value("spentby", EmptyList).toList();

            for (const auto & var : spentby) {
                TxHash spendtx = Util::ParseHexFast(var.toString().toUtf8());
                if (spendtx.length() != HashLen) {
                    Error() << "Error parsing spentby `" << var.toString() << "` for mempool tx " << hash.toHex();
                    emit errored();
                    return;
                }
                auto res = tx->spentBy.insert(spendtx);
                if (res.second) {
                    Debug() << "new spentby: " << spendtx.toHex() << " for tx: " << hash.toHex();
                }
            }
            // detect spentBy deletions... this normally won't happen unless a descendant tx has dropped out of the mempool
            // if this happens mempool needs to be completely rebuilt -- in which case we reset this class's state as well
            // as the known-mempool state, and try again.
            // TODO here: keep track of notifications?
            for (const auto & hash : tx->spentBy) {
                const auto hashHex = Util::ToHexFast(hash);
                if (UNLIKELY(!spentby.contains(hashHex))) {
                    Debug() << "spent-by descendant tx " << hashHex << " disappeared from mempool for parent tx " << Util::ToHexFast(tx->hash)
                            << ", resetting mempool and trying again ...";
                    mempool.clear();
                    clear();
                    AGAIN();
                    return;
                }
            }
        }
        if (UNLIKELY(!droppedTxs.empty())) {
            const bool recommendFullRetry = oldCt >= 2 && droppedTxs.size() >= oldCt/2; // more than 50% of the mempool tx's dropped out. something is funny. likely a new block arrived.
            // TODO here: keep track of notifications?
            Debug() << droppedTxs.size() << " txs dropped from mempool, resetting mempool and trying again ...";
            mempool.clear();
            if (recommendFullRetry) {
                emit retryRecommended(); // this is an exit point for this task
                return;
            }
            clear();
            AGAIN();
            return;
        }
        if (newCt)
            //Debug() << resp.method << ": got reply with " << vm.size() << " items, " << newCt << " new";
            // TESTING
            Log() << resp.method << ": got reply with " << vm.size() << " items, " << newCt << " new";
        isdlingtxs = true;
        expectedNumTxsDownloaded = unsigned(newCt);
        // TX data will be downloaded now, if needed
        AGAIN();
    });
}

struct Controller::StateMachine
{
    enum State {
        Begin=0, GetBlocks, DownloadingBlocks, FinishedDL, End, Failure, IBD, Retry,
        SynchMempool, SynchingMempool, SynchMempoolFinished
    };
    State state = Begin;
    int ht = -1; ///< the latest height bitcoind told us this run
    bool isMainNet = false;

    robin_hood::unordered_flat_map<unsigned, PreProcessedBlockPtr> ppBlocks; // mapping of height -> PreProcessedBlock (we use an unordered_flat_map because it's faster for frequent updates)
    unsigned startheight = 0, ///< the height we started at
             endHeight = 0; ///< the final (inclusive) block height we expect to receive to pronounce the synch done

    std::atomic<unsigned> ppBlkHtNext = 0;  ///< the next unprocessed block height we need to process in series

    // todo: tune this
    const size_t DL_CONCURRENCY = qMax(Util::getNPhysicalProcessors()-1, 1U);//size_t(qMin(qMax(int(Util::getNPhysicalProcessors())-BitcoinDMgr::N_CLIENTS, BitcoinDMgr::N_CLIENTS), 32));

    size_t nTx = 0, nIns = 0, nOuts = 0;

    const char * stateStr() const {
        static constexpr const char *stateStrings[] = { "Begin", "GetBlocks", "DownloadingBlocks", "FinishedDL", "End",
                                                        "Failure", "IBD", "Retry",
                                                        "SynchMempool", "SynchingMempool", "SynchMempoolFinished",
                                                        "Unknown" /* this should always be last */ };
        auto idx = qMin(size_t(state), std::size(stateStrings)-1);
        return stateStrings[idx];
    }

    static constexpr unsigned progressIntervalBlocks = 1000;
    size_t nProgBlocks = 0, nProgIOs = 0, nProgTx = 0;
    double lastProgTs = 0.;

    /// this pointer should *not* be dereferenced (which is why it's void *), but rather is just used to filter out
    /// old/stale GetChainInfoTask responses in Controller::process()
    void * mostRecentGetChainInfoTask = nullptr;
};

unsigned Controller::downloadTaskRecommendedThrottleTimeMsec(unsigned bnum) const
{
    std::shared_lock g(smLock); // this lock guarantees that 'sm' won't be deleted from underneath us
    if (sm) {
        int maxBackLog = 1000; // <--- TODO: have this be a more dynamic value based on current average blocksize.
        if (sm->isMainNet) {
            // mainnet
            if (bnum > 150000) // beyond this height the blocks are starting to be big enough that we want to not eat memory.
                maxBackLog = 250;
            else if (bnum > 550000) // beyond this height we may start to see 32MB blocks in the future
                maxBackLog = 100;
        } else {
            // testnet
            if (bnum > 1300000) // beyond this height 32MB blocks may be common, esp. in the future
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
    Error() << __FUNCTION__ << ": Task '" << t->objectName() << "' not found! FIXME!";
}

bool Controller::isTaskDeleted(CtlTask *t) const { return tasks.count(t) == 0; }

void Controller::add_DLHeaderTask(unsigned int from, unsigned int to, size_t nTasks)
{
    DownloadBlocksTask *t = newTask<DownloadBlocksTask>(false, unsigned(from), unsigned(to), unsigned(nTasks), this);
    connect(t, &CtlTask::success, this, [t, this]{
        if (UNLIKELY(!sm || isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        sm->nTx += t->nTx;
        sm->nIns += t->nIns;
        sm->nOuts += t->nOuts;
        Debug() << "Got all blocks from: " << t->objectName() << " blockCt: "  << t->goodCt
                << " nTx,nInp,nOutp: " << t->nTx << "," << t->nIns << "," << t->nOuts << " totals: "
                << sm->nTx << "," << sm->nIns << "," << sm->nOuts;
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
        if (LIKELY(sm))
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
    connect(task, &CtlTask::retryRecommended, this, [this]{ // only the SynchMempoolTask ever emits this
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
    //Debug() << "Process called...";
    if (!sm) {
        std::lock_guard g(smLock);
        sm = std::make_unique<StateMachine>();
    }
    using State = StateMachine::State;
    if (sm->state == State::Begin) {
        auto task = newTask<GetChainInfoTask>(true, this);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress debug prints here unless we are in trace mode
        sm->mostRecentGetChainInfoTask = task; // reentrancy defense mechanism for ignoring all but the most recent getchaininfo reply from bitcoind
        connect(task, &CtlTask::success, this, [this, task, beSilentIfUpToDate]{
            if (UNLIKELY(!sm || task != sm->mostRecentGetChainInfoTask || isTaskDeleted(task)))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            sm->mostRecentGetChainInfoTask = nullptr;
            if (task->info.initialBlockDownload) {
                sm->state = State::IBD;
                AGAIN();
                return;
            }
            if (const auto dbchain = storage->getChain(); dbchain.isEmpty() && !task->info.chain.isEmpty()) {
                storage->setChain(task->info.chain);
            } else if (dbchain != task->info.chain) {
                Fatal() << "Bitcoind reports chain: \"" << task->info.chain << "\", which differs from our database: \""
                        << dbchain << "\". You may have connected to the wrong bitcoind. To fix this issue either "
                        << "connect to a different bitcoind or delete this program's datadir to resynch.";
                return;
            }
            sm->isMainNet = task->info.chain == "main";
            QByteArray tipHeader;
            // TODO: detect reorgs here -- to be implemented later after we figure out data model more, etc.
            const auto [tip, tipHash] = storage->latestTip(&tipHeader);
            sm->ht = task->info.blocks;
            if (tip == sm->ht) {
                if (task->info.bestBlockhash == tipHash) { // no reorg
                    if (!beSilentIfUpToDate) {
                        storage->updateMerkleCache(unsigned(tip));
                        Log() << "Block height " << tip << ", up-to-date";
                        emit upToDate();
                        emit newHeader(unsigned(tip), tipHeader);
                    }
                    sm->state = State::SynchMempool; // now, move on to synch mempool
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
            }
            AGAIN();
        });
    } else if (sm->state == State::GetBlocks) {
        FatalAssert(sm->ht >= 0) << "Inconsistent state -- sm->ht cannot be negative in State::GetBlocks! FIXME!"; // paranoia
        const size_t base = size_t(storage->latestTip().first+1);
        const size_t num = size_t(sm->ht+1) - base;
        FatalAssert(num > 0) << "Cannot download 0 blocks! FIXME!"; // more paranoia
        const size_t nTasks = qMin(num, sm->DL_CONCURRENCY);
        sm->lastProgTs = Util::getTimeSecs();
        sm->ppBlkHtNext = sm->startheight = unsigned(base);
        sm->endHeight = unsigned(sm->ht);
        for (size_t i = 0; i < nTasks; ++i) {
            add_DLHeaderTask(unsigned(base + i), unsigned(sm->ht), nTasks);
        }
        sm->state = State::DownloadingBlocks; // advance state now. we will be called back by download task in putBlock()
    } else if (sm->state == State::DownloadingBlocks) {
        process_DownloadingBlocks();
    } else if (sm->state == State::FinishedDL) {
        size_t N = sm->endHeight - sm->startheight + 1;
        Log() << "Processed " << N << " new " << Util::Pluralize("block", N) << " with " << sm->nTx << " " << Util::Pluralize("tx", sm->nTx)
              << " (" << sm->nIns << " " << Util::Pluralize("input", sm->nIns) << " & " << sm->nOuts << " " << Util::Pluralize("output", sm->nOuts) << ")"
              << ", verified ok.";
        {
            std::lock_guard g(smLock);
            sm.reset(); // go back to "Begin" state to check if any new headers arrived in the meantime
        }
        AGAIN();
    } else if (sm->state == State::Retry) {
        // normally the result of Rewinding due to reorg, retry right away.
        Debug() << "Retrying download again ...";
        {
            std::lock_guard g(smLock);
            sm.reset();
        }
        AGAIN();
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
    } else if (sm->state == State::IBD) {
        {
            std::lock_guard g(smLock);
            sm.reset();  // great success!
        }
        enablePollTimer = true;
        Warning() << "bitcoind is in initial block download, will try again in 1 minute";
        polltimeout = 60 * 1000; // try again every minute
        emit synchFailure();
    } else if (sm->state == State::SynchMempool) {
        // ...
        auto task = newTask<SynchMempoolTask>(true, this, storage);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress verbose lifecycle prints unless trace mode
        connect(task, &CtlTask::success, this, [this, task]{
            if (UNLIKELY(!sm || isTaskDeleted(task) || sm->state != State::SynchingMempool))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            //Debug() << task->objectName() << " success!"; // TODO remove this, do actual stuff
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

void Controller::putBlock(CtlTask *task, PreProcessedBlockPtr p)
{
    // returns right away
    Util::AsyncOnObject(this, [this, task, p] {
        if (!sm || isTaskDeleted(task) || sm->state == StateMachine::State::Failure || stopFlag) {
            Debug() << "Ignoring block " << p->height << " for now-defunct task";
            return;
        } else if (sm->state != StateMachine::State::DownloadingBlocks) {
            Debug() << "Ignoring putBlocks request for block " << p->height << " -- state is not \"DownloadingBlocks\" but rather is: \"" << sm->stateStr() << "\"";
            return;
        }
        sm->ppBlocks[p->height] = p;
        //AGAIN(); // queue up, return right away -- turns out this spams events. better to call the process function directly here.
        process_DownloadingBlocks();
    });
}

void Controller::process_PrintProgress(unsigned height, size_t nTx, size_t nIO)
{
    if (UNLIKELY(!sm)) return; // paranaoia
    sm->nProgBlocks++;
    sm->nProgTx += nTx;
    sm->nProgIOs += nIO;
    if (UNLIKELY(height && !(height % sm->progressIntervalBlocks))) {
        static const auto formatRate = [](double rate, const QString & thing, bool addComma = true) {
            QString unit = "sec";
            if (rate < 1.0 && rate > 0.0) {
                rate *= 60.0;
                unit = "min";
            }
            if (rate < 1.0 && rate > 0.0) {
                rate *= 60.0;
                unit = "hour";
            }
            static const auto format = [](double rate) { return QString::number(rate, 'f', rate < 10. ? (rate < 1.0 ? 3 : 2) : 1); };
            return rate > 0.0 ? QString("%1%2 %3/%4").arg(addComma ? ", " : "").arg(format(rate)).arg(thing).arg(unit) : QString();
        };
        const double now = Util::getTimeSecs();
        const double elapsed = std::max(now - sm->lastProgTs, 0.00001); // ensure no division by zero
        QString pctDisplay = QString::number((height*1e2) / std::max(sm->endHeight, 1U), 'f', 1) + "%";
        const double rateBlocks = sm->nProgBlocks / elapsed;
        const double rateIO = sm->nProgIOs / elapsed;
        Log() << "Processed height: " << height << ", " << pctDisplay << formatRate(rateBlocks, "blocks") << formatRate(rateIO, "ins & outs");
        // update/reset ts and counters
        sm->lastProgTs = now;
        sm->nProgBlocks = sm->nProgTx = sm->nProgIOs = 0;
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

        process_PrintProgress(ppb->height, ppb->txInfos.size(), ppb->inputs.size()+ppb->outputs.size());

        if (sm->ppBlkHtNext > sm->endHeight) {
            sm->state = StateMachine::State::FinishedDL;
            AGAIN();
            return;
        }

    }

    // testing debug
    //if (auto backlog = sm->ppBlocks.size(); backlog < 100 || ct > 100) {
    //    Debug() << "ppblk - processed: " << ct << ", backlog: " << backlog;
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
        const bool saveUndoInfo = int(ppb->height) > (sm->ht - int(storage->configuredUndoDepth()));

        storage->addBlock(ppb, saveUndoInfo, nLeft);

    } catch (const HeaderVerificationFailure & e) {
        Debug() << "addBlock exception: " << e.what();
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
        storage->undoLatestBlock();
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
    : QObject(nullptr), ctl(ctl)
{
    setObjectName(name);
    _thread.setObjectName(name);
}

CtlTask::~CtlTask() {
    if (isLifecyclePrint()) Debug("%s (%s)", __FUNCTION__, objectName().isEmpty() ? "" : Q2C(objectName()));
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
    Warning() << resp.method << ": error response: " << resp.toJsonString();
    errorCode = resp.errorCode();
    errorMessage = resp.errorMessage();
    emit errored();
}
void CtlTask::on_failure(const RPC::Message::Id &id, const QString &msg)
{
    Warning() << id.toString() << ": FAIL: " << msg;
    errorCode = id.toInt();
    errorMessage = msg;
    emit errored();
}
quint64 CtlTask::submitRequest(const QString &method, const QVariantList &params, const BitcoinDMgr::ResultsF &resultsFunc)
{
    quint64 id = IdMixin::newId();
    ctl->bitcoindmgr->submitRequest(this, id, method, params,
                                    resultsFunc,
                                    [this](const RPC::Message &r){on_error(r);},
                                    [this](const RPC::Message::Id &id, const QString &msg){on_failure(id, msg);});
    return id;
}



// --- Controller stats
auto Controller::stats() const -> Stats
{
    // "Servers"
    auto st = QVariantMap{{ "Servers", srvmgr ? srvmgr->statsSafe() : QVariant() }};

    // "BitcoinD's"
    st["Bitcoin Daemon"] = bitcoindmgr->statsSafe();

    // "Controller" (self)
    QVariantMap m;
    const auto tipInfo = storage->latestTip();
    m["Header count"] = tipInfo.first+1;
    m["Chain"] = storage->getChain();
    m["Chain tip"] = tipInfo.second.toHex();
    m["UTXO set"] = qlonglong(storage->utxoSetSize());
    m["UTXO set bytes"] = QString::number(storage->utxoSetSizeMiB(), 'f', 3) + " MiB";
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
            m3["in-memory (est.)"] = QString("%1 MiB").arg(QString::number(double(backlogInMemoryBytes) / 1e6, 'f', 3));
            m3["block bytes"] = QString("%1 MiB").arg(QString::number(double(backlogBytes) / 1e6, 'f', 3));
            m3["numTxs"] = qulonglong(backlogTxs);
            m2["BackLog"] = m3;
        } else {
            m2["BackLog"] = QVariant(); // null
        }
        m["StateMachine"] = m2;
    } else
        m["StateMachine"] = QVariant(); // null
    QVariantMap timerMap;
    for (const auto & timer: _timerMap) {
        timerMap.insert(timer->objectName(), timer->interval());
    }
    m["activeTimers"] = timerMap;
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
    {
        QVariantMap m;
        m["extant jobs"] = Util::ThreadPool::ExtantJobs();
        m["extant jobs (max lifetime)"] = Util::ThreadPool::ExtantJobsMaxSeen();
        m["extant limit"] = Util::ThreadPool::ExtantJobLimit();
        m["job count (lifetime)"] = qulonglong(Util::ThreadPool::NumJobsSubmitted());
        m["job queue overflows (lifetime)"] = qulonglong(Util::ThreadPool::Overflows());
        misc["Job Queue (Thread Pool)"] = m;
    }
    st["Misc"] = misc;
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
        m["height"] = opt.has_value() ? int(opt.value()) : -1;
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
                m["fee"] = item.fee.value() / item.fee.value().satoshi();
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
            m["value"] = item.value / item.value.satoshi();
            l.push_back(m);
        }
        ret["unspent_debug"] = l;
    }
    if (p.count("mempool")) {
        QVariantMap mp, txs;
        auto [mempool, lock] = storage->mempool();
        for (const auto & [hash, tx] : mempool.txs) {
            if (!tx) continue;
            QVariantMap m;
            m["hash"] = tx->hash.toHex();
            m["ordinal"] = tx->ordinal;
            m["sizeBytes"] = tx->sizeBytes;
            m["fee"] = tx->fee.ToString().c_str();
            m["time"] = qlonglong(tx->time);
            m["height"] = unsigned(tx->height);
            m["ancestorCount"] = tx->ancestorCount;
            m["descendantCount"] = tx->descendantCount;
            QStringList l;
            for (const auto & d : tx->depends) l.push_back(d.toHex());
            m["depends"] = l;
            l.clear();
            for (const auto & s : tx->spentBy) l.push_back(s.toHex());
            m["spentBy"] = l;
            static const auto TXOInfo2Map = [](const TXOInfo &info) -> QVariantMap {
                return QVariantMap{
                    { "amount", QString::fromStdString(info.amount.ToString()) },
                    { "scriptHash", info.hashX.toHex() },
                };
            };
            QVariantMap txos;
            for (const auto & [num, info] : tx->txos) {
                txos[QString::number(num)] = TXOInfo2Map(info);
            }
            m["txos"] = txos;
            QVariantMap hxs;
            static const auto IOInfo2Map = [](const Mempool::Tx::IOInfo &inf) -> QVariantMap {
                QVariantMap ret;
                auto ul = Util::toList(inf.utxo);
                QVariantList vl;
                for (auto u : ul) vl.push_back(u);
                ret["utxos"] = vl;
                QVariantMap cs;
                for (const auto & [txo, info] : inf.confirmedSpends)
                    cs[txo.toString()] = TXOInfo2Map(info);
                ret["confirmedSpends"] = cs;
                QVariantMap us;
                for (const auto & [txo, info] : inf.unconfirmedSpends)
                    us[txo.toString()] = TXOInfo2Map(info);
                ret["unconfirmedSpends"] = us;
                return ret;
            };
            for (const auto & [sh, ioinfo] : tx->hashXs)
                hxs[sh.toHex()] = IOInfo2Map(ioinfo);
            m["hashXs"] = hxs;

            txs[hash.toHex()] = m;
        }
        mp["txs"] = txs;
        QVariantMap hxs;
        for (const auto & [sh, txset] : mempool.hashXTxs) {
            QVariantList l;
            for (const auto & tx : txset)
                if (tx) l.push_back(tx->hash.toHex());
            hxs[sh.toHex()] = l;
        }
        mp["hashXTxs"] = hxs;
        ret["mempool_debug"] = mp;
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
