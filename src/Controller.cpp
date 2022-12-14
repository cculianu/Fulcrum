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
#include "App.h"
#include "BlockProc.h"
#include "BTC.h"
#include "Controller.h"
#include "Controller_SynchDSPsTask.h"
#include "DSProof.h"
#include "Mempool.h"
#include "Merkle.h"
#include "SubsMgr.h"
#include "ThreadPool.h"
#include "TXO.h"
#include "ZmqSubNotifier.h"

#include "bitcoin/amount.h"
#include "bitcoin/crypto/common.h"  // ReadLE32
#include "bitcoin/rpc/protocol.h" // for RPC_INVALID_ADDRESS_OR_KEY
#include "bitcoin/transaction.h"
#include "robin_hood/robin_hood.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <ios>
#include <iterator>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <unordered_set>


Controller::Controller(const std::shared_ptr<const Options> &o, const SSLCertMonitor *certMon)
    : Mgr(nullptr), polltimeMS(int(o->pollTimeSecs * 1e3)), options(o), sslCertMonitor(certMon)
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
                                            " a new database.").arg(coin, QString{APPNAME}));
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

    bitcoindmgr = std::make_shared<BitcoinDMgr>(options->bdNClients, options->bdRPCInfo);
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
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::coinDetected, this, &Controller::on_coinDetected,
                         /* NOTE --> */ Qt::DirectConnection);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, waitForBitcoinD);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, &Controller::zmqHashBlockStop); // stop zmq unconditionally
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::gotFirstGoodConnection, this, [this](quint64 id) {
            // connection to kick off our 'process' method once the first auth is received
            if (lostConn) {
                lostConn = false;
                stopTimer(waitTimer);
                DebugM("Auth recvd from bicoind with id: ", id, ", proceeding with processing ...");
                callOnTimerSoonNoRepeat(smallDelay, callProcessTimer, [this]{process();}, true);

                // also (re)start the zmq notifier if we had one before and bitcoind came back (but only if we are
                // "ready" and able to serve connections)
                if (!lastKnownZmqHashBlockAddr.isEmpty() && srvmgr)
                    zmqHashBlockStart();
            }
        });

        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::zmqNotificationsChanged, this, [this](BitcoinDZmqNotifications zmqs) {
            // NB: this only fires if ZmqSubNotifier::isAvailable() == true
            if (!(lastKnownZmqHashBlockAddr = zmqs.value("hashblock")).isEmpty()) {
                DebugM("\"hashblock\" topic address: ", lastKnownZmqHashBlockAddr);
                // We only start the ZMQ notifier once we are "ready" and the servers are started
                // (see also one of the upToDate triggered slots below)
                if (srvmgr) {
                    // maybe restart if it was running (to apply new address)
                    if (zmqHashBlockNotifier && zmqHashBlockNotifier->isRunning()) {
                        DebugM("applying new hashblock address to already-running zmq notifier");
                    }
                    zmqHashBlockStart(); // may re-start existing notifier, or create a new one if none exists
                }
            } else {
                // bitcoind lacks the "hashblock" endpoint -- stop existing hashblock notifier, if it exists
                zmqHashBlockStop();
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

        // notify the bitcoind mgr when we enter/exit block download phase so that it treats connections differently
        conns += connect(this, &Controller::downloadingBlocks, bitcoindmgr.get(), &BitcoinDMgr::inBlockDownload);
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

            srvmgr = std::make_unique<SrvMgr>(options, sslCertMonitor, storage, bitcoindmgr);
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

            // If BitcoinDMgr told us about a ZMQ hashblock notification address, start the ZMQ notifier
            // (this does not happen if no ZMQ enabled at compile-time)
            if (!lastKnownZmqHashBlockAddr.isEmpty())
                zmqHashBlockStart();
        }
    }, Qt::QueuedConnection);

    // Checks if the remote bitcoind has -txindex or can serve arbitrary transactions. Called initially when upToDate()
    // is first emitted, and disconnects itself from upToDate if we did in fact detect that bitcoind can serve arbitrary
    // tx's. If there is an error retrieving tx #1, it will warn the user to enable txindex.
    // Assumption: tx #1 is not a bitcoind wallet tx. (If it is, then we will get a possible false positive here).
    auto connPtr2 = std::make_shared<QMetaObject::Connection>();
    *connPtr2 = connect(this, &Controller::upToDate, this, [this, connPtr2] {
        const auto optHash = storage->hashForTxNum(1, false, nullptr, true); // skip cache, read from txNum2txHash file to get first non-genesis tx hash
        if (!optHash) return; // no blocks yet, somehow. must be a brand new chain. we will be called again later when blocks start showing up.
        auto onSuccess = [this, connPtr2, hash=*optHash] (const RPC::Message &resp) {
            bitcoin::CMutableTransaction tx;
            constexpr auto kErrLine2 = "Something is wrong with either BitcoinD or our ability to understand its RPC responses.";
            try {
                BTC::Deserialize(tx, Util::ParseHexFast(resp.result().toByteArray()), 0, isSegWitCoin(), isMimbleWimbleCoin(), isBCHCoin());
            } catch (const std::exception &e) {
                Error() << "Failed to deserialize tx #1 with txid " << hash.toHex() << ": " << e.what();
                Error() << kErrLine2;
                return;
            }
            if (BTC::Hash2ByteArrayRev(tx.GetHash()) != hash) {
                Error() << "Failed to validate tx #1 with txid " << hash.toHex();
                Error() << kErrLine2;
                return;
            }
            DebugM("BitcoinD verified to have txindex enabled");
            // success! disconnect the slot now, connPtr2 will delete the managed object when we return.
            disconnect(*connPtr2);
        };
        auto onError = [] (const RPC::Message &resp) {
            Error() << "\n"
                    << "******************************************************************************\n"
                    << "*   Error: txindex verification failed!                                      *\n"
                    << "*   Please ensure that your BitcoinD node has txindex enabled (-txindex=1)   *\n"
                    << "******************************************************************************\n\n"
                    << "Error response was:\n\n\t" << resp.errorMessage() << "\n\n";
        };
        auto onFail = [] (RPC::Message::Id, const QString &errMsg) {
            Warning() << "Unable to verify that BitcoinD is using txindex. Error: " << errMsg;
        };
        // ask bitcoind for tx #1 (first tx after genesis) to ensure it has txindex enabled.
        bitcoindmgr->submitRequest(this, IdMixin::newId(), "getrawtransaction", {Util::ToHexFast(*optHash), false}, onSuccess, onError, onFail);
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

    {
        // Small utility function to add "ignore" txhashes coming from SynchMempoolTask to our somewhat-persistent
        // mempoolIgnoreTxns set (this set is cleared each time the tip changes, but persists across mempool synchs
        // for a given tip).
        conns += connect(this, &Controller::ignoreMempoolTxn, this, [this] (const QByteArray & txHash) {
            if (mempoolIgnoreTxns.insert(txHash).second)
                DebugM("Added txHash: ", txHash.toHex(), " to mempool ignore set, set size now: ", mempoolIgnoreTxns.size());
        });
        // Another small utility function: clears the mempoolIgnoreTxns set whenever we see a new tip
        conns += connect(this, &Controller::newHeader, this, [this] {
            // we just got to a new tip, clear this (will be repopulated in SynchMempoolTask if need be)
            if (!mempoolIgnoreTxns.empty()) DebugM("mempoolIgnoreTxns: ", mempoolIgnoreTxns.size(), Util::Pluralize(" txHash", mempoolIgnoreTxns.size()), " cleared");
            mempoolIgnoreTxns.clear();
        });
    }

    start();  // start our thread
}

void Controller::on_coinDetected(const BTC::Coin detectedtype)
{
    const auto ourtype = coinType.load(std::memory_order_relaxed);
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
            // Generic message for LTC/BCH/BTC mismatch.
            Fatal() << "Unexpected coin combination: ourtype=" << BTC::coinToName(ourtype)
                    << ", rpc daemon's type=" <<  BTC::coinToName(detectedtype) << ". Are you connected to the"
                    << " right node for this " << APPNAME << " database?";
        }
    }
}

void Controller::cleanup()
{
    stopFlag = true;
    stop();
    tasks.clear(); // deletes all tasks asap
    if (zmqHashBlockNotifier) { Log("Stopping ZMQ notifier ..."); zmqHashBlockNotifier.reset(); }
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

    static constexpr int HEADER_SIZE = BTC::GetBlockHeaderSize();

    std::atomic<size_t> nTx = 0, nIns = 0, nOuts = 0;

    const bool allowSegWit; ///< initted in c'tor. If true, deserialize blocks using the optional segwit extensons to the tx format.
    const bool allowMimble; ///< like above, but if true we allow mimblewimble (litecoin)
    const bool allowCashTokens; ///< allow special cashtoken deserialization rules (BCH only)

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

DownloadBlocksTask::DownloadBlocksTask(unsigned from, unsigned to, unsigned stride, unsigned nClients, Controller *ctl_)
    : CtlTask(ctl_, QStringLiteral("Task.DL %1 -> %2").arg(from).arg(to)), from(from), to(to), stride(stride),
      expectedCt(unsigned(nToDL(from, to, stride))), max_q(int(nClients)+1),
      allowSegWit(ctl_->isSegWitCoin()), allowMimble(ctl_->isMimbleWimbleCoin()), allowCashTokens(ctl_->isBCHCoin())
{
    FatalAssert( (to >= from) && (ctl_) && (stride > 0), "Invalid params to DonloadBlocksTask c'tor, FIXME!");
    if (stride > 1 || expectedCt > 1) {
        // tolerate slow request responses (up to 10 mins) if downloading multiple blocks
        // fixes issue #116
        reqTimeout = Options::bdTimeoutMax; // 10 mins
        DebugM(objectName(), ": multi-block download, will use very long RPC request timeout of ",
               QString::number(reqTimeout/1e3, 'f', 1), " sec");
    }
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
                    auto rawblock = Util::ParseHexFast(resp.result().toByteArray());
                    const auto header = rawblock.left(HEADER_SIZE); // we need a deep copy of this anyway so might as well take it now.
                    QByteArray chkHash;
                    if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                        PreProcessedBlockPtr ppb;
                        try {
                            const auto cblock = BTC::Deserialize<bitcoin::CBlock>(rawblock, 0, allowSegWit, allowMimble, allowCashTokens, allowMimble /* throw if junk at end if Litecoin (catch deser. bugs) */);
                            ppb = PreProcessedBlock::makeShared(bnum, size_t(rawblock.size()), cblock);
                            if (allowMimble && Debug::isEnabled()) {
                                // Litecoin only
                                bool doSerChk{};
                                if (cblock.mw_blob) {
                                    const auto n = std::min(cblock.mw_blob->size(), size_t(60));
                                    TraceM("MimbleBlock: ", bnum, ", data_size: ", cblock.mw_blob->size(),
                                           ", first ", n, " bytes: ",
                                           Util::ToHexFast(QByteArray::fromRawData(reinterpret_cast<const char *>(cblock.mw_blob->data()), n)));
                                    doSerChk = true;
                                }
                                if (cblock.vtx.size() >= 2 && cblock.vtx.back()->mw_blob && cblock.vtx.back()->mw_blob->size() > 1) {
                                    const auto & tx = *cblock.vtx.back();
                                    const auto n = std::min(tx.mw_blob->size(), size_t(60));
                                    // We debug out in Green here to catch this very rare thing which I have never seen before
                                    // to see if it's possible. Someday can demote this to Trace.
                                    Debug(Log::Green) << "MimbleTxn in block: " << bnum << ", hash: " << QString::fromStdString(tx.GetId().ToString())
                                                      << ", data_size: " << tx.mw_blob->size() << ", first " << n << " bytes: "
                                                      << Util::ToHexFast(QByteArray::fromRawData(reinterpret_cast<const char *>(tx.mw_blob->data()), n));
                                    doSerChk = true;
                                }
                                // check sanity (debug builds only)
                                if constexpr (!isReleaseBuild()) {
                                    if (doSerChk && rawblock != BTC::Serialize(cblock, allowSegWit, allowMimble)) {
                                        Fatal() << "Block re-serialized to different data! FIXME!";
                                        return;
                                    }
                                }
                            } // /Litecoin only
                        } catch (const std::ios_base::failure &e) {
                            // deserialization error -- check if block is segwit and we are not segwit
                            if (!allowSegWit) {
                                try {
                                    const auto cblock2 = BTC::DeserializeSegWit<bitcoin::CBlock>(rawblock);
                                    // If we get here the block deserialized ok as segwit but not ok as non-segwit.
                                    // We must assume that there is some misconfiguration e.g. the remote is BTC
                                    // but DB is not expecting BTC. This can happen if user is using non-Satoshi
                                    // bitcoind with BTC.  We only support /Satoshi... as uagent for BTC due to the
                                    // way that our auto-detection works.
                                    if (std::any_of(cblock2.vtx.begin(), cblock2.vtx.end(),
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

                        rawblock.clear(); // free memory right away (needed for ScaleNet huge blocks)

                        // . <--- NOTE: rawblock not to be used beyond this point (it is now empty)

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
/// most efficient.  With full mempools bitcoind CPU usage could spike to 100% if we use the verbose mode.
/// It turns out we don't need that verbose data anyway (such as a full ancestor count) -- it's enough to have a bool
/// flag for "has unconfirmed parent tx", and be done with it.  Everything else we can calculate.
struct SynchMempoolTask : public CtlTask
{
    SynchMempoolTask(Controller *ctl_, std::shared_ptr<Storage> storage, const std::atomic_bool & notifyFlag,
                     const std::unordered_set<TxHash, HashHasher> & ignoreTxns)
        : CtlTask(ctl_, "SynchMempool"), storage(storage), notifyFlag(notifyFlag),
          txnIgnoreSet(ignoreTxns), isSegWit(ctl_->isSegWitCoin()), isMimble(ctl_->isMimbleWimbleCoin()),
          isCashTokens(ctl_->isBCHCoin())
    {
        scriptHashesAffected.reserve(SubsMgr::kRecommendedPendingNotificationsReserveSize);
        txidsAffected.reserve(SubsMgr::kRecommendedPendingNotificationsReserveSize);
    }
    ~SynchMempoolTask() override;
    void process() override;

    const std::shared_ptr<Storage> storage;
    const std::atomic_bool & notifyFlag;
    bool isdlingtxs = false;
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

    void clear() {
        isdlingtxs = false;
        txsNeedingDownload.clear(); txsWaitingForResponse.clear(); txsDownloaded.clear(); txsFailedDownload.clear();
        txsIgnored.clear();
        expectedNumTxsDownloaded = 0;
        lastProgress = 0.;
        // Note: we don't clear "scriptHashesAffected" intentionally in case we are retrying. We want to accumulate
        // all the droppedTx scripthashes for each retry, so we never clear the set.
        // Note 2: we also never clear the redoCt since that counter needs to maintain state to abort too many redos.
        // Note 3: we also never clear dspTxsAffected
        // Note 4: we never clear txidsAffected
    }

    /// Called when getrawtransaction errors out or when we dropTxs() and the result is too many txs so we must
    /// do getrawmempool again.  Increments redoCt. Note that if redoCt > kRedoCtMax, will implicitly error out.
    /// Implicitly calls AGAIN().
    void redoFromStart();

    void doGetRawMempool();
    void doDLNextTx();
    void processResults();

    /// Update the lastProgress stat for /stats endpoint
    void updateLastProgress(std::optional<double> val = std::nullopt);
};

SynchMempoolTask::~SynchMempoolTask() {
    stop(); // paranoia
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
            //DebugM(objectName(), ": txidsAffected: ", txidsAffected.size());
            storage->txSubs()->enqueueNotifications(std::move(txidsAffected));
        }
    }

    if (elapsed.secs() >= 1.0) {
        // if total runtime for task >1s, log for debug
        DebugM(objectName(), " elapsed total: ", elapsed.secsStr(), " secs");
    }
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
        printMempoolStatusToLog(newSize, numAddresses, -1, false);
    }
}
// static
void Controller::printMempoolStatusToLog(size_t newSize, size_t numAddresses, double msec, bool isDebug, bool force)
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
        if (msec > 0.5) // only print this stat if the lock was held for >0.5 msec
            log << " (exclusive lock held for " << QString::number(msec, 'f', 3) << " msec)";
        if (!force) {
            oldSize = newSize;
            oldNumAddresses = numAddresses;
            lastTS = now;
        }
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

    // precache the confirmed spends with the lock held in shared mode, allowing for concurrency during this slow operation
    using ConfirmedSpendCache = std::unordered_map<TXO, std::optional<TXOInfo>>;
    ConfirmedSpendCache cache;
    cache.reserve(128); // reserve a bit of memory so we don't start from 0 and so we don't have to rehash right away
    updateLastProgress(0.6);
    struct { std::size_t nTxs, nHashXs; } sizes; // save the numeber of txs in mempool to detect if another thread modified mempool
    Tic cachet0;
    {
        // we do this with the shared lock (read lock) -- this at least prevents block processing from taking mempool away as we run
        // but it also allows concurrency with clients, etc that want their requests serviced while we read from disk.
        auto [mempool, lock] = storage->mempool();
        cachet0 = Tic(); // start timestamp
        // save mempool size to detect mempool change after we relese and re-acquire the lock in exclusive mode
        // this hopefully detects if the block processing task somehow ran in between the time we release and reacquire
        std::tie(sizes.nTxs, sizes.nHashXs) = std::tuple(mempool.txs.size(), mempool.hashXTxs.size());
        // iterate through all vins for all txs and find the confirmed spends (not already in mempool) and
        // read their TXOInfo's from the db.
        for (const auto & [txid, pair] : txsDownloaded) {
            const auto & [tx, ctx] = pair;
            for (const auto & in : ctx->vin) {
                const TXO txo{BTC::Hash2ByteArrayRev(in.prevout.GetTxId()), IONum(in.prevout.GetN())};
                if (mempool.txs.count(txo.txHash) || txsDownloaded.count(txo.txHash))
                    continue; // unconfirmed spend, we don't pre-cache this, continue
                // otherwise look it up in the db and cache the resulting answer
                cache.emplace(txo, storage->utxoGetFromDB(txo, false)); // may throw on very low level db error; returns nullopt if not found
            }
        }
        cachet0.fin(); // end timestamp
    }
    if (cache.size())
        DebugM("Mempool: pre-cache of ", cache.size(), Util::Pluralize(" confirmed spend", cache.size()),
               " from db took ", cachet0.msecStr(), " msec");

    updateLastProgress(0.75);

    // At this point we pre-cached all the confirmed spends (we hope) with the shared lock held. We did this
    // because holding the exclusive lock for all this time while accessing the db would be *very* slow on
    // full mempools the first time we get e.g. 20k txs.  Before we came up with this scheme, we held the
    // exclusive lock while accessing the db and Fulcrum would freeze on chains such as BTC when first
    // starting up as it built up the initial large mempool.  With this scheme, it runs much faster.

    auto res = [this, &cache, &sizes] {
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
        // check that the mempool didn't change
        if (UNLIKELY(std::tie(sizes.nTxs, sizes.nHashXs) != std::tuple(mempool.txs.size(), mempool.hashXTxs.size()))) {
            // This size heuristic is enough because other subsystems can only drop or clear, never add.
            // This branch should rarely be taken in practice but it pays to be defensive.
            throw InternalError("Warning: Mempool changed in between the time we released the shared lock and "
                                "re-acquired the lock exclusively.  We will try again later...");
        }
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
                    // keep going
                    updateLastProgress();
                    AGAIN();
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

        txidsAffected.insert(tx->hash);
        txsWaitingForResponse.erase(tx->hash);
        updateLastProgress();
        AGAIN();
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
        // otherwise, keep going
        updateLastProgress();
        AGAIN();
    });
}

void SynchMempoolTask::doGetRawMempool()
{
    submitRequest("getrawmempool", {false}, [this](const RPC::Message & resp){
        std::size_t newCt = 0, droppedCt = 0, ignoredCt = 0;
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
                if (txnIgnoreSet.find(hash) != txnIgnoreSet.end()) {
                    // suppressed txn (in ignore set)
                    if (TRACE) Debug() << "Ignored mempool tx: " << hash.toHex();
                    ++ignoredCt;
                } else {
                    // new txn
                    if (TRACE) Debug() << "New mempool tx: " << hash.toHex();
                    ++newCt;
                    Mempool::TxRef tx = std::make_shared<Mempool::Tx>();
                    tx->hashXs.max_load_factor(.9); // hopefully this will save some memory by expicitly setting max table size to 90%
                    tx->hash = hash;
                    // Note: we end up calculating the fee ourselves since I don't trust doubles here. I wish bitcoind would have returned sats.. :(
                    txsNeedingDownload[hash] = tx;
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
                   droppedCt, " dropped, ", newCt, " new");
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
        Retry, RetryInIBD,
        SynchMempool, SynchingMempool, SynchMempoolFinished,
        SynchDSPs, SynchingDSPs, SynchDSPsFinished, // happens after synch mempool; only reached if bitcoind has the dsproof rpc
    };
    State state = Begin;
    bool suppressSaveUndo = false; ///< true if bitcoind is in IBD, in which case we don't save undo info.
    int ht = -1; ///< the latest height bitcoind told us this run
    int nHeaders = -1; ///< the number of headers our bitcoind has, in the chain we are synching
    BTC::Net net = BTC::Net::Invalid;  ///< This gets set by calls to getblockchaininfo by parsing the "chain" in the resulting dict

    robin_hood::unordered_map<unsigned, PreProcessedBlockPtr> ppBlocks; // mapping of height -> PreProcessedBlock (we use robin_hood because it's faster for frequent updates)
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

    /// will be valid and not empty only if a zmq hashblock notification happened while we were running the block & mempool synch task
    QByteArray mostRecentZmqNotif;

    /// This is valid only if we are in an initial sync
    std::optional<Storage::InitialSyncRAII> initialSyncRaii;
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
            else if (bnum > 550'000 && !isSegWitCoin()) // beyond this height we may start to see 32MB blocks in the future
                maxBackLog = 100;
        } else if (sm->net == BTC::ScaleNet) {
            if (bnum > 10'000)
                maxBackLog = 10; // on ScaleNet, after block 10,000 -- we may start to hit big blocks.
        } else if (sm->net == BTC::TestNet4) {
            // nothing, use 1000 always, testnet4 has has 2MB blocks.
        } else {
            // testnet
            if (bnum > 1'300'000) // beyond this height 32MB blocks may be common, esp. in the future
                maxBackLog = isSegWitCoin() ? 250 : 100;
        }

        const int diff = int(bnum) - int(sm->ppBlkHtNext.load()); // note: ppBlkHtNext is not guarded by the lock but it is an atomic value, so that's fine.
        if ( diff > maxBackLog ) {
            // Make the backoff time be from 10ms to 50ms, depending on how far in the future this block height is from
            // what we are processing.  The hope is that this enforces some order on future block arrivals and also
            // prevents excessive polling for blocks that are too far ahead of us.
            return std::min(10u + 5u*unsigned(diff - maxBackLog - 1), 50u); // TODO: also have this be tuneable
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

void Controller::add_DLBlocksTask(unsigned int from, unsigned int to, size_t nTasks)
{
    DownloadBlocksTask *t = newTask<DownloadBlocksTask>(false, unsigned(from), unsigned(to), unsigned(nTasks), options->bdNClients, this);
    // notify BitcoinDMgr that we are in a block download when the first task starts
    connect(t, &CtlTask::started, this, [this]{
        const auto nTasksExtant = ++nDLBlocksTasks;
        if (nTasksExtant == 1) emit downloadingBlocks(true);
        // defensive programming
        FatalAssert(size_t(nTasksExtant) <= tasks.size(), "nTasksExtant = ", nTasksExtant, ", tasks.size() = ", tasks.size(), "! FIXME!");
    });
    // when the last DownloadBlocksTask ends, notify that block download is done.
    connect(t, &CtlTask::finished, this, [this]{
        const auto nTasksRemaining = --nDLBlocksTasks;
        if (nTasksRemaining == 0) emit downloadingBlocks(false);
        // defensive programming, detect asymmetry between started/finished signals
        FatalAssert(nTasksRemaining >= 0, "nTasksRemaining = ", nTasksRemaining, "! FIXME!");
    });
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
    CtlTaskT *task{};
    {
        auto uptr = std::make_unique<CtlTaskT>(std::forward<Args>(args)...); // idiomatic way to avoid leaks if exceptions are thrown
        task = uptr.get();
        tasks.emplace(task, std::move(uptr));
    }
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

            // Ensure genesis hash matches what we have in DB (post-initial sync only)
            if (const auto hashDaemon = bitcoindmgr->getBitcoinDGenesisHash(), hashDb = storage->genesisHash();
                    !hashDb.isEmpty() && !hashDaemon.isEmpty() && hashDb != hashDaemon) {
                Fatal() << "Bitcoind reports genesis hash: \"" << hashDaemon.toHex() << "\", which differs from our "
                        << "database: \"" << hashDb.toHex() << "\". You may have connected to the wrong bitcoind. "
                        << "To fix this issue either connect to a different bitcoind or delete this program's datadir "
                        << "to resynch.";
                return;
            }

            // Check that "chain" didn't change, and if it did, warn and save new chain to db if it's one we
            // understand.
            const auto & chain = task->info.chain;
            const auto normalizedChain = BTC::NetNameNormalize(chain);
            const auto net = BTC::NetFromName(chain);
            if (const auto dbchain = storage->getChain();
                    dbchain != normalizedChain && !normalizedChain.isEmpty() && net != BTC::Net::Invalid) {
                if (!dbchain.isEmpty()) {
                    Warning() << "Database had chain \"" << dbchain << "\", but bitcoind reports chain \"" << normalizedChain
                              << "\".  Persisting \"" << normalizedChain << "\" to database.  Please ensure that you"
                              << " are connected to the correct bitcoind instance!";
                }
                // save the normalized chain to the db, if we were able to grok it. Older versions of Fulcrum
                // will expect to see it in the DB since they use it to check sanity.  Newer versions >= 1.2.7
                // instead query bitcoind for its genesish hash and compare it to db.
                storage->setChain(normalizedChain);
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
                const bool hasUndo = storage->hasUndo();
                if (task->info.initialBlockDownload && !hasUndo) {
                    sm->suppressSaveUndo = sm->nHeaders > 0 && sm->ht > 0 && sm->nHeaders >= sm->ht
                                           && unsigned(sm->nHeaders - sm->ht) > storage->configuredUndoDepth();
                }

                // Set initial sync flag, if we are in initial sync (heuristic is: initial sync == we have no undo data)
                // Note: This may not be the best place for this. Also, if assumptions change, this will not
                // work as before. TODO: revisit the placement of where this logic goes.
                if (!hasUndo && !sm->initialSyncRaii)
                    sm->initialSyncRaii.emplace( storage->setInitialSync() );
                else if (sm->initialSyncRaii && hasUndo)
                    sm->initialSyncRaii.reset();
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
            add_DLBlocksTask(unsigned(base + i), unsigned(sm->ht), nTasks);
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
        if (!sm->mostRecentZmqNotif.isEmpty()) {
            if (sm->mostRecentZmqNotif != storage->latestTip().second) {
                // While we were synching -- a zmq notification happened -- and it told us about a block header that is
                // not our latest tip. Just to be sure, schedule us to run again immediately.
                polltimeout = 0;
                DebugM("zmq hashblock received with a (possibly) new header while we were synching, re-scheduling"
                       " another bitcoind update immediately ...");
            } else
                DebugM("zmq hashblock received while we were synching, however it matches our latest tip, ignoring ...");
        }
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
        auto task = newTask<SynchMempoolTask>(true, this, storage, masterNotifySubsFlag, mempoolIgnoreTxns);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress verbose lifecycle prints unless trace mode
        connect(task, &CtlTask::success, this, [this, task]{
            if (UNLIKELY(!sm || isTaskDeleted(task) || sm->state != State::SynchingMempool))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            sm->state = State::SynchMempoolFinished;
            AGAIN();
        });
        sm->state = State::SynchingMempool;
    } else if (sm->state == State::SynchDSPs) {
        auto task = newTask<SynchDSPsTask>(false, this, storage, masterNotifySubsFlag);
        task->threadObjectDebugLifecycle = Trace::isEnabled(); // suppress verbose lifecycle prints unless trace mode
        connect(task, &CtlTask::success, this, [this, task]{
            if (UNLIKELY(!sm || isTaskDeleted(task) || sm->state != State::SynchingDSPs))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            sm->state = State::SynchDSPsFinished;
            AGAIN();
        });
        // synch mempool task is an optional task, not critical. tolerate errors as if they were successes
        connect(task, &CtlTask::errored, this, [this, task]{
            if (UNLIKELY(!sm || isTaskDeleted(task) || sm->state != State::SynchingDSPs))
                // task was stopped from underneath us and/or this response is stale.. so return and ignore
                return;
            Warning() << "SynchDSPs RPC error, ignoring...";
            sm->state = State::SynchDSPsFinished;
            AGAIN();
        });
        sm->state = State::SynchingDSPs;
    } else if (sm->state == State::SynchingMempool || sm->state == State::SynchingDSPs) {
        // ... nothing..
    } else if (sm->state == State::SynchMempoolFinished) {
        // ...
        if (bitcoindmgr->hasDSProofRPC())
            sm->state = State::SynchDSPs; // remote bitcoind has dsproof rpc, proceed to synch dsps
        else
            sm->state = State::End; // remote bitcoind lacks dsproof rpc, finish successfully
        AGAIN();
    } else if (sm->state == State::SynchDSPsFinished) {
        // ...
        sm->state = State::End;
        AGAIN();
    }

    if (enablePollTimer)
        callOnTimerSoonNoRepeat(polltimeout, pollTimerName, [this]{ on_Poll(); });
}

void Controller::on_Poll(std::optional<QByteArray> zmqBlockHash)
{
    if (!sm)
        process(true); // process immediately
    else if (zmqBlockHash)
        sm->mostRecentZmqNotif = std::move(*zmqBlockHash); // deferred processing for when current task completes
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
            return rate > 0.0 ? QStringLiteral("%1%2 %3/%4").arg(QString{addComma ? ", " : ""}, format(rate), thing, unit) : QString{};
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
    unsigned ct [[maybe_unused]] = 0;

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
        for (const auto & [task, ign] : tasks) {
            Q_UNUSED(ign)
            l.push_back(QVariantMap{{ task->objectName(), QVariantMap{
                {"age", QString("%1 sec").arg(task->elapsed.secsStr())} ,
                {"progress" , QString("%1%").arg(QString::number(task->lastProgress*100.0, 'f', 1)) }}
            }});
        }
        Util::updateMap(m, QVariantMap{{"tasks" , l}});
    }
    { // ZMQ
        QVariantMap m2;
        if (zmqHashBlockNotifier && zmqHashBlockNotifier->isRunning()) {
            QVariantMap m3;
            m3["address"] = lastKnownZmqHashBlockAddr;
            m3["notifications"] = zmqHashBlockNotifCt;
            m2["hashblock"] = m3;
        }
        m["ZMQ Notifiers (active)"] = m2;
    }
    st["Controller"] = m;
    st["Storage"] = storage->statsSafe();
    QVariantMap misc;
    misc["Job Queue (Thread Pool)"] = ::AppThreadPool()->stats();
    st["Misc"] = misc;
    st["SubsMgr"] = storage->subs()->statsSafe(kDefaultTimeout/2);
    st["SubsMgr (DSPs)"] = storage->dspSubs()->statsSafe(kDefaultTimeout/4);
    st["SubsMgr (Txs)"] = storage->txSubs()->statsSafe(kDefaultTimeout/4);
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

        const auto items = storage->listUnspent(hashx, Storage::TokenFilterOption::IncludeTokens);
        for (const auto & item : items)
            l.push_back(Server::unspentItemToVariantMap(item));
        ret["unspent_debug"] = l;
    }
    if (p.contains("utxo_stats")) {
        // Note: This is slow and times-out on mainnet or even testnet3. Was mainly used for testing on chipnet.
        const auto stats = storage->calcUTXOSetStats([](size_t ctr){ DebugM("utxo_stats: progress counter = ", ctr); });
        QVariantMap m;
        m["block_height"] = qlonglong(stats.block_height);
        m["block_hash"] = QString::fromLatin1(stats.block_hash.toHex());
        m["utxo_db_ct"] = qlonglong(stats.utxo_db_ct);
        m["utxo_db_size_bytes"] = qlonglong(stats.utxo_db_size_bytes);
        m["utxo_db_shasum"] = QString::fromLatin1(stats.utxo_db_shasum.toHex());
        m["shunspent_db_ct"] = qlonglong(stats.shunspent_db_ct);
        m["shunspent_db_size_bytes"] = qlonglong(stats.shunspent_db_size_bytes);
        m["shunspent_db_shasum"] = QString::fromLatin1(stats.shunspent_db_shasum.toHex());
        ret["utxo_stats"] = m;
    }
    if (p.contains("mempool")) {
        auto [mempool, lock] = storage->mempool();
        ret["mempool_debug"] = mempool.dump();
    }
    if (p.contains("subs")) {
        const auto timeLeft = kDefaultTimeout - (Util::getTime() - t0/1000000) - 50;
        ret["subscriptions"] = storage->subs()->debugSafe(p, std::max(5, int(timeLeft)));
    }
    if (p.contains("dspsubs")) {
        const auto timeLeft = kDefaultTimeout - (Util::getTime() - t0/1000000) - 50;
        ret["subscriptions (DSProof)"] = storage->dspSubs()->debugSafe(p, std::max(5, int(timeLeft)));
    }
    if (p.contains("txsubs")) {
        const auto timeLeft = kDefaultTimeout - (Util::getTime() - t0/1000000) - 50;
        ret["subscriptions (Txs)"] = storage->txSubs()->debugSafe(p, std::max(5, int(timeLeft)));
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

void Controller::zmqHashBlockStart()
{
    if (!ZmqSubNotifier::isAvailable()) {
        DebugM(__func__, ": zmq unavailable, ignoring start request");
        zmqHashBlockNotifier.reset(); // ensure it's dead -- should never be alive in this case (indicates a bug).
        return;
    }
    if (!zmqHashBlockNotifier) {
        // first time through, create a new notifier
        zmqHashBlockNotifier = std::make_unique<ZmqSubNotifier>(this);
        zmqHashBlockNotifier->setObjectName("ZMQ Notifier (hashblock)");
        // connect signals
        conns += connect(zmqHashBlockNotifier.get(), &ZmqSubNotifier::errored, this, [](const QString &errMsg){
            Warning() << "zmqHashBlockNotifier: " << errMsg;
        });
        conns += connect(zmqHashBlockNotifier.get(), &ZmqSubNotifier::gotMessage, this, [this](const QString &topic, const QByteArrayList &parts) {
            std::optional<QByteArray> optHash;
            if (Debug::isEnabled()) {
                Debug d;
                d << "got zmq " << topic << " notification: ";
                int i = 0;
                for (const auto & part : parts) {
                    if (i++) d << ", ";
                    if (i == 1) // topic string
                        d << QString(part);
                    else if (i == 3) // sequence number (little endian)
                        d << bitcoin::ReadLE32(reinterpret_cast<const uint8_t *>(part.constData()));
                    else { // block hash (binary, big endian byte order)
                        optHash = part;
                        d << QString(Util::ToHexFast(part));
                    }
                 }
            }
            if (!optHash && parts.size() >= 2) {
                const auto &part = parts[1]; // blockhash is second element
                if (part.size() == 32) // ensure proper format
                    optHash = part; // this is already in big endian order (which is how we also store them)
            }
            if (UNLIKELY(!optHash))
                Error() << "Unexpected format: got zmq hashblock notification but it is missing the block hash!";
            else
                ++zmqHashBlockNotifCt;
            // notify (may end up calling this->process())
            on_Poll(std::move(optHash));
        });
    }
    if (zmqHashBlockNotifier->isRunning())
        zmqHashBlockNotifier->stop();
    if (lastKnownZmqHashBlockAddr.isEmpty()) {
        DebugM(__func__, ": zmq hashblock address is empty, ignoring start request");
        return;
    }
    if (!zmqHashBlockDidLogStartup) {
        zmqHashBlockDidLogStartup = true;
        Log() << "Starting " << zmqHashBlockNotifier->objectName() << " ...";
    }
    if (!zmqHashBlockNotifier->start(lastKnownZmqHashBlockAddr, "hashblock", 30 * 60 * 1000 /* idle timeout: 30 mins in msecs */)) {
        Warning() << __func__ << ": start failed";
    }
}

void Controller::zmqHashBlockStop()
{
    if (!zmqHashBlockNotifier || !zmqHashBlockNotifier->isRunning())
        return;
    zmqHashBlockNotifier->stop();
}

// --- Debug dump support
void Controller::dumpScriptHashes(const QString &fileName)
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
