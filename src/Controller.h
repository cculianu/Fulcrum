//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "BitcoinD.h"
#include "BTC.h"
#include "BlockProc.h"
#include "Mixins.h"
#include "Options.h"
#include "Storage.h"
#include "SrvMgr.h"

#include <atomic>
#include <concepts> // for std::derived_from
#include <functional> // for std::hash
#include <iterator> // for std::size
#include <memory>
#include <optional>
#include <tuple>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility> // for std::pair

class CtlTask;
class SSLCertMonitor;
class ZmqSubNotifier;

class Controller : public Mgr, public ThreadObjectMixin, public TimersByNameMixin, public ProcessAgainMixin
{
    Q_OBJECT
public:
    explicit Controller(const std::shared_ptr<const Options> & options, const SSLCertMonitor *certMon /* nullable */);
    ~Controller() override;

    void startup() override; ///< may throw
    void cleanup() override;

    const int polltimeMS; ///< the amount of time for polling bitcoind for new headers -- comes from options->pollTimeSecs

    inline bool isStopping() const { return stopFlag; }

    /// Returns a positive nonzero value if the calling download task should throttle because the backlog is too large.
    /// In that case the caller should try again in the returned value ms.
    /// If the return value is 0, the caller may proceed immediately to continue downloading headers.
    /// This function is not intended to be used by code outside this subsystem -- it is intended to be called by the
    /// internal DownloadBlocksTask only.
    unsigned downloadTaskRecommendedThrottleTimeMsec(unsigned forBlockHeight) const;

    QVariantMap statsDebug(const QMap<QString, QString> & params) const;

    /// Helper for log printing mempool status. Called this instance (from a timer), also called from the SynchMempoolTask
    /// for debug printing when it receives new mempool tx's.
    static void printMempoolStatusToLog(size_t newSize, size_t numAddresses, double msec, bool useDebugLogger, bool force = false);

    /// Thread-safe, lock-free, returns true for BTC and LTC
    bool isSegWitCoin() const {
        auto const c = coinType.load(std::memory_order_relaxed);
        return c == BTC::Coin::BTC || c == BTC::Coin::LTC;
    }

    /// Thread-safe, lock-free, returns true for LTC
    bool isMimbleWimbleCoin() const { return coinType.load(std::memory_order_relaxed) == BTC::Coin::LTC; }

    /// Thread-safe, lock-free, returns true for BCH. Note: also returns true for "Unknown" coins since we "prefer" BCH
    /// if we happen to have a regression where the coin info is not propagated from BitcoinDMgr. This is to ensure
    /// that on BCH, CashTokens always deserialize correctly.
    bool isBCHCoin() const {
        const auto type = coinType.load(std::memory_order_relaxed);
        return type == BTC::Coin::BCH || type == BTC::Coin::Unknown;
    }

    /// Type used internally by the putRpaIndex signal
    struct RpaOnlyModeData {
        BlockHeight height{};
        QByteArray serializedPrefixTable;
        size_t nTx{}, nTxsIndexed{}, nIns{}, nInsIndexed{}, nOuts{}, rawBlockSizeBytes{};
    };
    using RpaOnlyModeDataPtr = std::shared_ptr<RpaOnlyModeData>;

signals:
    /// Emitted whenever bitcoind is detected to be up-to-date, and everything (except mempool) is synched up.
    /// note this is not emitted during regular polling, but only after `synchronizing` was emitted previously.
    void upToDate();
    /// Emitted whenever we begin dl'ing blocks from bitcoind. After this completes successfully, upToDate will be
    /// emitted exactly once.
    /// This signal may be emitted multiple times if there were errors and we are periodically retrying.
    void synchronizing();
    /// Emitted whenever we failed to synchronize to bitcoind.
    void synchFailure();
    /// Emitted wheneever upToDate() is emitted. This is identical except the header info is also sent. This is used by
    /// blockchain.headers.subscribe system. See Servers.cpp.
    void newHeader(unsigned height, const QByteArray & header);

    /// "Private" signal, not intended to be used by outside code. Used internally to send blocks that are ready from
    /// any thread to to this object for processing in Controller's thread. Connected to the on_putBlock slot.
    /// This is typially called from the DownloadBlocksTask. (Note: we did it this way, using a signal/slot, rather
    /// than a more succinct and anonymous Util::AsyncOnObject() call, because on Linux, the timer events arrive
    /// *after* signal/slots do.. and they arrive out-of-order with respect to them -- and we want to make sure to
    /// get all the blocks *before* the DownloadBlocksTasks are removed after they finish).
    void putBlock(CtlTask *sender, PreProcessedBlockPtr);

    /// "Private" signal, not intended to be used by outside code. Used internally to send serialized processed prefix
    /// table data that is ready from any thread to to this object for processing in Controller's thread.
    void putRpaIndex(CtlTask *sender, Controller::RpaOnlyModeDataPtr);

    /// Emitted only iff the user specified --dump-sh on the CLI. This is emitted once the script hash dump has completed.
    void dumpScriptHashesComplete();

    /// "Private" signal, not intended to be used by outside code.  Used internally to mark a txHash as to be "ignored"
    /// and not downloaded from the mempool.  The private SynchMempoolTask emits this to add hashes to our mempoolIgnoreTxns
    /// set in a thread-safe manner
    void ignoreMempoolTxn(const QByteArray & txhash);

    /// Emitted whenever we begin downloading blocks, and whenever we end the last DownloadBlocksTask (for whatever reason)
    void downloadingBlocks(bool b);

    /// Emitted after a successful mempool synch. This is emitted more often than upToDate() (which is only emitted
    /// when new blocks arrive); this is emitted every time we successfully poll the mempool for new txns.
    void synchedMempool();

protected:
    Stats stats() const override; // from StatsMixin
    Stats debug(const StatsParams &) const override; // from StatsMixin

protected slots:
    void process(bool beSilentIfUpToDate); ///< generic callback to advance state
    void process() override { process(false); } ///< from ProcessAgainMixin

    /// Slot for putBlock signal. Runs in this thread, adds the block to the queue and kicks off block processing (if
    /// the supplied block was the next one by height).
    void on_putBlock(CtlTask *, PreProcessedBlockPtr);

    /// Slot for the BitcoinDMgr::bitcoinCoreDetection. This is compared to this->coinType and if there is a
    /// mismatch there, we may end up aborting the app and logging an error in this slot.
    void on_coinDetected(BTC::Coin); //< NB: Connected via DirectConnection and may run in the BitcoinDMgr thread!

    /// Slot for putRpaIndex signal. Runs in this thread, adds the supplied data to the RPA index.
    void on_putRpaIndex(CtlTask *, Controller::RpaOnlyModeDataPtr);

private:
    friend class CtlTask;
    /// \brief newTask - Create a specific task using this template factory function. The task will be auto-started the
    ///        next time this thread enters the event loop, via a QTimer::singleShot(0,...).
    ///
    /// \param connectErroredSignal If true, auto-connect signal CtlTask::errored() to this->genericTaskErrored()
    /// \param args The rest of the args get passed to the c'tor of the concrete class specified (in the template arg).
    /// \return Returns the newly constructed CtrlTask* subclass. Note the task will start as soon as control returns
    ///         to this thread's event loop, and the task is already emplaced into the `tasks` map when this function
    ///         returns.
    template <std::derived_from<CtlTask> CtlTaskT, typename ...Args>
    CtlTaskT *newTask(bool connectErroredSignal, Args && ...args);
    /// remove and stop a task (called after task finished() signal fires)
    void rmTask(CtlTask *);
    /// returns true iff t is not in the tasks list
    bool isTaskDeleted(CtlTask *t) const;

    /// The default 'errored' handler used if a task was created with connectErroredSignal=true in newTask above.
    void genericTaskErrored();
    static constexpr auto pollTimerName = "pollForBlockchainChanges";

    const std::shared_ptr<const Options> options;
    const SSLCertMonitor * const sslCertMonitor;
    std::shared_ptr<Storage> storage; ///< shared with srvmgr, but we control its lifecycle
    std::shared_ptr<BitcoinDMgr> bitcoindmgr; ///< shared with srvmgr, but we control its lifecycle
    std::unique_ptr<SrvMgr> srvmgr; ///< NB: this may be nullptr if we haven't yet synched up and started listening.  Additionally, this should be destructed before storage or bitcoindmgr.

    struct StateMachine;
    std::unique_ptr<StateMachine> sm;
    mutable std::shared_mutex smLock;

    std::unordered_map<CtlTask *, std::unique_ptr<CtlTask>, Util::PtrHasher> tasks;
    int nDLBlocksTasks = 0;

    CtlTask * add_DLBlocksTask(unsigned from, unsigned to, size_t nTasks, bool isRpaOnlyMode);
    void process_DownloadingBlocks();
    bool process_VerifyAndAddBlock(PreProcessedBlockPtr); ///< helper called from within DownloadingBlocks state -- makes sure block is sane and adds it to db
    void process_PrintProgress(const QString &verb, unsigned height, size_t nTx, size_t nIns, size_t nOuts, size_t nSH,
                               size_t rawBlockSizeBytes, bool showRateBytes, std::optional<double> pctOverride = std::nullopt);
    void process_DoUndoAndRetry(); ///< internal -- calls storage->undoLatestBlock() and schedules a task death and retry.
    template <typename T>
    void on_putCommon(CtlTask *, const T &, int expectedState, const QString &expectedStateName); ///< internal. Called by on_putBlock and on_PutRpaIndex.

    size_t nBlocksDownloadedSoFar() const; ///< not 100% accurate. call this only from this thread
    std::tuple<size_t, size_t, size_t> nTxInOutSoFar() const; ///< not 100% accurate. call this only from this thread

    std::atomic_bool stopFlag = false;
    bool lostConn = true;
    /// Master subscription notification flag. Initially we don't do notifications. However, after we start the srvmgr,
    /// this gets set to true permanently, and future blocks/undoes/mempool changes notify the app-wide SubsMgr, which
    /// notifies subscribed clients (if any).
    std::atomic_bool masterNotifySubsFlag = false;

    /// Comes from DB. If DB had no entry (newly initialized DB), then we update this variable whe we first connect
    /// to the BitcoinD.  We look for "/Satoshi..." in the useragen to set BTC, otherwise everything else is BCH.
    std::atomic<BTC::Coin> coinType = BTC::Coin::Unknown;

    /// takes locks, prints to Log() every 30 seconds if there were changes
    void printMempoolStatusToLog() const;

    /// If --dump-sh was specified on CLI, this will execute at startup() time right after storage has been loaded. May throw.
    void dumpScriptHashes(const QString &fileName);

    /// Stores ZMQ notification state for "hashblock" and "hashtx" ZMQ topics from remote bitcoind.
    struct ZmqPvt {
        struct Topic {
            enum class Tag : uint8_t { HashBlock, HashTx };
            const Tag tag;
            // returns: "hashblock" or "hashtx"
            const char *str() const noexcept;
            constexpr auto operator<=>(const Topic &) const noexcept = default;
        };
        using enum Topic::Tag;
        static constexpr const Topic allTopics[] = { {HashBlock}, {HashTx}  /* very spammy, disabled unless zmq_allow_hashtx = true in config */ };
        static constexpr size_t nTopics() noexcept { return std::size(allTopics); }
        struct TopicHasher {
            std::hash<int> hasher;
            inline size_t operator()(Topic t) const noexcept { return hasher(static_cast<int>(t.tag)); }
        };

        struct TopicState {
            /// Will be nullptr if zmq disabled or bitcoind lacks this topic endpoint
            std::unique_ptr<ZmqSubNotifier> notifier;
            /// Populated from bitcoindmgr's zmqNotificationsChanged signal. If empty, remote has no notifications
            /// advertised in `getzmqnotifications` for this topic.
            QString lastKnownAddr;
            /// Permanently latched to true after the first time we start this ZMQ notifier (to suppress logging for subsequent re-starts)
            bool didLogStartup = false;
            /// The number of notifications received from bitcoind via ZMQ for this topic since app start.
            size_t notifCt = 0u;
            ~TopicState(); // must define d'tor in Controller.cpp translation unit due to incomplete ZmqSubNotifier type
        };

        std::unordered_map<Topic, TopicState, TopicHasher> map{nTopics()};

        TopicState & operator[](Topic t); // must define in Controller.cpp translation unit due to incomplete ZmqSubNotifier type
        TopicState *find(Topic t) noexcept { if (auto it = map.find(t); it != map.end()) return &it->second; return nullptr; }

        auto begin() { return map.begin(); }
        auto begin() const { return map.begin(); }
        auto end() { return map.end(); }
        auto end() const { return map.end(); }
        size_t erase(Topic t);

        ~ZmqPvt(); // must define d'tor in Controller.cpp translation unit due to incomplete ZmqSubNotifier type
    } zmqs;

    using ZmqTopic = ZmqPvt::Topic;

    /// (re)starts listening for notifications from the ZmqNotifier for this topic; called if we received a valid zmq
    /// address for this topic from BitcoinDMgr, after servers are started.
    void zmqTopicStart(ZmqTopic topic);

    /// Stops the ZmqNotifier for this topic; called if we received an empty address for this topic from BitcoinDMgr or
    /// when all connections to bitcoind are lost
    void zmqTopicStop(ZmqTopic topic);

    /// (re)starts all zmq notifiers that have a non-empty lastKnownAddr
    void zmqStartAllKnown();

    /// Stops all notifiers that are running. If cleanup==true also deletes all notifier instances.
    void zmqStopAll(bool cleanup = false);

    /// Litecoin only: Ignore these txhashes from mempool (don't download them). This gets cleared each time
    /// before the first SynchMempool after we receive a new block, then is persisted for all the SynchMempools
    /// for that block, until a new block arrives, then is cleared again.
    std::unordered_set<TxHash, HashHasher> mempoolIgnoreTxns;

    /// Used to update the mempool fee histogram early right after the synchedMempool() signal is emitted
    bool needFeeHistogramUpdate = true;

    /// Latched to true as soon as on_coinDetected is called at least once. This allows us to wait until bitcoind tells
    /// us what coin we are connected to before we proceed with initial synch. Also latched to true if we already have
    /// a "coin" defined in storage already.
    std::atomic_bool didReceiveCoinDetectionFromBitcoinDMgr = false;

    /// Used internally to decide if we need to skip the RPA is sane check or not
    bool skipRpaSanityCheck = false;

    /// Called by controller in its state machine processing function -- returns false normally, but if true is returned
    /// then the state machine has already advanced to GetBlocks_RPA and the controller should return early return from
    /// its current process() invocation.
    bool checkRpaIndexNeedsSync(int tipHeight);

protected:
    /// Called from the poll timer to restart the state machine and get latest blocks and mempool (process());
    /// Also called if we received a zmq hashblock or hashtx notification (in which case it will be called with the valid
    /// header or tx hash, already in big endian byte order).
    void on_Poll(std::optional<std::pair<ZmqTopic, QByteArray>> zmqNotifOpt = std::nullopt);
};

/// Abstract base class for our private internal tasks. Concrete implementations are in Controller.cpp.
class CtlTask : public QObject, public ThreadObjectMixin, public ProcessAgainMixin
{
    Q_OBJECT
public:
    CtlTask(Controller *ctl, const QString &name = "UnnamedTask");
    ~CtlTask() override;

    int errorCode = 0;
    QString errorMessage = "";

    std::atomic<double> lastProgress = 0.0;

    const Tic elapsed; ///< to keep track of when the task was created

    using ThreadObjectMixin::start;
    using ThreadObjectMixin::stop;

signals:
    void started();

    // the below 4 signals are all exit points. After they are emitted the task will stop.

    /// Emitted after one of: success(), errored() or retryRecommended() to indicate the task thread has stopped.
    /// The task has or will soon remove itself after this has been emitted.
    void finished();
    /// Emitted if the task has completed successfully. finished() will be emitted afterwards.
    void success();
    /// Emitted if the task has encountered an error. finished() will be emitted afterwards.
    void errored();
    /// Only the SynchMempoolTask emits this when it thinks that the mempool looks funny and like a new block may have
    /// arrived. After this is emitted the task will stop. The Controller listens for this and immediately retries
    /// a full poll cycle of bitcoind. finished() will be emitted afterwards.
    void retryRecommended();

    void progress(double); ///< some tasks emit this to indicate progress. may be a number from 0->1.0 or anything else (task specific)
protected:
    void on_started() override;
    void on_finished() override;

    void process() override = 0; ///< from ProcessAgainMixin -- here to illustrate it's still pure virtual

    void on_error(const RPC::Message &);
    void on_error_retry(const RPC::Message &, const char *msg);
    void on_failure(const RPC::Message::Id &, const QString &msg);

    using ResultsF = BitcoinDMgr::ResultsF;
    using ErrorF = BitcoinDMgr::ErrorF;
    quint64 submitRequest(const QString &method, const QVariantList &params, const ResultsF &resultsFunc,
                          const ErrorF &errorFunc = {});

    Controller * const ctl; ///< initted in c'tor. Is always valid since all tasks' lifecycles are managed by the Controller.
    int reqTimeout; ///< initted in c'tor, cached from ctl->options->bdTimeout. DownloadBlocksTask overrides this with a custom value if doing multi-block DL
};

Q_DECLARE_METATYPE(CtlTask *);
Q_DECLARE_METATYPE(PreProcessedBlockPtr);
Q_DECLARE_METATYPE(Controller::RpaOnlyModeDataPtr);
