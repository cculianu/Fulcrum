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

#include "BitcoinD.h"
#include "BlockProc.h"
#include "Mixins.h"
#include "Options.h"
#include "Storage.h"
#include "SrvMgr.h"

#include "robin_hood/robin_hood.h"

#include <atomic>
#include <memory>
#include <tuple>
#include <shared_mutex>
#include <type_traits>
#include <vector>

class CtlTask;

class Controller : public Mgr, public ThreadObjectMixin, public TimersByNameMixin, public ProcessAgainMixin
{
    Q_OBJECT
public:
    explicit Controller(const std::shared_ptr<const Options> & options);
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
    static void printMempoolStatusToLog(size_t newSize, size_t numAddresses, bool useDebugLogger, bool force = false);

signals:
    /// Emitted whenever bitcoind is detected to be up-to-date, and everything is synched up.
    /// note this is not emitted during regular polling, but only after `synchronizing` was emitted previously.
    void upToDate();
    /// Emitted whenever we begin synching to bitcoind. After this completes successfully, upToDate will be emitted
    /// exactly once.
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

    /// Emitted only iff the user specified --dump-sh on the CLI. This is emitted once the script hash dump has completed.
    void dumpScriptHashesComplete() const;

protected:
    Stats stats() const override; // from StatsMixin
    Stats debug(const StatsParams &) const override; // from StatsMixin

protected slots:
    void process(bool beSilentIfUpToDate); ///< generic callback to advance state
    void process() override { process(false); } ///< from ProcessAgainMixin

    /// Slot for putBlock signal. Runs in this thread, adds the block to the queue and kicks off block processing (if
    /// the supplied block was the next one by height).
    void on_putBlock(CtlTask *, PreProcessedBlockPtr);

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
    template <typename CtlTaskT, typename ...Args,
              typename = std::enable_if_t<std::is_base_of_v<CtlTask, CtlTaskT>> >
    CtlTaskT *newTask(bool connectErroredSignal, Args && ...args);
    /// remove and stop a task (called after task finished() signal fires)
    void rmTask(CtlTask *);
    /// returns true iff t is not in the tasks list
    bool isTaskDeleted(CtlTask *t) const;

    /// The default 'errored' handler used if a task was created with connectErroredSignal=true in newTask above.
    void genericTaskErrored();
    static constexpr auto pollTimerName = "pollForNewHeaders";

    const std::shared_ptr<const Options> options;
    std::shared_ptr<Storage> storage; ///< shared with srvmgr, but we control its lifecycle
    std::shared_ptr<BitcoinDMgr> bitcoindmgr; ///< shared with srvmgr, but we control its lifecycle
    std::unique_ptr<SrvMgr> srvmgr; ///< NB: this may be nullptr if we haven't yet synched up and started listening.  Additionally, this should be destructed before storage or bitcoindmgr.

    struct StateMachine;
    std::unique_ptr<StateMachine> sm;
    mutable std::shared_mutex smLock;

    robin_hood::unordered_flat_map<CtlTask *, std::unique_ptr<CtlTask>> tasks;

    void add_DLHeaderTask(unsigned from, unsigned to, size_t nTasks);
    void process_DownloadingBlocks();
    bool process_VerifyAndAddBlock(PreProcessedBlockPtr); ///< helper called from within DownloadingBlocks state -- makes sure block is sane and adds it to db
    void process_PrintProgress(unsigned height, size_t nTx, size_t nIns, size_t nOuts, size_t nSH);
    void process_DoUndoAndRetry(); ///< internal -- calls storage->undoLatestBlock() and schedules a task death and retry.

    size_t nBlocksDownloadedSoFar() const; ///< not 100% accurate. call this only from this thread
    std::tuple<size_t, size_t, size_t> nTxInOutSoFar() const; ///< not 100% accurate. call this only from this thread

    volatile bool stopFlag = false;
    bool lostConn = true;
    /// Master subscription notification flag. Initially we don't do notifications. However, after we start the srvmgr,
    /// this gets set to true permanently, and future blocks/undoes/mempool changes notify the app-wide SubsMgr, which
    /// notifies subscribed clients (if any).
    std::atomic_bool masterNotifySubsFlag = false;

    /// If true, BitcoinDMgr informed us that the bitcoind node we are connected to is bitcoin core (thus we allow segwit)
    std::atomic_bool bitcoinCoreFlag = false;

    /// takes locks, prints to Log() every 30 seconds if there were changes
    void printMempoolStatusToLog() const;

    /// If --dump-sh was specified on CLI, this will execute at startup() time right after storage has been loaded. May throw.
    void dumpScriptHashes(const QString &fileName) const;
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

    const qint64 ts = Util::getTime(); ///< timestamp -- when the task was created

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

    virtual void on_error(const RPC::Message &);
    virtual void on_failure(const RPC::Message::Id &, const QString &msg);

    quint64 submitRequest(const QString &method, const QVariantList &params, const BitcoinDMgr::ResultsF &resultsFunc);

    Controller * const ctl; ///< initted in c'tor. Is always valid since all tasks' lifecycles are managed by the Controller.
    const bool allowSegWitTx; ///< initted in c'tor. If true, subclasses may deserialize tx's using the optional segwit extensons to the tx format.
};

Q_DECLARE_METATYPE(CtlTask *);
Q_DECLARE_METATYPE(PreProcessedBlockPtr);
