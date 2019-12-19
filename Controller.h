#ifndef CONTROLLER_H
#define CONTROLLER_H

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
    explicit Controller(const std::shared_ptr<Options> & options);
    ~Controller() override;

    void startup() override; ///< may throw
    void cleanup() override;

    int polltime_ms = 5 * 1000; ///< the default amount of time for polling bitcoind for new headers

    /// thread-safe -- call this from the slave task thread to submit a block
    /// Note: we had to make this a public member but it's not really intended to be used from code outside this subsystem.
    void putBlock(CtlTask *sender, PreProcessedBlockPtr);

    inline bool isStopping() const { return stopFlag; }

    /// Returns a positive nonzero value if the calling download task should throttle because the backlog is too large.
    /// In that case the caller should try again in the returned value ms.
    /// If the return value is 0, the caller may proceed immediately to continue downloading headers.
    /// This function is not intended to be used by code outside this subsystem -- it is intended to be called by the
    /// internal DownloadBlocksTask only.
    unsigned downloadTaskRecommendedThrottleTimeMsec(unsigned forBlockHeight) const;


    QVariantMap statsDebug(const QMap<QString, QString> & params) const;

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

protected:
    Stats stats() const override; // from StatsMixin
    Stats debug(const StatsParams &) const override; // from StatsMixin

protected slots:
    void process(bool beSilentIfUpToDate); ///< generic callback to advance state
    void process() override { process(false); } ///< from ProcessAgainMixin

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

    const std::shared_ptr<Options> options;
    std::shared_ptr<Storage> storage; ///< shared with srvmgr, but we control its lifecycle
    std::unique_ptr<SrvMgr> srvmgr; ///< NB: this may be nullptr if we haven't yet synched up and started listening.  Additionally, this should be destructed before storage or bitcoindmgr.
    std::shared_ptr<BitcoinDMgr> bitcoindmgr; ///< shared with srvmgr, but we control its lifecycle

    struct StateMachine;
    std::unique_ptr<StateMachine> sm;
    mutable std::shared_mutex smLock;

    robin_hood::unordered_flat_map<CtlTask *, std::unique_ptr<CtlTask>> tasks;

    void add_DLHeaderTask(unsigned from, unsigned to, size_t nTasks);
    void process_DownloadingBlocks();
    bool process_VerifyAndAddBlock(PreProcessedBlockPtr); ///< helper called from within DownloadingBlocks state -- makes sure block is sane and adds it to db
    void process_PrintProgress(unsigned height, size_t nTx, size_t nIO);
    void process_DoUndoAndRetry(); ///< internal -- calls storage->undoLatestBlock() and schedules a task death and retry.

    size_t nBlocksDownloadedSoFar() const; ///< not 100% accurate. call this only from this thread
    std::tuple<size_t, size_t, size_t> nTxInOutSoFar() const; ///< not 100% accurate. call this only from this thread

    volatile bool stopFlag = false;
    bool lostConn = true;
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
    void finished();
    void success();
    void errored();
    void progress(double); ///< some tasks emit this to indicate progress. may be a number from 0->1.0 or anything else (task specific)
protected:
    void on_started() override;
    void on_finished() override;

    void process() override = 0; ///< from ProcessAgainMixin -- here to illustrate it's still pure virtual

    virtual void on_error(const RPC::Message &);
    virtual void on_failure(const RPC::Message::Id &, const QString &msg);

    quint64 submitRequest(const QString &method, const QVariantList &params, const BitcoinDMgr::ResultsF &resultsFunc);

    Controller * const ctl;  ///< initted in c'tor
};

#endif // CONTROLLER_H
