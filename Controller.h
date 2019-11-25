#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "BitcoinD.h"
#include "Mixins.h"
#include "Options.h"
#include "SrvMgr.h"

#include <atomic>
#include <map>
#include <memory>
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

protected:
    Stats stats() const override;

protected slots:
    void process(bool beSilentIfUpToDate); ///< generic callback to advance state
    void process() override { process(false); } ///< from ProcessAgainMixin

private:
    friend class CtlTask;
    void rmTask(CtlTask *);
    bool isTaskDeleted(CtlTask *t) const;
    static constexpr auto pollTimerName = "pollForNewHeaders";

    const std::shared_ptr<Options> options;
    std::unique_ptr<SrvMgr> srvmgr;
    std::unique_ptr<BitcoinDMgr> bitcoindmgr;

    struct StateMachine;
    std::unique_ptr<StateMachine> sm;

    struct Storage {
        std::vector<QByteArray> headers;
    } storage;  /// temp data store. to be replaced by data model / and/or database

    std::map<CtlTask *, std::unique_ptr<CtlTask>> tasks;

    void add_DLHeaderTask(unsigned from, unsigned to, size_t nTasks);

    size_t nHeadersDownloadedSoFar() const; ///< not 100% accurate. call this only from this thread
};

class CtlTask : public QObject, public ThreadObjectMixin, public TimersByNameMixin, public ProcessAgainMixin
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
