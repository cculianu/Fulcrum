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

#include <QObject>
#include <QPointer>
#include <QRunnable>

#include <atomic>
#include <functional>
#include <memory>

class QThreadPool;

/// A wrapper around QThreadPool, whereby all work is submitted via lambdas.  It also keeps some stats and
/// provides some limits on number of jobs that can be enqueued.  Currently, there is one of these globally
/// owned by the 'App' object and accessible via ::AppThreadPool() (declared in App.h).
///
/// Each instance of this class internally creates its own QThreadPool instance, thus each instance never conflicts with
/// other thread pools such as the Qt-provided QThreadPool::globalInstance().
///
/// All of the public methods of this class are thread-safe.  None of the methods of this class throw.
class ThreadPool : public QObject
{
    Q_OBJECT
public:
    explicit ThreadPool(QObject *parent = nullptr);
    /// Will implicitly call ShutdownWaitForDone(-1), thus blocking potentially until all extant threads that are
    /// currently running exit.
    ~ThreadPool() override;

    /// Callback used below to indicate an exception was thrown or other low-level unlikely failure.
    using FailFunc = std::function<void(const QString &)>;
    using VoidFunc = std::function<void()>;

    /// Submit work to be performed asynchronously from a thread pool thread.
    ///
    /// `work` is called in the context of one of this instance's QThreadPool threads (it should lambda-capture all
    /// data it needs to compute its results). It may throw, in which case `fail` (if specified) is invoked with the
    /// exception.what() message.
    ///
    /// `completion` will be called in the context of `context`'s thread. If `context` dies before the work
    /// is completed, completion will never be called.
    ///
    /// `fail` will be called in the context of `context`'s thread on failure such as an exception being thrown
    /// by `work` .. *OR* if there is an excessive amount of work to be done and no room left in the queue (in which
    /// case it is called immediately).  If unspecified, the default fail func simply prints an error message to the
    /// error log.  In either case, if a failure occurs, `completion` will not be called.
    ///
    /// The intended client code usecase is that `work` and `completion` would share a shared_ptr to the same
    /// result set, which `work` writes-to to produce results, and `completion` reads-from and acts upon within
    /// the thread context of the caller. `completion` is guaranteed to be called *after* `work` returns (*if*
    /// `context` was not deleted first -- if it was, then `completion` is never called. `completion` is also never
    /// called if a failure occurs, in which case `fail`, if specified, is called instead).
    ///
    /// Using shared_ptr to share data between `work` and `completion` (via lambda-capture) is thus the intended
    /// way to use this mechanism.
    void submitWork(QObject *context, const VoidFunc & work, const VoidFunc & completion = VoidFunc(),
                    const FailFunc & fail = FailFunc(), int priority = 0);

    /// Call this on app or pool shutdown to wait for extant jobs that may be running to complete. This prevents jobs
    /// that are currently running from referencing data that may go away during shutdown (a situation that would cause
    /// a segfault).
    ///
    /// For example, our App has a ThreadPool instance it uses. The App's exit handler calls this on shutdown as the
    /// first thing it does, before deconstructing other objects.
    ///
    /// Destructing the ThreadPool instance will also implicitly call this function.
    ///
    /// Returns true if the jobs completed before timeout_ms expired, or false otherwise.
    /// Negative timeout_ms indicates "wait forever" for jobs to complete.
    ///
    /// This function should only ever be called once. After it is called, no more work can ever again be successfully
    /// submitted to the ThreadPool instance (it latches a boolean that permanently blocks the creation of new jobs once
    /// called). Note that after this function is called all extant jobs that may begin to run will exit immediately as
    /// well (as a consequence of said "shutting down" boolean being true).
    ///
    /// Despite the lack of a noexcept declaration, this does not throw (however I cannot guarantee Qt code we call
    /// does not throw, hence the lack of noexcept here).
    bool shutdownWaitForJobs(int timeout_ms = -1);

    /// Returns the number of jobs currently running or scheduled to run.
    int extantJobs() const noexcept;
    /// Returns the maximal value ExtantJobs() has ever reached during the lifetime of this application.
    int extantJobsMaxSeen() const noexcept;
    /// Returns the maximum number of extant jobs before failure is unconditionally asserted on SubmitWork (currently the default is 1000)
    int extantJobLimit() const noexcept;
    /// Sets the extant job limit.  This number cannot be set below 10, doing so returns false.
    bool setExtantJobLimit(int limit) noexcept;
    /// Returns the maximum number of threads used by the pool.
    int maxThreadCount() const noexcept;
    /// Sets the maximum number of threads used by the pool. Cannot be set <1.  Returns true on success (usually this is the case).
    bool setMaxThreadCount(int max);
    /// Returns the number of lifetime job overflows (the number of times the job queue was full and work was rejected).
    /// Ideally this number is always 0 even under load.
    uint64_t overflows() const noexcept;

    /// Returns the number of jobs that were ever successfilly submitted via SubmitWork
    uint64_t numJobsSubmitted() const noexcept;

    /// Returns true if the ThreadPool is currently being shutdown. A shutting-down ThreadPool will reject all new work.
    inline bool isShuttingDown() const noexcept { return blockNewWork.load(); }

    /// Thred-safe.  Returns some stats suitable for placing into a JSON object, etc. Used by the Controller as
    /// well as the AdminServer classes.
    QVariantMap stats() const noexcept;

private:
    const std::unique_ptr<QThreadPool> pool;
    std::atomic_uint64_t ctr = 0, noverflows = 0;
    std::atomic_int extant = 0, extantMaxSeen = 0;
    std::atomic_bool blockNewWork = false;
    /// maximum number of extant jobs we allow before failing and not enqueuing more.
    std::atomic_int extantLimit = 10000;
};

/// Semi-private class not intended to be constructed by client code, but used inside ThreadPool::SubmitWork.
/// We put it here because the meta object compiler needs to see it for signal/slot glue code generation.
class Job : public QObject, public QRunnable {
    Q_OBJECT

    friend class ::ThreadPool;
    using VoidFunc = ThreadPool::VoidFunc;
    using FailFunc = ThreadPool::FailFunc;

    const ThreadPool * const pool; ///< since the ThreadPool object owns us, this pointer is always valid if we exist.
    const VoidFunc work;
    QPointer<QObject> weakContextRef;


    Job(QObject *context, ThreadPool *pool,
        const VoidFunc & work,
        const VoidFunc & completion = VoidFunc(),
        const FailFunc & = FailFunc()) noexcept;

public:
    void run() override;
    ~Job() override;

signals:
    void started(); ///< emitted inside run() on job start
    void completed(); ///< calls completion in QObject context via a signal emit
    void failed(const QString &); ///< called if work() throws.
};

