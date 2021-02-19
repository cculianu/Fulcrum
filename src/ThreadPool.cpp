//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "ThreadPool.h"
#include "Util.h"

#include <QThreadPool>

namespace {
    constexpr bool debugPrt = false;
}


ThreadPool::ThreadPool(QObject *parent)
    : QObject(parent), pool(std::make_unique<QThreadPool>(this))
{
}

ThreadPool::~ThreadPool()
{
    shutdownWaitForJobs();
}


Job::Job(QObject *context, ThreadPool *pool, const VoidFunc & work, const VoidFunc & completion, const FailFunc &fail) noexcept
    : QObject(nullptr), pool(pool), work(work), weakContextRef(context ? context : pool)
{
    if (!context && (completion || fail))
        Debug(Log::Magenta) << "Warning: use of ThreadPool jobs without a context is not recommended, FIXME!";
    if (completion)
        connect(this, &Job::completed, context ? context : pool, [completion]{ completion(); });
    if (fail)
        connect(this, &Job::failed, context ? context : pool, [fail](const QString &err){ fail(err); });
}
Job::~Job() {}

void Job::run() {
    emit started();
    if (UNLIKELY(pool->isShuttingDown())) {
        Debug() << objectName() << ": blockNewWork = true, exiting early without doing any work";
        return;

    } else if (UNLIKELY(!weakContextRef)) {
        // this is here so we avoid doing any work in case work is costly when we know for a fact the
        // interested/subscribed context object is already deleted.
        DebugM(objectName(), ": context already deleted, exiting early without doing any work");
        return;
    }
    if (LIKELY(work)) {
        try {
            work();
        } catch (const std::exception &e) {
            emit failed(e.what());
            return;
        } catch (...) {
            emit failed("Unknown exception");
            return;
        }
    }
    emit completed();
}

void ThreadPool::submitWork(QObject *context, const VoidFunc & work, const VoidFunc & completion, const FailFunc & fail, int priority)
{
    if (blockNewWork) {
        Debug() << __func__ << ": Ignoring new work submitted because blockNewWork = true";
        return;
    }
    static const FailFunc defaultFail = [](const QString &msg) {
            Warning() << "A ThreadPool job failed with the error message: " << msg;
    };
    const FailFunc & failFuncToUse (fail ? fail : defaultFail);
    Job *job = new Job(context, this, work, completion, failFuncToUse);
    QObject::connect(job, &QObject::destroyed, this, [this](QObject *){ --extant;}, Qt::DirectConnection);
    if (const auto njobs = ++extant; njobs > extantLimit) {
        ++noverflows;
        delete job; // will decrement extant on delete
        const auto msg = QString("Job limit exceeded (%1)").arg(njobs);
        failFuncToUse(msg);
        return;
    } else if (UNLIKELY(njobs < 0)) {
        // should absolutely never happen.
        Error() << "FIXME: njobs " << njobs << " < 0!";
    } else if (njobs > extantMaxSeen)
        // FIXME: this isn't entirely atomic but this value is for diagnostic purposes and doesn't need to be strictly correct
        extantMaxSeen = njobs;
    job->setAutoDelete(true);
    const auto num = ++ctr;
    job->setObjectName(QStringLiteral("Job %1 for '%2'").arg(num).arg( context ? context->objectName() : QStringLiteral("<no context>")));
    if constexpr (debugPrt) {
        QObject::connect(job, &Job::started, this, [n=job->objectName()]{
            Debug() << n << " -- started";
        }, Qt::DirectConnection);
        QObject::connect(job, &Job::completed, this, [n=job->objectName()]{
            Debug() << n << " -- completed";
        }, Qt::DirectConnection);
        QObject::connect(job, &Job::failed, this, [n=job->objectName()](const QString &msg){
            Debug() << n << " -- failed: " << msg;
        }, Qt::DirectConnection);
    }
    pool->start(job, priority);
}

bool ThreadPool::shutdownWaitForJobs(int timeout_ms)
{
    blockNewWork = true;
    if constexpr (debugPrt) {
        Debug() << __func__ << ": waiting for jobs ...";
    }
    pool->clear();
    return pool->waitForDone(timeout_ms);
}

int ThreadPool::extantJobs() const noexcept { return extant.load(); }
int ThreadPool::extantJobsMaxSeen() const noexcept { return extantMaxSeen.load(); }
int ThreadPool::extantJobLimit() const noexcept { return extantLimit.load(); }
bool ThreadPool::setExtantJobLimit(int limit)  noexcept {
    if (limit < 10)
        return false;
    extantLimit = limit;
    return true;
}
uint64_t ThreadPool::numJobsSubmitted() const noexcept { return ctr.load(); }
uint64_t ThreadPool::overflows() const noexcept { return noverflows.load(); }
int ThreadPool::maxThreadCount() const noexcept { return pool->maxThreadCount(); }
bool ThreadPool::setMaxThreadCount(int max) {
    if (max < 1)
        return false;
    pool->setMaxThreadCount(max);
    return pool->maxThreadCount() == max;
}

QVariantMap ThreadPool::stats() const noexcept
{
    QVariantMap m;
    m["extant jobs"] = extantJobs();
    m["extant jobs (max lifetime)"] = extantJobsMaxSeen();
    m["extant limit"] = extantJobLimit();
    m["job count (lifetime)"] = qulonglong(numJobsSubmitted());
    m["job queue overflows (lifetime)"] = qulonglong(overflows());
    m["thread count (max)"] = maxThreadCount();
    return m;
}
