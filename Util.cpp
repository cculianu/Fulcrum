//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
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
#include "Logger.h"
#include "Util.h"

// below headers are for getN*Processors, etc.
#if defined(Q_OS_DARWIN)
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  include <mach/mach_time.h>
#elif defined(Q_OS_LINUX)
#  include <unistd.h>
#endif

#include <iostream>
#include <thread>

namespace Util {
    QString basename(const QString &s) {
        QRegExp re("[\\/]");
        auto toks = s.split(re);
        return toks.last();
    }

    static const auto t0 = std::chrono::high_resolution_clock::now();

    qint64 getTime() {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
    }

    qint64 getTimeNS() {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now - t0).count();
    }

    double getTimeSecs() {
        return double(getTime()) / 1000.0;
    }

    bool isClockSteady() {
        return std::chrono::high_resolution_clock::is_steady;
    }

    namespace Json {
        QVariant parseString(const QString &str, bool expectMap) {
            QJsonParseError e;
            QJsonDocument d = QJsonDocument::fromJson(str.toUtf8(), &e);
            if (d.isNull())
                throw ParseError(QString("Error parsing Json from string: %1").arg(e.errorString()));
            auto v = d.toVariant();
            if (expectMap && v.type() != QVariant::Map)
                throw Error("Json Error, expected map, got a list instead");
            if (!expectMap && v.type() != QVariant::List)
                throw Error("Json Error, expected list, got a map instead");
            return v;
        }
        QVariant parseFile(const QString &file, bool expectMap) {
            QFile f(file);
            if (!f.open(QFile::ReadOnly))
                throw Error(QString("Could not open file: %1").arg(file));
            QString s(f.readAll());
            return parseString(s, expectMap);
        }
        QString toString(const QVariant &v, bool compact) {
            if (v.isNull() || !v.isValid()) throw Error("Empty or invalid QVariant passed to Json::toString");
            auto d = QJsonDocument::fromVariant(v);
            if (d.isNull())
                throw Error("Bad QVariant pased to Json::toString");
            return d.toJson(compact ? QJsonDocument::Compact : QJsonDocument::Indented);
        }

    } // end namespace Json

    bool VoidFuncOnObjectNoThrow(const QObject *obj, const std::function<void()> & lambda, int timeout_ms)
    {
        try {
            LambdaOnObject<void>(obj, lambda, timeout_ms);
            return true;
        } catch (const Exception &) {}
        return false;
    }

#if defined(Q_OS_DARWIN)
    unsigned getNVirtualProcessors()
    {
        static std::atomic<unsigned> nVProcs = 0;
        if (!nVProcs) {
            int a = 0;
            size_t b = sizeof(a);
            if (0 == sysctlbyname("hw.ncpu",&a, &b, nullptr, 0)) {
                nVProcs = unsigned(a); // this returns virtual CPUs which isn't always what we want..
            }
        }
        return nVProcs.load() ? nVProcs.load() : 1;
    }

    unsigned getNPhysicalProcessors()
    {
        static std::atomic<unsigned> nProcs = 0;
        if (!nProcs) {
            int a = 0;
            size_t b = sizeof(a);
            if (0 == sysctlbyname("hw.physicalcpu",&a,&b,nullptr,0)) {
                nProcs = unsigned(a);
            }
            //Debug() << "nProcs = " << nProcs;//  << " a:" << a << "  b:" << b;
        }
        return nProcs.load() ? nProcs.load() : 1;
    }
#elif defined(Q_OS_LINUX)
    unsigned getNVirtualProcessors() { return std::thread::hardware_concurrency(); }
    unsigned getNPhysicalProcessors() {
        static std::atomic<unsigned> nProcs = 0;
        if (!nProcs) {
            nProcs = unsigned(sysconf(_SC_NPROCESSORS_ONLN));
        }
        return nProcs.load() ? nProcs.load() : 1;
    }
#else
    unsigned getNVirtualProcessors() { return std::thread::hardware_concurrency(); }
    unsigned getNPhysicalProcessors() { return std::thread::hardware_concurrency(); }
#endif

    QByteArray ParseHexFast(const QByteArray &hex, bool checkDigits)
    {
        const int size = hex.size();
        QByteArray ret(size / 2, Qt::Initialization::Uninitialized);
        if (UNLIKELY(size % 2)) {
            // bad / not hex because not even number of chars.
            ret.clear();
            return ret;
        }
        const char *d = hex.constData(), * const dend = d + size;
        for (char c1, c2, *out = ret.data(); d < dend; d += 2, ++out) {
            constexpr char offset_A = 'A' - 0xa,
                           offset_a = 'a' - 0xa,
                           offset_0 = '0';
            // slightly unrolled loop, does 2 chars at a time
            c1 = d[0];
            c2 = d[1];

            // c1
            if (c1 <= '9') // this is the most likely for any random digit, so we check this first
                c1 -= offset_0;
            else if (c1 >= 'a') // next, we anticipate lcase, so we do this check first
                c1 -= offset_a;
            else // c1 >= 'A'
                c1 -= offset_A;
            // c2
            if (c2 <= '9') // this is the most likely for any random digit, so we check this first
                c2 -= offset_0;
            else if (c2 >= 'a') // next, we anticipate lcase, so we do this check first
                c2 -= offset_a;
            else // c2 >= 'A'
                c2 -= offset_A;


            // The below is slowish... we can just accept bad hex data as 'corrupt' ...
            // checkDigit = false allows us to skip this check, making this function >5x faster!
            if (UNLIKELY(checkDigits && (c1 < 0 || c1 > 0xf || c2 < 0 || c2 > 0xf))) { // ensure data was actually in range
                ret.clear();
                break;
            }
            *out = char(c1 << 4) | c2;
        }
        return ret;
    }

    QByteArray ToHexFast(const QByteArray &ba)
    {
        QByteArray ret(ba.size()*2, Qt::Initialization::Uninitialized);
        if (!ToHexFastInPlace(ba, ret.data(), size_t(ret.size())))
            ret.clear();
        return ret;
    }
    bool ToHexFastInPlace(const QByteArray &ba, char *out, size_t bufsz)
    {
        const int size = ba.size();
        if (bufsz < size_t(size*2))
            return false;
        const char *cur = ba.constData(), * const end = cur + size;
        for (char c1, c2; cur < end; ++cur, out += 2) {
            constexpr char dist_from_9_to_a = ('a'-'9')-1;
            c1 = ((*cur >> 4) & 0xf) + '0';
            c2 = (*cur & 0xf) + '0';
            if (c1 > '9') c1 += dist_from_9_to_a;
            if (c2 > '9') c2 += dist_from_9_to_a;
            out[0] = c1;
            out[1] = c2;
        }
        return true;
    }


} // end namespace Util

Log::Log() {}

Log::Log(Color c)
{
    setColor(c);
}

Log::Log(const char *fmt...)
    :  s()
{
    va_list ap;
    va_start(ap,fmt);
    str = QString::vasprintf(fmt,ap);
    va_end(ap);
    s.setString(&str, QIODevice::WriteOnly|QIODevice::Append);
}

Log::~Log()
{
    if (doprt) {
        App *ourApp = app();
        s.flush(); // does nothing probably..
        // note: we always want to log the timestamp, even in syslog mode.
        // this is because if logging from a thread, log lines may be out-of-order.
        // The timestamp is the only record of the actual order in which things
        // occurred. Currently the timestamp is to 4 decimal places (hundreds of micros)
        const auto unow = Util::getTimeNS()/1000LL;
        const QString tsStr = QString::asprintf("[%lld.%04d] ", unow/1000000LL, int((unow/100LL)%10000));
        QString thrdStr = "";

        if (QThread *th = QThread::currentThread(); th && ourApp && th != ourApp->thread()) {
            QString thrdName = th->objectName();
            if (thrdName.trimmed().isEmpty()) thrdName = QString::asprintf("%p", reinterpret_cast<void *>(QThread::currentThreadId()));
            thrdStr = QString("<Thread: %1> ").arg(thrdName);
        }

        Logger *logger = ourApp ? ourApp->logger() : nullptr;

        QString theString = tsStr + thrdStr + (logger && logger->isaTTY() ? colorify(str, color) : str);

        if (logger) {
            emit logger->log(level, theString);
        } else {
            // just print to console for now..
            std::cerr << Q2C(theString) << std::endl << std::flush;
        }
    }
}

/* static */
QString Log::colorString(Color c) {
    const char *suffix = "[0m"; // normal
    switch(c) {
    case Black: suffix = "[30m"; break;
    case Red: suffix = "[31m"; break;
    case Green: suffix = "[32m"; break;
    case Yellow: suffix = "[33m"; break;
    case Blue: suffix = "[34m"; break;
    case Magenta: suffix = "[35m"; break;
    case Cyan: suffix = "[36m"; break;
    case White: suffix = "[37m"; break;
    case BrightBlack: suffix = "[30;1m"; break;
    case BrightRed: suffix = "[31;1m"; break;
    case BrightGreen: suffix = "[1,32m"; break;
    case BrightYellow: suffix = "[33;1m"; break;
    case BrightBlue: suffix = "[34;1m"; break;
    case BrightMagenta: suffix = "[35;1m"; break;
    case BrightCyan: suffix = "[36;1m"; break;
    case BrightWhite: suffix = "[37;1m"; break;

    default:
        // will just use normal
        break;
    }
    static const char prefix[2] = { 033, 0 }; // esc 033 in octal
    return QString::asprintf("%s%s", prefix, suffix);
}

QString Log::colorify(const QString &str, Color c) {
    QString colorStr = useColor && c != Normal ? colorString(c) : "";
    QString normalStr = useColor && c != Normal ? colorString(Normal) : "";
    return colorStr + str + normalStr;
}

template <> Log & Log::operator<<(const Color &c) { setColor(c); return *this; }

Debug::~Debug()
{
    level = Logger::Level::Debug;
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Cyan;
    str = QString("(Debug) ") + str;
}

bool Debug::isEnabled() {
    auto ourApp = app();
    return !ourApp || !ourApp->options || ourApp->options->verboseDebug;
}

Trace::~Trace()
{
    level = Logger::Level::Debug;
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Green;
    str = QString("(Trace) ") + str;
}

bool Trace::isEnabled() {
    auto ourApp = app();
    return ourApp && ourApp->options && ourApp->options->verboseTrace && Debug::isEnabled();
}

Error::~Error()
{
    level = Logger::Level::Critical;
    if (!colorOverridden) color = BrightRed;
}


Warning::~Warning()
{
    level = Logger::Level::Warning;
    if (!colorOverridden) color = Yellow;
}

Fatal::~Fatal()
{
    level = Logger::Level::Fatal;
    str = QString("FATAL: ") + str;
    if (!colorOverridden) color = BrightRed;
}

FatalAssert::FatalAssert(bool expr)
    : assertion(expr)
{
    doprt = !assertion;
}

FatalAssert::~FatalAssert()
{
    if ((doprt = !assertion)) {
        level = Logger::Level::Fatal;
        str = QString("ASSERTION FAILED: ") + str;
        if (!colorOverridden) color = BrightRed;
    }
}

/// ThreadPool work stuff
#include <QThreadPool>
namespace Util {
    namespace ThreadPool {
        namespace {
            std::atomic_uint64_t ctr = 0, overflows = 0;
            std::atomic_int extant = 0, extantMaxSeen = 0;
            std::atomic_bool blockNewWork = false;
            constexpr bool debugPrt = false;
            /// maximum number of extant jobs we allow before failing and not enqueuing more.
            /// TODO: make this configurable and/or tune this "magic" value
            constexpr int extantLimit = 1000;
        }

        Job::Job(QObject *context, const VoidFunc & work, const VoidFunc & completion, const FailFunc &fail)
            : QObject(nullptr), work(work), weakContextRef(context ? context : qApp)
        {
            if (!context && (completion || fail))
                Debug(Log::Magenta) << "Warning: use of ThreadPool jobs without a context is not recommended, FIXME!";
            if (completion)
                connect(this, &Job::completed, context ? context : qApp, [completion]{ completion(); });
            if (fail)
                connect(this, &Job::failed, context ? context : qApp, [fail](const QString &err){ fail(err); });
        }
        Job::~Job() {}

        void Job::run() {
            emit started();
            if (UNLIKELY(blockNewWork)) {
                Debug() << objectName() << ": blockNewWork = true, exiting early without doing any work";
                return;
            } else if (UNLIKELY(!weakContextRef)) {
                // this is here so we avoid doing any work in case work is costly when we know for a fact the
                // interested/subscribed context object is already deleted.
                Debug() << objectName() << ": context already deleted, exiting early without doing any work";
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

        void SubmitWork(QObject *context, const VoidFunc & work, const VoidFunc & completion, const FailFunc & fail, int priority)
        {
            if (blockNewWork) {
                Debug() << __FUNCTION__ << ": Ignoring new work submitted because blockNewWork = true";
                return;
            }
            static const FailFunc defaultFail = [](const QString &msg) {
                    Warning() << "A ThreadPool job failed with the error message: " << msg;
            };
            const FailFunc & failFuncToUse (fail ? fail : defaultFail);
            Job *job = new Job(context, work, completion, failFuncToUse);
            QObject::connect(job, &QObject::destroyed, qApp, [](QObject *){ --extant;}, Qt::DirectConnection);
            if (const auto njobs = ++extant; njobs > extantLimit) {
                ++overflows;
                delete job; // will decrement extant on delete
                const auto msg = QString("Job limit exceeded (%1)").arg(njobs);
                failFuncToUse(msg);
                if (&failFuncToUse != &defaultFail)
                    // make sure log gets the error
                    Warning() << msg;
                return;
            } else if (UNLIKELY(njobs < 0)) {
                // should absolutely never happen.
                Error() << "FIXME: njobs " << njobs << " < 0!";
            } else if (njobs > extantMaxSeen)
                // FIXME: this isn't entirely atomic but this value is for diagnostic purposes and doesn't need to be strictly correct
                extantMaxSeen = njobs;
            job->setAutoDelete(true);
            const auto num = ++ctr;
            job->setObjectName(QString("Job %1 for '%2'").arg(num).arg( context ? context->objectName() : "<no context>"));
            if constexpr (debugPrt) {
                QObject::connect(job, &Job::started, qApp, [n=job->objectName()]{
                    Debug() << n << " -- started";
                }, Qt::DirectConnection);
                QObject::connect(job, &Job::completed, qApp, [n=job->objectName()]{
                    Debug() << n << " -- completed";
                }, Qt::DirectConnection);
                QObject::connect(job, &Job::failed, qApp, [n=job->objectName()](const QString &msg){
                    Debug() << n << " -- failed: " << msg;
                }, Qt::DirectConnection);
            }
            QThreadPool::globalInstance()->start(job, priority);
        }

        bool ShutdownWaitForJobs(int timeout_ms)
        {
            blockNewWork = true;
            if constexpr (debugPrt) {
                Debug() << __FUNCTION__ << ": waiting for jobs ...";
            }
            auto tp = QThreadPool::globalInstance();
            return tp->waitForDone(timeout_ms);
        }

        int ExtantJobs() { return extant.load(); }
        int ExtantJobsMaxSeen() { return extantMaxSeen.load(); }
        int ExtantJobLimit() { return extantLimit; }
        uint64_t NumJobsSubmitted() { return ctr.load(); }
        uint64_t Overflows() { return overflows.load(); }

    } // end namespace ThreadPool
} // end namespace Util
