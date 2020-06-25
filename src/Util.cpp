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
#include "Logger.h"
#include "Util.h"

// below headers are for getN*Processors, etc.
#if defined(Q_OS_DARWIN)
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  include <mach/mach_time.h>
#elif defined(Q_OS_LINUX)
#  include <unistd.h>
#  include <time.h>
#elif defined(Q_OS_WINDOWS)
#define WIN32_LEAN_AND_MEAN 1
#  include <windows.h>
#endif

#include <iostream>
#include <thread>

namespace Util {
    QString basename(const QString &s) {
        QRegExp re("[\\/]");
        auto toks = s.split(re);
        return toks.last();
    }

#if defined(Q_OS_LINUX)
    static int64_t getAbsTimeNS()
    {
        struct timespec ts;
        // Note: CLOCK_MONOTONIC does *not* include the time spent suspended. If we want that, then we can Use
        // CLOCK_BOOTTIME here for that.
        if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
            ts = {0, 0};
            // We can't do a Warning() or Error() here because that would cause infinite recursion.
            // This is an unlikely and also pretty fatal situation, though, so we must warn
            std::cerr << "Fatal: clock_gettime for CLOCK_MONOTONIC returned error status: %s" << strerror(errno) << std::endl;
        }
        return int64_t(ts.tv_sec * 1000000000LL) + int64_t(ts.tv_nsec);
    }
    static int64_t absT0 = getAbsTimeNS();
    qint64 getTimeNS() {
        const auto now = getAbsTimeNS();
        return now - absT0;
    }
    qint64 getTime() {
        return getTimeNS()/1000000LL;
    }
    bool isClockSteady() { return true; }
#elif defined(Q_OS_WINDOWS)
    // Windows lacks a decent high resolution clock source on some C++ implementations (such as MinGW). So we
    // query the OS's QPC mechanism, which, on Windows 7+ is very fast to query and guaranteed to be accurate, and also
    // monotocic ("steady").
    static int64_t getAbsTimeNS()
    {
        static __int64 freq = 0;
        __int64 ct, factor;

        if (!freq) {
            QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
        }
        QueryPerformanceCounter((LARGE_INTEGER *)&ct);   // reads the current time (in system units)
        factor = 1000000000LL/freq;
        if (factor <= 0) factor = 1;
        return int64_t(ct * factor);
    }
    static qint64 absT0 = qint64(getAbsTimeNS()); // initializes static data inside getAbsTimeNS() once at startup in main thread.
    qint64 getTimeNS() {
        const auto now = getAbsTimeNS();
        return now - absT0;
    }
    qint64 getTime() {
        return getTimeNS()/1000000LL;
    }
    bool isClockSteady() { return true; }
#else
    // MacOS or generic platform (on MacOS with clang this happens to be very accurate)
    static const auto t0 = std::chrono::high_resolution_clock::now();
    qint64 getTime() {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
    }
    qint64 getTimeNS() {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now - t0).count();
    }
    bool isClockSteady() {
        return std::chrono::high_resolution_clock::is_steady;
    }
#endif

    qint64 getTimeMicros() {
        return getTimeNS()/1000LL;
    }

    double getTimeSecs() {
        return double(getTime()) / 1e3;
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
        static const char hexmap[513] =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

        const int size = ba.size();
        if (bufsz < size_t(size*2))
            return false;
        const uint8_t *cur = reinterpret_cast<const uint8_t *>(ba.constData()), * const end = cur + size;
        for (const char *nibbles; cur < end; ++cur, out += 2) {
            nibbles = &hexmap[*cur * 2];
            out[0] = nibbles[0];
            out[1] = nibbles[1];
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
        using LTS = Options::LogTimestampMode;
        const LTS ltsMode = !ourApp ? Options::defaultLogTimeStampMode : ourApp->options->logTimestampMode;
        s.flush(); // does nothing probably..
        // [timestamp]
        // Note: we always want to log the timestamp, even in syslog mode.
        // This is because if logging from a thread, log lines may be out-of-order.
        // The timestamp is the only record of the actual order in which things
        // occurred. Currently the timestamp is to 4 decimal places (hundreds of micros) in Uptime mode only.
        // We do offer LogTimestampMode::None for users really wishing to suppress timestamp logging.
        QString tsStr;
        switch (ltsMode) {
        case LTS::None:
            break;
        case LTS::Uptime: {
            const auto unow = Util::getTimeNS()/1000LL;
            tsStr = QString::asprintf("[%lld.%04d] ", unow/1000000LL, int((unow/100LL)%10000));
        }
            break;
        case LTS::UTC:
        case LTS::Local: {
            const auto now = ltsMode == LTS::UTC ? QDateTime::currentDateTimeUtc() : QDateTime::currentDateTime();
            tsStr = now.toString(u"[yyyy-MM-dd hh:mm:ss.zzz] ");
        }
            break;
        }
        // /[timestamp]
        QString thrdStr;
        if (QThread *th = QThread::currentThread(); th && ourApp && th != ourApp->thread()) {
            QString thrdName = th->objectName();
            if (thrdName.trimmed().isEmpty()) thrdName = QString::asprintf("%p", reinterpret_cast<void *>(QThread::currentThreadId()));
            thrdStr = QStringLiteral("<%1> ").arg(thrdName);
        }

        Logger *logger = ourApp ? ourApp->logger() : nullptr;

        QString theString = tsStr + thrdStr + (logger && logger->isaTTY() ? colorize(str, color) : str);

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

QString Log::colorize(const QString &str, Color c) {
    QString colorStr = useColor && c != Normal ? colorString(c) : "";
    QString normalStr = useColor && c != Normal ? colorString(Normal) : "";
    return colorStr + str + normalStr;
}

template <> Log & Log::operator<<(const Color &c) { setColor(c); return *this; }
template <> Log & Log::operator<<(const std::string &t) { s << t.c_str(); return *this; }

Debug::~Debug()
{
    level = Logger::Level::Debug;
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Cyan;
    str = QStringLiteral("(Debug) ") + str;
}

bool Debug::forceEnable = false;

bool Debug::isEnabled() {
    auto ourApp = app();
    return forceEnable || !ourApp || !ourApp->options || ourApp->options->verboseDebug;
}


Trace::~Trace()
{
    level = Logger::Level::Debug;
    doprt = isEnabled();
    if (!doprt) return;
    if (!colorOverridden) color = Green;
    str = QStringLiteral("(Trace) ") + str;
}

bool Trace::forceEnable = false;

bool Trace::isEnabled() {
    auto ourApp = app();
    return forceEnable
            || (ourApp && ourApp->options && ourApp->options->verboseTrace && ourApp->options->verboseDebug); // both trace and debug must be on
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
