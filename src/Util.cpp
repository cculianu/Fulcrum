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
#include "CityHash.h"
#include "Json/Json.h"
#include "Logger.h"
#include "Util.h"

#include "bitcoin/hash.h"

// below headers are for getN*Processors, etc.
#if defined(Q_OS_DARWIN)
#  include <sys/types.h>
#  include <sys/sysctl.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#elif defined(Q_OS_LINUX)
#  include <array>
#  include <fstream>
#  include <locale>
#  include <sstream>
#  include <strings.h>
#  include <time.h>
#  include <unistd.h>
#elif defined(Q_OS_WINDOWS)
#  define WIN32_LEAN_AND_MEAN 1
#  include <windows.h>
#  include <psapi.h>
#  include <io.h>              // for _write(), _read(), _pipe(), _close()
#  include <fcntl.h>           // for O_BINARY, O_TEXT
#  include <errno.h>           // for errno
#endif

#if defined(Q_OS_UNIX)
#  include <unistd.h>          // for write(), read(), pipe(), close()
#  if __has_include(<sys/time.h>) && __has_include(<sys/resource.h>) // POSIX includes for setrlimit/getrlimit
#    include <sys/time.h>      // for setrlimit related stuff
#    include <sys/resource.h>  // for setrlimit related stuff
#    define HAS_SETRLIMIT
#  endif
#endif

#include <QRegularExpression>

#include <cstring>             // for strerror
#include <iostream>
#include <mutex>
#include <thread>

namespace Util {
    QString basename(const QString &s) {
        const QRegularExpression re("[\\/]");
        auto toks = s.split(re);
        return toks.last();
    }

#if defined(Q_OS_LINUX)
    static int64_t getAbsTimeNS() noexcept
    {
        struct timespec ts;
        // Note: CLOCK_MONOTONIC does *not* include the time spent suspended. If we want that, then we can Use
        // CLOCK_BOOTTIME here for that.
        if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
            ts = {0, 0};
            // We can't do a Warning() or Error() here because that would cause infinite recursion.
            // This is an unlikely and also pretty fatal situation, though, so we must warn.
            // Also we will use these noexcept functions here to preserve our noexcept-ness
            using namespace AsyncSignalSafe;
            writeStdErr(SBuf("Fatal: clock_gettime for CLOCK_MONOTONIC returned error status: ", std::strerror(errno)));
        }
        return int64_t(ts.tv_sec * 1000000000LL) + int64_t(ts.tv_nsec);
    }
    static int64_t absT0 = getAbsTimeNS();
    qint64 getTimeNS() noexcept {
        const auto now = getAbsTimeNS();
        return now - absT0;
    }
    qint64 getTime() noexcept {
        return getTimeNS()/1000000LL;
    }
    bool isClockSteady() noexcept { return true; }
#elif defined(Q_OS_WINDOWS)
    // Windows lacks a decent high resolution clock source on some C++ implementations (such as MinGW). So we
    // query the OS's QPC mechanism, which, on Windows 7+ is very fast to query and guaranteed to be accurate, and also
    // monotocic ("steady").
    static int64_t getAbsTimeNS() noexcept
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
    qint64 getTimeNS() noexcept {
        const auto now = getAbsTimeNS();
        return now - absT0;
    }
    qint64 getTime() noexcept {
        return getTimeNS()/1000000LL;
    }
    bool isClockSteady() noexcept { return true; }
#else
    // MacOS or generic platform (on MacOS with clang this happens to be very accurate)
    static const auto t0 = std::chrono::high_resolution_clock::now();
    qint64 getTime() noexcept {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
    }
    qint64 getTimeNS() noexcept {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now - t0).count();
    }
    bool isClockSteady() noexcept {
        return std::chrono::high_resolution_clock::is_steady;
    }
#endif

    qint64 getTimeMicros() noexcept {
        return getTimeNS()/1000LL;
    }

    double getTimeSecs() noexcept {
        return double(getTime()) / 1e3;
    }

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
        uint8_t c1, c2;
        for (char *out = ret.data(); d < dend; d += 2, ++out) {
            constexpr uint8_t offset_A = 'A' - 0xa,
                              offset_a = 'a' - 0xa,
                              offset_0 = '0';
            // slightly unrolled loop, does 2 chars at a time
            c1 = uint8_t(d[0]);
            c2 = uint8_t(d[1]);

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
            if (UNLIKELY(checkDigits && (c1 > 0xf || c2 > 0xf))) { // ensure data was actually in range
                ret.clear();
                break;
            }
            *out = char((c1 << 4) | c2);
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

    namespace {
        /// Stores a hash seed that we will use for our hash tables.
        /// There really should only be one of these globally.
        class HashSeed {
            uint64_t seed;
        public:
            /// seeds 'seed' from QRandomGenerator
            HashSeed() {
                auto gen = QRandomGenerator::global();
                if (!gen) {
                    Warning() << "App-global random number generator is null! Seeding hash seed with current time. FIXME!";
                    seed = uint64_t(getTimeNS());
                } else {
                    seed = uint64_t(gen->generate64());
                }
            }
            template <typename IntType, typename = std::enable_if_t<std::is_integral_v<IntType>>>
            IntType get() const { return static_cast<IntType>(seed); }
        };

        /// app-global hash seed -- initialized before we enter main()
        const HashSeed hashSeed;
    } // namespace (anonymous)

    uint32_t hashData32(const ByteView &bv) noexcept
    {
        // bitcoin::MurmurHash3 is not marked noexcept but it will never throw -- it does not allocate and
        // just uses basic arithmetic ops on the data in-place.
        return bitcoin::MurmurHash3(hashSeed.get<uint32_t>(), bv.ucharData(), bv.size());
    }
    uint64_t hashData64(const ByteView &bv) noexcept
    {
        // CityHash::CityHash64WithSeed is not marked noexcept but it will never throw -- it does not allocate and
        // just uses basic arithmetic ops on the data in-place.
        return uint64_t(CityHash::CityHash64WithSeed(bv.charData(), bv.size(), hashSeed.get<CityHash::uint64>()));
    }

    MemUsage getProcessMemoryUsage()
    {
#if defined(Q_OS_WINDOWS)
        PROCESS_MEMORY_COUNTERS_EX pmc;
        GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
        return { std::size_t{pmc.WorkingSetSize}, std::size_t{pmc.PrivateUsage} };
#elif defined(Q_OS_LINUX)
        MemUsage ret;
        std::ifstream file("/proc/self/status", std::ios_base::in);
        if (!file) return ret;
        file.imbue(std::locale::classic());
        std::array<char, 256> buf;
        buf[0] = 0;
        // sizes are in kB
        while (file.getline(buf.data(), buf.size()) && (ret.phys == 0 || ret.virt == 0)) {
            if (strncasecmp(buf.data(), "VmSize:", 7) == 0) {
                std::istringstream is(buf.data() + 7);
                is.imbue(std::locale::classic());
                is >> std::skipws >> ret.virt;
                ret.virt *= std::size_t(1024);
            } else if (strncasecmp(buf.data(), "VmRSS:", 6) == 0) {
                std::istringstream is(buf.data() + 6);
                is.imbue(std::locale::classic());
                is >> std::skipws >> ret.phys;
                ret.phys *= std::size_t(1024);
            }
        }
        return ret;
#elif defined(Q_OS_DARWIN)
        struct task_basic_info t_info;
        mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

        if (KERN_SUCCESS != task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count)) {
            return {};
        }
        return { std::size_t{t_info.resident_size}, std::size_t{t_info.virtual_size} };
#else
        return {};
#endif
    }

    uint64_t getAvailablePhysicalRAM()
    {
        uint64_t ret = 2048u * 1024u * 1024u; // just return 2GB, even if it's wrong, for unknown platforms
#if defined(Q_OS_WINDOWS)
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        GlobalMemoryStatusEx(&statex);
        ret = static_cast<uint64_t>(statex.ullAvailPhys);
#elif defined(Q_OS_DARWIN)
        // can't easily query memory on darwin, just take 1/2 of physical memory
        char buf[8];
        size_t bufsz = 8;
        if ( 0 == ::sysctlbyname("hw.memsize", buf, &bufsz, nullptr, 0) ) {
            switch (bufsz) {
            case 4: { uint32_t tmp; std::memcpy(&tmp, buf, 4); ret = tmp; ret /= uint64_t(2); break; }
            case 8: { std::memcpy(&ret, buf, 8); ret /= uint64_t(2); break; }
            default: qWarning() << "Failed to query physical RAM, kernel returned unexpected bufsize: " << bufsz;
            }
        }
#elif defined(Q_OS_LINUX)
        std::ifstream file("/proc/meminfo", std::ios_base::in);
        if (!file) return ret;
        file.imbue(std::locale::classic());
        std::array<char, 256> buf;
        buf[0] = 0;
        // sizes are in kB
        while (file.getline(buf.data(), buf.size())) {
            if (strncasecmp(buf.data(), "MemAvailable:", 13) == 0) {
                std::istringstream is(buf.data() + 13);
                is.imbue(std::locale::classic());
                uint64_t tmp = 0;
                is >> std::skipws >> tmp;
                tmp *= uint64_t(1024);
                if (tmp > 0) ret = tmp;
                break;
            }
        }
#endif
        return ret;
    }

    namespace AsyncSignalSafe {
        namespace {
#if defined(Q_OS_WIN)
            auto writeFD = ::_write; // Windows API docs say to use this function, since write() is deprecated
            auto readFD  = ::_read;  // Windows API docs say to use this function, since read() is deprecated
            auto closeFD = ::_close; // Windows API docs say to use this function, since close() is deprecated
            inline constexpr std::array<char, 3> NL{"\r\n"};
#elif defined(Q_OS_UNIX)
            auto writeFD = ::write;
            auto readFD  = ::read;
            auto closeFD = ::close;
            inline constexpr std::array<char, 2> NL{"\n"};
#else
            // no-op on unknown platform (this platform would use the cond variable and doesn't need read/close/pipe)
            auto writeFD = [](int, const void *, size_t n) { return int(n); };
            inline constexpr std::array<char, 1> NL{0};
#endif
        }
        void writeStdErr(const std::string_view &sv, bool wrnl) noexcept {
            constexpr int stderr_fd = 2; /* this is the case on all platforms */
            writeFD(stderr_fd, sv.data(), sv.length());
            if (wrnl && NL.size() > 1)
                writeFD(stderr_fd, NL.data(), NL.size()-1);
        }
#if defined(Q_OS_WIN) || defined(Q_OS_UNIX)
        Sem::Pipe::Pipe() {
            const int res =
#           ifdef Q_OS_WIN
                ::_pipe(fds, 32 /* bufsize */, O_BINARY);
#           else
                ::pipe(fds);
#           endif
            if (res != 0)
                throw InternalError(QString("Failed to create a Cond::Pipe: (%1) %2").arg(errno).arg(std::strerror(errno)));
        }
        Sem::Pipe::~Pipe() { closeFD(fds[0]), closeFD(fds[1]); }
        std::optional<SBuf<>> Sem::acquire() noexcept {
            std::optional<SBuf<>> ret;
            char c;
            if (const int res = readFD(p.fds[0], &c, 1); res != 1)
                ret.emplace("Sem::acquire: readFD returned ", res);
            return ret;
        }
        std::optional<SBuf<>> Sem::release() noexcept {
            std::optional<SBuf<>> ret;
            const char c = 0;
            if (const int res = writeFD(p.fds[1], &c, 1); res != 1)
                ret.emplace("Sem::release: writeFD returned ", res);
            return ret;
        }
#else
        // fallback to emulated -- use std C++ condition variable which is not technically
        // guaranteed async signal safe, but for all pratical purposes it's safe enough as a fallback.
        std::optional<SBuf<>> Sem::acquire() noexcept {
            std::mutex dummy; // hack, but works
            std::unique_lock l(dummy);
            p.cond.wait(l);
            return std::nullopt;
        }
        std::optional<SBuf<>> Sem::release() noexcept {
            p.cond.notify_one();
            return std::nullopt;
        }
#endif // defined(Q_OS_WIN) || defined(Q_OS_UNIX)
    } // end namespace AsyncSignalSafe

    MaxOpenFilesResult raiseMaxOpenFilesToHardLimit()
    {
#ifdef HAS_SETRLIMIT
        MaxOpenFilesResult ret;
        struct rlimit rl;
        auto get = [&rl, &ret] {
            if (getrlimit(RLIMIT_NOFILE, &rl)) {
                ret.status = ret.Error;
                ret.errMsg = QString("getrlimit: ") + std::strerror(errno);
                return false;
            }
            return true;
        };
        // first get the current limits
        if (!get())
            return ret;
        // paranoia
        if (long(rl.rlim_cur) < 0 || long(rl.rlim_max) < 0) {
            ret.status = ret.Error;
            ret.errMsg = "getrlimit reports limits are negative";
        }
        // more paranoia
        if (rl.rlim_cur > rl.rlim_max) {
            ret.status = ret.Error;
            ret.errMsg = "soft limit > hard limit (this shouldn't happen)";
        }
        // save value
        ret.oldLimit = long(rl.rlim_cur);
        if (rl.rlim_cur != rl.rlim_max) { // if not at hard limit, raise it
            // set to max
            rl.rlim_cur = rl.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &rl)) {
                ret.status = ret.Error;
                ret.errMsg = QString("setrlimit: ") + std::strerror(errno);
                return ret;
            }
        }
        // get the new limits again
        if (!get())
            return ret;
        // save value, indicate success
        ret.newLimit = long(rl.rlim_cur);
        ret.status = ret.Ok;

        return ret;
#else
        // On Windows this call is not even needed -- our use of Qt uses the Win32 API directly which has a limit
        // of 16.7 million for the handle tables.
        return {MaxOpenFilesResult::NotRelevant};
#endif
    }

    QPair<QString, quint16> ParseHostPortPair(const QString &s, bool allowImplicitLoopback)
    {
        constexpr auto parsePort = [](const QString & portStr) -> quint16 {
            bool ok;
            quint16 port = portStr.toUShort(&ok);
            if (!ok || port == 0)
                throw BadArgs(QString("Bad port: %1").arg(portStr));
            return port;
        };
        auto toks = s.split(":");
        constexpr const char *msg1 = "Malformed host:port spec. Please specify a string of the form <host>:<port>";
        if (const auto len = toks.length(); len < 2) {
            if (allowImplicitLoopback && len == 1)
                // this option allows bare port number with the implicit ipv4 127.0.0.1 -- try that (may throw if bad port number)
                return QPair<QString, quint16>{QHostAddress(QHostAddress::LocalHost).toString(), parsePort(toks.front())};
            throw BadArgs(msg1);
        }
        QString portStr = toks.last();
        toks.removeLast(); // pop off port
        QString hostStr = toks.join(':'); // rejoin on ':' in case it was IPv6 which is full of colons
        if (hostStr.isEmpty())
            throw BadArgs(msg1);
        return {hostStr, parsePort(portStr)};
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
        if (UNLIKELY(ourApp && !ourApp->options))
            ourApp = nullptr; // spurious Qt message -- ourApp not yet fully constructed.
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
            static std::mutex mut;
            {
                std::unique_lock g(mut);
                std::cerr << Q2C(theString) << std::endl << std::flush;
            }
            // Fatal should signal a quit even here
            if (level == Logger::Level::Fatal && qApp) {
                QTimer::singleShot(0, qApp, []{ qApp->quit(); });
            }
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
    case BrightGreen: suffix = "[32;1m"; break;
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


#ifdef ENABLE_TESTS
#include "bitcoin/utilstrencodings.h"

#include <QMap>
#include <QSet>

#include <algorithm>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
template<> struct std::hash<QString> {
    std::size_t operator()(const QString &s) const noexcept { return Util::hashForStd(s); }
};
#endif

namespace {
    // ---bench hexparse
    void BenchHexParse()
    {
        const auto fn = std::getenv("HEXJSON");
        if (!fn)
            throw Exception("Please specify a HEXJSON= env var that points to a file containing a JSON array of hex strings");
        const QString filename = fn;
        const auto varlist = Json::parseFile(filename, Json::ParseOption::RequireArray).toList(); // throws on error
        QList<QByteArray> hexList;
        size_t bytes = 0;
        for (const auto & v : varlist) {
            auto ba = v.toByteArray();
            ba = ba.trimmed().simplified();
            if (ba.isEmpty())
                throw Exception(QString("read an empty bytearray for item %1 -- make sure json has hex strings").arg(hexList.size()));
            if (QByteArray::fromHex(ba).toHex() != ba)
                throw Exception(QString("read bad hex data at %1: %2").arg(hexList.count()).arg(v.toString()));
            bytes += size_t(ba.size());
            hexList.push_back(ba);
        }
        Log() << "Read " << bytes << " hex-digits in " << hexList.count() << " bytearrays ...";
        using BVec = std::vector<QByteArray>;
        BVec vec1, vec2;
        using UVec = std::vector<std::vector<uint8_t>>;
        UVec vec3;
        vec1.reserve(size_t(hexList.size()));
        vec2.reserve(size_t(hexList.size()));
        vec3.reserve(size_t(hexList.size()));
        const auto customMethod = [&vec1, &hexList, &bytes]() -> qint64 {
            size_t bytes2 = 0;
            Log() << "Parsing hex using Util::ParseHexFast() ...";
            const auto t0 = Util::getTimeNS();
            for (const auto & hex : hexList) {
                vec1.emplace_back(Util::ParseHexFast(hex));
            }
            const auto tf = Util::getTimeNS();
            for (const auto & b : vec1)
                bytes2 += size_t(b.size());
            if (bytes2 * 2 != bytes)
                throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
            const auto micros = qint64((tf-t0)/1000LL);
            Log() << "Util::ParseHexFast method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
            return micros;
        };
        const auto qtMethod = [&vec2, &hexList, &bytes]() -> qint64 {
            size_t bytes2 = 0;
            Log() << "Parsing hex using Qt's QByteArray::fromHex() ...";
            const auto t0 = Util::getTimeNS();
            for (const auto & hex : hexList) {
                vec2.emplace_back(QByteArray::fromHex(hex));
            }
            const auto tf = Util::getTimeNS();
            for (const auto & b : vec2)
                bytes2 += size_t(b.size());
            if (bytes2 * 2 != bytes)
                throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
            const auto micros = qint64((tf-t0)/1000LL);
            Log() << "Qt method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
            return micros;
        };
        const auto bitcoindMethod = [&vec3, &hexList, &bytes]() -> qint64 {
            size_t bytes2 = 0;
            Log() << "Parsing hex using bitcoin::ParseHex() from bitcoind ...";
            const auto t0 = Util::getTimeNS();
            for (const auto & hex : hexList) {
                vec3.emplace_back(bitcoin::ParseHex(hex.constData()));
            }
            const auto tf = Util::getTimeNS();
            for (const auto & b : vec3)
                bytes2 += size_t(b.size());
            if (bytes2 * 2 != bytes)
                throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
            const auto micros = qint64((tf-t0)/1000LL);
            Log() << "bitcoind method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
            return micros;
        };
        customMethod();
        qtMethod();
        bitcoindMethod();
        if (vec1 == vec2)
            Log() << "The first two resulting vectors match perfectly";
        else
            throw Exception("The first two vectors don't match!");
        if (vec3.size() != vec2.size())
            throw Exception("The bitcoind method vector is of the wrong size");
        for (size_t i = 0; i < vec3.size(); ++i) {
            if (std::memcmp(vec3[i].data(), vec2[i].constData(), vec3[i].size()) != 0)
                throw Exception(QString("The bitcoind method hex string %1 does not match").arg(i));
        }
        Log() << "The bitcoind method data matches the other two data sets ok";

        Log() << "Checking ToHexFast vs. Qt vs. bitcoind ...";
        for (const auto & ba : vec1) {
            if (Util::ToHexFast(ba) != ba.toHex())
                throw Exception("ToHexFast and Qt toHex produced different hex strings!");
        }

        // Lasty, benchmark encoding hex
        BVec res; res.reserve(vec1.size());
        // Util::ToHexFast
        auto t0 = Tic();
        for (const auto & ba : vec1) {
            res.emplace_back(Util::ToHexFast(ba));
        }
        t0.fin();
        Log() << "Util::ToHexFast took: " << t0.usec() << " usec";
        res.clear(); res.reserve(vec1.size());
        // Qt toHex()
        t0 = Tic();
        for (const auto & ba : vec1) {
            res.emplace_back(ba.toHex());
        }
        t0.fin();
        Log() << "Qt toHex took: " << t0.usec() << " usec";
        // bitcoind HexStr()
        res.clear();
        {
            std::vector<std::string> res;
            res.reserve(vec1.size());
            t0 = Tic();
            for (const auto & ba : vec1) {
                res.emplace_back(bitcoin::HexStr(ba.cbegin(), ba.cend()));
            }
            t0.fin();
            Log() << "bitcoind HexStr took: " << t0.usec() << " usec";
        }
    }

    const auto b1 = App::registerBench("hexparse", &BenchHexParse);

    // ---test keyset
    void TestKeySetAndValueSet() {
        const std::map<QString, QString> map{
            { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
        };
        const QMap<QString, QString> qmap{
            { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
        };
        const std::unordered_map<QString, QString> umap{
            { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
        };
        int num = 0;
        // Util::keySet
        {
            auto s1 = Util::keySet<QSet<QString>>(map);
            auto s2 = Util::keySet<QSet<QString>>(qmap);
            auto s3 = Util::keySet<QSet<QString>>(umap);
            if (s1.size() != int(map.size()) || s2.size() != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("keySet<QSet> test failed!");
            for (const auto &k : s1)
                if (map.find(k) == map.end())
                    throw Exception(QString("key %1 not found in map").arg(k));
            ++num;
        }
        {
            auto s1 = Util::keySet<std::unordered_set<QString>>(map);
            auto s2 = Util::keySet<std::unordered_set<QString>>(qmap);
            auto s3 = Util::keySet<std::unordered_set<QString>>(umap);
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("keySet<unordered_set> test failed!");
            ++num;
        }
        {
            auto s1 = Util::keySet<std::vector<QString>>(map);
            auto s2 = Util::keySet<std::vector<QString>>(qmap);
            auto s3 = Util::keySet<std::vector<QString>>(umap);
            std::sort(s3.begin(), s3.end());
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("keySet<vector> test failed!");
            ++num;
        }
        {
            auto s1 = Util::keySet<std::list<QString>>(map);
            auto s2 = Util::keySet<std::list<QString>>(qmap);
            auto s3 = Util::keySet<std::list<QString>>(umap);
            auto v = Util::toVec(s3);
            std::sort(v.begin(), v.end());
            s3 = Util::toList(v);
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("keySet<list> test failed!");
            ++num;
        }
        {
            auto s1 = Util::keySet<QStringList>(map);
            auto s2 = Util::keySet<QStringList>(qmap);
            auto s3 = Util::keySet<QStringList>(umap);
            std::sort(s3.begin(), s3.end());
            if (s1.size() != int(map.size()) || s2.size() != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("keySet<QStringList> test failed!");
            ++num;
        }
        // Util::valueSet
        {
            auto s1 = Util::valueSet<QSet<QString>>(map);
            auto s2 = Util::valueSet<QSet<QString>>(qmap);
            auto s3 = Util::valueSet<QSet<QString>>(umap);
            if (s1.size() != int(map.size()) || s2.size() != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("valueSet<QSet> test failed!");
            for (const auto &v : s1) {
                bool found = false;
                for (const auto & [mk, mv] : map) {
                    if (v == mv) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    throw Exception(QString("value %1 not found in map").arg(v));
            }
            ++num;
        }
        {
            auto s1 = Util::valueSet<std::unordered_set<QString>>(map);
            auto s2 = Util::valueSet<std::unordered_set<QString>>(qmap);
            auto s3 = Util::valueSet<std::unordered_set<QString>>(umap);
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("valueSet<unordered_map> test failed!");
            ++num;
        }
        {
            auto s1 = Util::valueSet<std::vector<QString>>(map);
            auto s2 = Util::valueSet<std::vector<QString>>(qmap);
            auto s3 = Util::valueSet<std::vector<QString>>(umap);
            for (auto * s : { &s1, &s2, &s3 })
                std::sort(s->begin(), s->end());
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("valueSet<vector> test failed!");
            ++num;
        }
        {
            auto s1 = Util::valueSet<std::list<QString>>(map);
            auto s2 = Util::valueSet<std::list<QString>>(qmap);
            auto s3 = Util::valueSet<std::list<QString>>(umap);
            for (auto * s : { &s1, &s2, &s3 }) {
                auto v = Util::toVec(*s);
                std::sort(v.begin(), v.end());
                *s = Util::toList(v);
            }
            if (s1.size() != map.size() || int(s2.size()) != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("valueSet<list> test failed!");
            ++num;
        }
        {
            auto s1 = Util::valueSet<QStringList>(map);
            auto s2 = Util::valueSet<QStringList>(qmap);
            auto s3 = Util::valueSet<QStringList>(umap);
            for (auto * s : { &s1, &s2, &s3 })
                std::sort(s->begin(), s->end());
            if (s1.size() != int(map.size()) || s2.size() != qmap.size() || s1 != s2 || s1 != s3)
                throw Exception("valueSet<QStringList> test failed!");
            ++num;
        }
        Log() << "keyset test passed " << num << Util::Pluralize(" test", num) << " ok";
    }

    const auto t1 = App::registerTest("keyset", &TestKeySetAndValueSet);
} // namespace

#endif
