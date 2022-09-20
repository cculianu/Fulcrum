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
#pragma once

#include "ByteView.h"
#include "Common.h"
#include <QtCore>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <list>
#include <mutex>
#include <optional>
#include <random>
#include <shared_mutex>
#include <set>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#define Q2C(qstr) ((qstr).toUtf8().constData())

class App;

#if !defined(_MSC_VER) && (defined(__clang__) || defined(__GNUC__))
#define ATTR_PRINTF(fmt, arg) __attribute__((format(printf, fmt, arg)))
#else
#define ATTR_PRINTF(fmt, arg)
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif

#if defined(__clang__) || defined(__GNUC__)
#define EXPECT(expr, constant) __builtin_expect(expr, constant)
#else
#define EXPECT(expr, constant) (expr)
#endif

#define LIKELY(bool_expr)   EXPECT(int(bool(bool_expr)), 1)
#define UNLIKELY(bool_expr) EXPECT(int(bool(bool_expr)), 0)

/// Super class of Debug, Warning, Error classes.  Can be instantiated for regular log messages.
class Log
{
public:
    enum Color {
        Reset = 0,
        Normal = Reset, // no color/reset
        Black,
        Red, Green, Yellow, Blue, Magenta, Cyan, White,
        BrightBlack,
        BrightRed, BrightGreen, BrightYellow, BrightBlue, BrightMagenta, BrightCyan, BrightWhite,
        Color_N
    };


    bool doprt = true;

    explicit Log(const char *fmt...) ATTR_PRINTF(2,3);
    explicit Log(Color);
    Log();
    virtual ~Log();

    template <class T> Log & operator<<(const T & t) { s << t; return *this;  }

    Log & setColor(Color c) { color = c; colorOverridden = true; return *this; }
    Color getColor() const { return color; }

    /// Used by the DebugM macros, etc.  Unpacks all of its args using operator<< for each arg.
    template <class ...Args>
    Log & operator()(Args&& ...args) {  ((*this) << ... << args); return *this; }

protected:
    static QString colorString(Color c);
    QString colorize(const QString &, Color c);

    bool colorOverridden = false, useColor = true;
    int level = 0;
    Color color = Normal;
    QString str = "";
    QTextStream s = QTextStream(&str, QIODevice::WriteOnly);
};


// specialization to set the color.
template <> Log & Log::operator<<(const Color &);
// specialization for std::string
template <> Log & Log::operator<<(const std::string &t);

/** \brief Stream-like class to print a debug message to the app's logging facility
    Example:
   \code
        Debug() << "This is a debug message"; // would print a debug message to the logging facility
   \endcode
 */
class Debug : public Log
{
public:
    using Log::Log; // inherit c'tor
    virtual ~Debug();

    static bool isEnabled();
    static bool forceEnable; ///< defaults false -- set to true if there is no App and you want to ensure Debug() works

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Debug(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

/// This is fast: It only evaluates args if Debug is enabled. Use this in performance-critical code.
/// Unfortunately, there is no way to do this exact thing with templates, so we opted for a C-style macro
/// to avoid evaluating the args in the !Debug::isEnabled() case.
#define DebugM(...)                \
    do {                           \
        if (Debug::isEnabled())    \
            Debug()(__VA_ARGS__);  \
    } while (0)

/** \brief Stream-like class to print a trace message to the app's logging facility
    Example:
   \code
        Trace() << "This is a trace debug message"; // would print a trace message to the logging facility
   \endcode
 */
class Trace : public Log
{
public:
    using Log::Log; // inherit c'tor
    virtual ~Trace();

    static bool isEnabled();
    static bool forceEnable; ///< defaults false -- set to true if there is no App and you want Trace() to work.

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Trace(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

/// This is fast: It only evaluates args if Trace is enabled. Use this in performance-critical code.
/// Unfortunately, there is no way to do this exact thing with templates, so we opted for a C-style macro
/// to avoid evaluating the args in the !Trace::isEnabled() case.
#define TraceM(...)                \
    do {                           \
        if (Trace::isEnabled())    \
            Trace()(__VA_ARGS__);  \
    } while (0)

/** \brief Stream-like class to print an error message to the app's logging facility
    Example:
   \code
        Error() << "This is an ERROR message!!"; // would print an error message to the logging facility
   \endcode
 */
class Error : public Log
{
public:
    using Log::Log; // inherit c'tor
    virtual ~Error();

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Error(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

/** \brief Stream-like class to print a warning message to the app's logging facility

    Example:
  \code
        Warning() << "This is a warning message..."; // would print a warning message to the logging facility
   \endcode
*/
class Warning : public Log
{
public:
    using Log::Log; // inherit c'tor
    virtual ~Warning();

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Warning(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

/// Like Error(), except it will enqueue a qApp->exit(1) after logging the message
class Fatal : public Log
{
public:
    using Log::Log;
    virtual ~Fatal();

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Fatal(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

// Now add these macros for symmetry
#define LogM(...) (Log()(__VA_ARGS__))
#define WarningM(...) (Warning()(__VA_ARGS__))
#define ErrorM(...) (Error()(__VA_ARGS__))
#define FatalM(...) (Fatal()(__VA_ARGS__))

#define FatalAssert(b,...)                                            \
    do {                                                              \
        if (!(b))                                                     \
            FatalM("ASSERTION FAILED: \"", #b, "\" - ", __VA_ARGS__); \
    } while (0)

namespace Util {
    extern QString basename(const QString &);

    qint64 getTime() noexcept; ///< returns a timestamp in milliseconds
    qint64 getTimeMicros() noexcept; ///< returns a timestamp in microseconds
    qint64 getTimeNS() noexcept; ///< returns a timestamp in nanoseconds
    double getTimeSecs() noexcept; ///< returns a timestamp in seconds (resolution is milliseconds precision)
    bool isClockSteady() noexcept; ///< returns true if the above timestamp clock is steady (monotonic).

    /// returns the number of virtual processors on the system
    unsigned getNVirtualProcessors();
    /// returns the number of physical (real) processors on the system
    unsigned getNPhysicalProcessors();

    template <typename Iterator>
    void shuffle(Iterator begin, Iterator end)
    {
        // We use Qt's implementation here because apparently MinGW on Windows using GCC before 9.2 uses a deterministic
        // RNG even if using std::random_device.  Qt's RNG does not have this problem.
        auto seed = QRandomGenerator::global()->generate();
        std::shuffle(begin, end, std::default_random_engine(seed));
    }

    template <typename T, typename std::enable_if_t<std::is_pod_v<T> && sizeof(T) == 1, int> = 0>
    void getRandomBytes(T *buf, std::size_t n) {
        int ctr = 0;
        quint64 bits = 0;
        std::generate_n(buf, n, [&]{
            if (ctr == 0) {
                bits = QRandomGenerator::global()->generate64();
                ctr = 8;
            }
            const T ret = static_cast<T>(bits & 0xffu);
            bits >>= 8;
            --ctr;
            return ret;
        });
    }

    template <typename Map>
    Map & updateMap(Map &map, const Map &updates) {
        for (auto it = updates.cbegin(); it != updates.cend(); ++it) {
            map.insert(it.key(), it.value());
        }
        return map;
    }

    /// SFINAE-based functor that calls .reserve(size) on an instance, otherwise does nothing if instance's
    /// type has no reserve() method.  Used by keySet() and valueSet() below.
    struct CallReserve {
        template <typename T>
        auto operator()(T &s, size_t size) const -> decltype(s.reserve(size)) // SFINAE fail if no .reserve()
        { return s.reserve(size); }
        // fallback if SFINAE failed, no-op
        template <typename T> void operator()(const T &, size_t) const {}
    };
    /// SFINAE-based functor that calls .insert(item) on an set-like instance, or push_back(item) on a
    /// vector/list-like instance.  Used by keySet() and valueSet() below.
    struct CallPushBackOrInsert {
        template <typename T, typename U>
        auto operator()(T &s, const U &item) const -> decltype(s.insert(item)) // SFINAE fail if no .insert()
        { return s.insert(item); }
        template <typename T, typename U>
        auto operator()(T &s, const U &item) const -> decltype(s.push_back(item)) // SFINAE fail if no .push_back()
        { return s.push_back(item); }
    };
    /// SFINAE-based functor that calls it.key() on a QMap-like iterator or it->first on an STL-map-like iterator
    struct GetMapItKey {
        template <typename It>
        auto operator()(const It &it) const -> decltype((it.key())) // SFINAE fail if no it.key()
        { return it.key(); }
        template <typename It>
        auto operator()(const It &it) const -> decltype((it->first)) // SFINAE fail if no it->first
        { return it->first; }
    };
    /// SFINAE-based functor that calls it.value() on a QMap-like iterator or it->second on an STL-map-like iterator
    struct GetMapItValue {
        template <typename It>
        auto operator()(const It &it) const -> decltype((it.value())) // SFINAE fail if no it.value()
        { return it.value(); }
        template <typename It>
        auto operator()(const It &it) const -> decltype((it->second)) // SFINAE fail if no it->second
        { return it->second; }
    };

    /// Grab just the keys from a map, by copy construction.
    /// If no Set template arg is specified, std::set<Map::key_type> is used.
    /// Otherwise specify any set type such as std::unordered_set<type>, etc.
    /// This fuction also can create vectors and/or lists (both STL and Qt varieties).
    template <typename Set = void, typename Map> /* We do it this way so that Set is the first arg an Map is inferred from args. */
    auto keySet(const Map &map) {
        // lambda template
        constexpr auto inner = [](const Map &map, auto & set) {
            CallReserve{}(set, map.size());
            for (auto it = map.begin(); it != map.end(); ++it) {
                CallPushBackOrInsert{}(set, GetMapItKey{}(it));
            }
        };
        // this lambda template is only here to assist in type deduction, it's never called.
        constexpr auto DeduceSet = [] {
            if constexpr (std::is_void_v<Set>)
                // default of void leads to std::set being used as the return type
                return std::set<typename Map::key_type>();
            else
                return Set();
        };
        decltype( DeduceSet() ) ret;
        inner(map, ret);
        return ret;
    }
    /// Similar to keySet(), but instead grabs all the values from a map.
    /// This fuction also can create vectors and/or lists (both STL and Qt varieties).
    template <typename Set = void, typename Map>
    auto valueSet(const Map &map) {
        // lambda template
        constexpr auto inner = [](const Map &map, auto & set) {
            CallReserve{}(set, map.size());
            for (auto it = map.begin(); it != map.end(); ++it) {
                CallPushBackOrInsert{}(set, GetMapItValue{}(it));
            }
        };
        // this lambda template is only here to assist in type deduction, it's never called.
        constexpr auto DeduceSet = [] {
            if constexpr (std::is_void_v<Set>)
                // default of void leads to std::set being used as the return type
                return std::set<typename Map::mapped_type>();
            else
                return Set();
        };
        decltype( DeduceSet() ) ret;
        inner(map, ret);
        return ret;
    }

    /// Convert an iterable container from one format to another, using ranged iterator constructors. Only works
    /// on containers supporting such constructors.  Pass the out container return type as the first argument.
    template <typename OutCont, typename InCont>
    auto toCont(const InCont &in) { return OutCont{in.begin(), in.end()}; }
    /// Convert an iterable container (normally a vector) into a list.  Pass the List return type as the first argument
    /// (defaults to std::list<ItCont::value_type> if unspecified).
    template <typename List = void, typename ItCont>
    auto toList(const ItCont &cont) {
        constexpr auto DeduceList = []{
            // this code doesn't ever execute, it is just used for type deduction
            if constexpr (std::is_same_v<List, void>)
                return std::list<typename ItCont::value_type>();
            else
                return List();
        };
        return toCont<decltype( DeduceList() )>(cont);
    }
    /// Convert an iterable container (normally a list) into a vector. Pass the Vec return type as the first argument
    /// (defaults to std::vector<ItCond::value_tyoe> if unspecified).
    template <typename Vec = void, typename ItCont>
    auto toVec(const ItCont &cont) {
        constexpr auto DeduceVec = []{
            // this code doesn't ever execute, it is just used for type deduction
            if constexpr (std::is_same_v<Vec, void>)
                return std::vector<typename ItCont::value_type>();
            else
                return Vec();
        };
        return toCont<decltype( DeduceVec() )>(cont);
    }

    /// Boilerplate to sort a container using Comparator class (defaults to just using operator<), and then
    /// uniqueify it (remove adjacent dupes).
    template <typename Comparator = void, typename Container>
    void sortAndUniqueify(Container &cont, bool shrinkIfSupported = true)
    {
        if constexpr(std::is_same_v<std::list<typename Container::value_type>, Container>) {
            if constexpr (std::is_same_v<Comparator,void>)
                cont.sort();
            else
                cont.sort(Comparator());
        } else {
            if constexpr (std::is_same_v<Comparator,void>)
                std::sort(cont.begin(), cont.end());
            else
                std::sort(cont.begin(), cont.end(), Comparator());
        }
        auto last = std::unique(cont.begin(), cont.end());
        cont.erase(last, cont.end());
        if constexpr (std::is_same_v<std::vector<typename Container::value_type>, Container>) {
            if (shrinkIfSupported) cont.shrink_to_fit();
        } else if constexpr (std::is_same_v<QVector<typename Container::value_type>, Container>) {
            if (shrinkIfSupported) cont.squeeze();
        }
    }

    /// For each item in Container, reverse each item in-place using std::reverse(item.begin(), item.end()).
    /// Note that each item in the container must have a bidirectional iterator returned from .begin()/.end().
    template <typename Container>
    void reverseEachItem(Container &c) { for (auto & item : c) std::reverse(item.begin(), item.end()); }

    /// Copy constructs t, and returns a reversed version of it. T must have a bidirecitonal iterator for .begin() & .end().
    template <typename T>
    T reversedCopy(const T &t) { T ret(t); std::reverse(ret.begin(), ret.end()); return ret; }

    /// Thrown by Channel.get (if throwsOnTimeout=true), and also CallOnObjectWithTimeout if the method didn't get to
    /// execute before the timeout specified.
    struct TimeoutException : public Exception { using Exception::Exception; };
    /// May be thrown by CallOnObjectWithTimeout if target object's thread is not running.
    struct ThreadNotRunning : public Exception { using Exception::Exception; };
    /// Thrown from Channel if throwsIfClosed = true and if the channel is closed and no more data is available.
    struct ChannelClosed : public Exception { using Exception::Exception; };
    /// Thrown if attempting to put to a channel that has a sizeLimit > 0 and it is full.
    struct ChannelFull : public Exception { using Exception::Exception;  };

    // Go channel work-alike for sharing data across threads
    // T must be copy constructible and copyable, also default constructible
    template <typename T> class Channel
    {
    public:
        Channel() {}
        ~Channel() { deleted = true; close(); }

        std::atomic_bool throwsOnTimeout = false, throwsIfClosed = false, clearsOnClose = true;
        std::atomic_int sizeLimit = 0; ///< set this to > 0 to specify a limit on the number of elements the channel accepts before put() throws ChannelFull.

        /// returns T() on fail (unless either throwsIfClosed=true or throwsOnTimeout=true, in which case it throws on failure)
        T get(unsigned long timeout_ms = ULONG_MAX) {
            T ret{};
            QMutexLocker ml(&mut);
            if (!killed && !ct && timeout_ms > 0) {
                cond.wait(&mut, timeout_ms);
            }
            if (LIKELY(ct != 0)) {
                ret = data.takeFirst(); --ct;
            }
            else if (UNLIKELY(killed && throwsIfClosed))
                throw ChannelClosed("Cannot read from closed Channel");
            else if (throwsOnTimeout)
                throw TimeoutException(QString("Timed out waiting for channel with timeout_ms = %1").arg(long(timeout_ms)));
            return ret;
        }
        /// Put to the queue.  Note that if you specified a sizeLimit > 0 it will potentially throw ChannelFull if
        /// the queue is full.  Also may throw ChannelClosed if throwsIfClosed and the channel was closed.
        void put(const T & t) {
            if (UNLIKELY(killed)) {
                if (throwsIfClosed)
                    throw ChannelClosed("Cannot write to closed Channel");
                return;
            }
            QMutexLocker ml(&mut);
            if (UNLIKELY(sizeLimit > 0 && ct >= sizeLimit))
                throw ChannelFull(QString("The channel is full (size = %1)").arg(ct));
            data.push_back(t);
            ++ct;
            cond.wakeOne();
        }

        int count() const { return ct; }

        bool isClosed() const { return killed; }

        void clear() { QMutexLocker ml(&mut); _clear(); }
        void close() { QMutexLocker ml(&mut); killed = true; if (clearsOnClose) { _clear(); } cond.wakeAll(); }
    private:
        void _clear() { ct = 0; data.clear(); } ///< like clear() but caller must already hold mutex.
        std::atomic_bool killed = false, deleted = false;
        std::atomic_int ct = 0; ///< we keep track of the size of the queue because QList<>.count isn't always constant time.
        QList<T> data;
        QMutex mut;
        QWaitCondition cond;
    };

    struct VariantChannel : public Channel<QVariant>
    {
        template <typename V>
        inline V get(unsigned long timeout_ms = ULONG_MAX)
        { return Channel<QVariant>::get(timeout_ms).value<V>(); }
    };

    using VoidFunc = std::function<void()>;

    /// Stringify any 1D container's values (typically QSet or QList) by calling 'ToStringFunc'
    /// on each item, and producing a comma-separate string result, e.g.: "item1, item2, someotheritem" etc...
    template <typename CONTAINER>
    QString Stringify(const CONTAINER &cont,
                      const std::function<QString(const typename CONTAINER::value_type &)> & ToStringFunc,
                      const QString & sep = ", ")
    {
        QString ret;
        {
            QTextStream ss(&ret);
            int ct = 0;
            std::for_each(cont.begin(), cont.end(), [&](const typename CONTAINER::value_type & v){
                ss << (ct++ ? sep : "") << ToStringFunc(v);
            });
        }
        return ret;
    }
    /// Convenience for above -- call Stringify using a method pointer instead.
    /// Method signature is QString method() const;
    /// Defaults to 'toString()'
    template <typename CONTAINER>
    QString Stringify(const CONTAINER &cont,
                      // Pass any method pointer -- by default it's &value_type::toString
                      // but anything else works here if it matches the type signature.
                      QString (CONTAINER::value_type::*ToStringMethodPtr)() const = &CONTAINER::value_type::toString,
                      const QString & sep = ", ")
    {
        return Stringify(cont, [ToStringMethodPtr](const typename CONTAINER::value_type &v) -> QString {
            return (v.*ToStringMethodPtr)();
        }, sep);
    }

    template <typename StringLike>
    StringLike Ellipsify(const StringLike &s, int limit = 100)
    {
        if (limit < 0) return s;
        return s.length() > limit ? s.left(limit) + "..." : s;
    }

    template <typename Numeric,
              std::enable_if_t<std::is_arithmetic_v<Numeric>, int> = 0>
    QString Pluralize(const QString &wordIn, Numeric n) {
        QString ret;
        {
            if (qAbs(n) != Numeric(1)) {
                QString word(wordIn);
                QString ending = QStringLiteral("s"); // default to 's' ending
                const auto wordend = word.right(2);
                // 's' or "sh" sound in English are pluralized with "es" rather than simple "s"
                // 'y' endings have the 'y' truncated and 'ies' appended in its stead for plurals as well.
                // TODO: suppored ALL CAPS? Not needed for now in this app, so we don't bother...
                if (wordend.endsWith('s') || wordend == QStringLiteral("sh"))
                    ending = QStringLiteral("es");
                else if (wordend.endsWith('y')) {
                    word.truncate(word.length()-1);  // remove training 'y'
                    ending = QStringLiteral("ies");  // .. append 'ies' eg entry -> entries
                }
                ret = QStringLiteral("%1%2").arg(word, ending);
            } else
                ret = wordIn; // constant time copy (implicitly shared)
        }
        return ret;
    }

    /// -- Fast Hex Parser --
    /// Much faster than either bitcoin-abc's or Qt's hex parsers, especially if checkDigits=false.
    /// This function is about 6x faster than Qt's hex parser and 5x faster than abc's (iff checkDigits=false).
    /// Note that with checkDigits=true it's still faster than Qt's, and will detect errors in that case
    /// and return an empty string if non-hex digits are encountered. Unlike Qt's version it will not skip whitespace
    /// or skip invalid characters and it *will* fail in that case (whereas with checkDigits=false, it's blazingly
    /// fast but may return garbage data if non-hex digits are encountered).
    ///
    /// Does not throw any exceptions.  Returns an empty QByteArray on error, or a QByteArray that is
    /// the hex decoded version of its input on success.
    ///
    /// Note 1: If checkDigits=true this function is about 5x slower but it does detect invalid characters and returns
    ///         an empty QByteArray on malformed input.
    /// Note 2: If checkDigits=false, this function is blazingly fast. However it may return garbage/nonsense
    ///         data if the input contains any non-hex digits (including spaces!).
    /// Note 3: Whitespace is *never* skipped -- the input data must be nothing but hex digits, lower or upprcase is ok.
    QByteArray ParseHexFast(const QByteArray &, bool checkDigits = false);
    /// Identical to Qt's toHex, but 60% faster (returned string is lcase hex encoded).
    QByteArray ToHexFast(const QByteArray &);
    /// More efficient, if less convenient version of above. Operates on a buffer in-place.  Make sure bufsz is at least
    /// 2x the length of bytes.  `buf` must not overlap with `bytes`.
    bool ToHexFastInPlace(const QByteArray & bytes, char *buf, size_t bufsz);

    /// For each item in a QByteArray Container, hex encode each item using Util::ToHexFast().
    template <typename Container,
              std::enable_if_t<std::is_base_of_v<QByteArray, typename Container::value_type>, int> = 0>
    void hexEncodeEachItem(Container &c) { for (auto & item : c) item = Util::ToHexFast(item); }
    /// For each item in a QByteArray Container, hex decode each item using Util::ParseHexFast().
    template <typename Container,
              std::enable_if_t<std::is_base_of_v<QByteArray, typename Container::value_type>, int> = 0>
    void hexDecodeEachItem(Container &c) { for (auto & item : c) item = Util::ParseHexFast(item); }


    /// Call lambda() in the thread context of obj's thread. Will block until completed.
    /// If timeout_ms is not specified or negative, will block forever until lambda returns,
    /// otherwise will block for timeout_ms ms.  Will throw TimeoutException if the timeout
    /// elapsed without lambda() having a result ready. Will throw ThreadNotRunning if the target
    /// object's thread is not running.
    template <typename RET>
    RET LambdaOnObject(const QObject *obj, const std::function<RET()> & lambda, int timeout_ms=-1)
    {
        assert(obj);
        if (auto const objThr = obj->thread(); QThread::currentThread() == objThr) {
            // direct call to save on a copy c'tor
            return lambda();
        } else if (UNLIKELY(!objThr->isRunning())) {
            throw ThreadNotRunning(QString("Target object's thread is not running (objectName: '%1')").arg(obj->objectName()));
        } else {
            auto taskp = std::make_shared< std::packaged_task<RET()> >(lambda);
            auto future = taskp->get_future();
            QTimer::singleShot(0, const_cast<QObject *>(obj), [taskp] { (*taskp)(); });
            if (timeout_ms >= 0) {
                if (auto status = future.wait_for(std::chrono::milliseconds(timeout_ms));
                        status != std::future_status::ready) {
                    throw TimeoutException("Unable to obtain a result within the time period specified");
                }
            }
            return future.get();
        }
    }

    /// Like the above but doesn't throw, instead wraps the result in a std::optional and if the optional
    /// not has_value, you know there was an error or a timeout.
    /// Does not work if the RET type is void (optional<void> is disallowed).
    template <typename RET>
    std::optional<RET> LambdaOnObjectNoThrow(const QObject *obj, const std::function<RET()> & lambda, int timeout_ms=-1)
    {
        std::optional<RET> ret;
        try {
            ret.emplace( LambdaOnObject<RET>(obj, lambda, timeout_ms) );
        } catch (const ThreadNotRunning & e) {
            Warning() << __func__ << ": " << e.what();
        } catch (const Exception &) {}
        return ret;
    }

    /// Like the above but for VoidFunc lambdas.  Returns true if the lambda was called before timeout,
    /// false otherwise. (Note lambda may still run later asynchronously).
    bool VoidFuncOnObjectNoThrow(const QObject *obj, const VoidFunc & lambda, int timeout_ms=-1);

    /// Convenience for just setting up a QTimer::singleShot on an object, calling a lambda as the timeout.
    /// By default if when_ms is 0, the object will have the lambda invoked in its thread as soon as it
    /// returns to the event loop.  Always returns immediately.
    template <typename VoidFuncT,
    std::enable_if_t<std::is_invocable_v<VoidFuncT>, int> = 0>
    void AsyncOnObject(const QObject *obj, const VoidFuncT & lambda, unsigned when_ms=0, Qt::TimerType ttype = Qt::TimerType::CoarseTimer) {
        QTimer::singleShot(int(when_ms), ttype, const_cast<QObject *>(obj), lambda);
    }

    /// This is an alternative to creating signal/slot pairs for calling a method on an object that runs in another
    /// thread.
    ///
    /// I got tired of repeating that pattern over and over again (e.g. creating myMethod() as a signal connected to
    /// a private slot _myMethod()).
    ///
    /// To save typing, this template can just allow you to directly call a method on an object in its thread (uses
    /// QTimer::singleShot).
    ///
    /// Arguments are capture-copied.
    ///
    /// Basically, it directly checks the current thread versus object thread, and if they match, calls 'method'
    /// immediately.  If they do not match, enqeues the call using argument to the target's event loop, and returns
    /// right away.
    ///
    /// Example usage:
    ///
    ///       // if timeout is negative, no timeout used and will block forever until method executes and return result
    ///       int res = Util::CallOnObjectWithTimeout<int>(-1, myObj, &MyObj::doSomething, arg1, arg2, arg3)
    ///
    ///       // with timeout, will throw TimeoutException if timeout_ms expires before method returns
    ///       double res = Util::CallOnObjectWithTimeout<double>(500, myObj, &MyObj::getSum, 1.2, 3.4);
    ///
    ///       // void return type usage
    ///       Util::CallOnObjectWithTimeout<void>(250, myObj, &MyObj::noReturnVal, arg1)
    ///
    /// Exceptions thrown:
    ///    TimeoutException -- The method did not return a result in the timeout period specified.
    ///    ThreadNotRunning -- The target object's thred is not running.
    template <typename RET=void, typename QOBJ, typename METHOD, typename ... Args>
    RET CallOnObjectWithTimeout(int timeout_ms, QOBJ obj, METHOD method, Args && ...args) {
        assert(obj);
        static_assert(std::is_base_of<QObject, typename std::remove_pointer<QOBJ>::type>::value, "Not a QObject subclass");
        static_assert(std::is_member_function_pointer<METHOD>::value, "Not a member function pointer");
        if (QThread::currentThread() == obj->thread()) {
            // direct call to save on a copy c'tor
            return (obj->*method)(std::forward<Args>(args)...);
        } else {
            auto lambda = [method, args = std::make_tuple(obj, std::forward<Args>(args)...)]() -> RET {
                return std::apply(method, args);
            };
            return LambdaOnObject<RET>(obj, lambda, timeout_ms);
        }
    }

    /// Convenience method -- Identical CallOnObjectWithTimeout above except doesn't ever throw, instead returns an
    /// optional with no value on failure/timeout. Does not work if the RET type is void (optional<void> is disallowed).
    template <typename RET, typename QOBJ, typename METHOD, typename ... Args>
    std::optional<RET> CallOnObjectWithTimeoutNoThrow(int timeout_ms, QOBJ obj, METHOD method, Args && ...args) {
        std::optional<RET> ret;
        try {
            ret.emplace( CallOnObjectWithTimeout<RET>(timeout_ms, obj, method, std::forward<Args>(args)...) );
        } catch (const ThreadNotRunning & e) {
            Warning() << __func__ << ": " << e.what();
        } catch (const Exception &) {}
        return ret;
    }

    /// Convenience method -- Identical CallOnObjectWithTimeout  except uses an infinite timeout, so a valid result is always returned.
    /// Note: May still throw ThreadNotRunning (if thread for target object is not running).
    template <typename RET=void, typename QOBJ, typename METHOD, typename ... Args>
    RET CallOnObject(QOBJ obj, METHOD method, Args && ...args) {
        return CallOnObjectWithTimeout<RET>(-1, obj, method, std::forward<Args>(args)...);
    }

    /// Convenience method -- Identical CallOnObject above except doesn't ever throw, instead returns an optional with
    /// no value on failure/timeout.  Does not work if the RET type is void (optional<void> is disallowed).
    template <typename RET, typename QOBJ, typename METHOD, typename ... Args>
    std::optional<RET> CallOnObjectNoThrow(QOBJ obj, METHOD method, Args && ...args) {
        std::optional<RET> ret;
        try {
            ret.emplace( CallOnObject<RET>(obj, method, std::forward<Args>(args)...) );
        } catch (const ThreadNotRunning & e) {
            Warning() << __func__ << ": " << e.what();
        } catch (const Exception &) {}
        return ret;
    }

    /// uses MurmurHash3 with the unique seed initialized at app start.  Not safe to call before main() is entered.
    uint32_t hashData32(const ByteView &) noexcept;

    /// uses CityHash64 with the unique seed initialized at app start  Not safe to call before main() is entered.
    uint64_t hashData64(const ByteView &) noexcept;

    inline std::size_t hashForStd(const ByteView &bv) noexcept {
        constexpr auto size_t_size = sizeof(std::size_t);
        static_assert(size_t_size == sizeof(uint32_t) || size_t_size == sizeof(uint64_t));
        if constexpr (size_t_size == sizeof(uint64_t)) {
            return std::size_t(hashData64(bv));
        } else {
            return std::size_t(hashData32(bv));
        }
    }

    /// Hash a pointer for use with a std::unordered_map using murmur3 or cityhash64 (depending if 32bit or 64bit).
    /// Hashing a pointer is to prevent situations where patholically-spaced pointers lead to hashtable collisions.
    struct PtrHasher {
        template <typename T>
        std::size_t operator()(const T * const t) const noexcept {
            return hashForStd(ByteView{reinterpret_cast<const std::byte *>(&t), sizeof(t)});
        }
    };

    /// Template of use with unordered_map or unordered_set or similar.
    /// Returns a tuple of: [number_of_collisions_total, largest_single_bucket, median_bucket_size, median_nonzero_bucket_size]
    /// Note: this is slow-ish so it should be used for debug purposes only and not in a critical path.
    template<typename UnorderedSetOrMap>
    auto bucketStats(const UnorderedSetOrMap &m) -> std::tuple<decltype(std::declval<UnorderedSetOrMap>().bucket_size(0)), std::size_t, std::size_t, std::size_t> /* rely on SFINAE here */ {
        std::size_t collisions{}, max{};
        std::vector<std::size_t> sizes;
        sizes.reserve(m.bucket_count());
        for (std::size_t i = 0; i < m.bucket_count(); ++i) {
            const auto bsz = m.bucket_size(i); // this call itself is linear to the number of elements in the bucket
            if (bsz > 1) collisions += bsz;
            if (bsz > max) max = bsz;
            sizes.push_back(bsz);
        }
        // get median
        std::sort(sizes.begin(), sizes.end());
        const std::size_t median = sizes.empty() ? 0 : sizes[sizes.size()/2];
        // get median nonzero
        std::size_t medianNonzero = 0;
        if (!sizes.empty()) {
            // find first nonzero
            auto it = std::find_if(sizes.begin(), sizes.end(), [](auto num){ return num != 0; });
            if (it != sizes.end()) {
                // get middle element of that range
                const auto n = std::distance(it, sizes.end()), offset = std::distance(sizes.begin(), it);
                medianNonzero = sizes[offset + n/2];
            }
        }
        return {collisions, max, median, medianNonzero};
    }

    struct MemUsage { std::size_t phys{}, virt{}; };
    MemUsage getProcessMemoryUsage();
    /// On Linux and Windows, this will be accurate. On OSX will just be 1/2 of physical RAM.
    /// If unknown platform, or as a fallback on error, will return 2GiB.
    uint64_t getAvailablePhysicalRAM();

    /// A namespace for a bunch of functionality that can be used from an async POSIX signal handler.
    ///
    /// We can't really use any functions in a signal handler besides the ones in this table --
    /// https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04
    namespace AsyncSignalSafe {

        //! A very simple C string buffer. Uses the stack only, so it's async signal safe.
        //! Use this in an the app signal handler to build a simple (non-allocating) C string for
        //! writeStdErr() declared later in this file.
        template <std::size_t N = 255>
        struct SBuf {
            static_assert (N < std::size_t(std::numeric_limits<long>::max())); // ensure no signed overflow
            static constexpr std::size_t MaxLen = N;
            std::size_t len = 0;
            std::array<char, MaxLen + 1> strBuf;

            constexpr SBuf() noexcept { clear(); }

            /// Construct by formatting the args to this buffer.
            /// Usage: SBuf("A string: ", anum, " another string\n", anotherNum), etc.
            template <typename ... Args>
            SBuf(Args && ...args) noexcept : SBuf() {
                // fold expression: calls append() for each argument in the pack
                (append(std::forward<Args>(args)),...);
            }

            constexpr void clear() noexcept { len = 0; strBuf[0] = 0; }

            // append a string_view to the buffer
            SBuf & append(const std::string_view &sv) noexcept {
                auto *const s = sv.data();
                long slen = long(sv.length());
                if (slen <= 0) return *this;
                if (slen + len > MaxLen)
                    slen = long(MaxLen) - len;
                if (slen <= 0) return *this;
                std::strncpy(strBuf.data() + len, s, slen);
                len += slen;
                strBuf[len] = 0;
                return *this;
            }
            // append a single character
            SBuf & append(char c) noexcept {
                if (len >= MaxLen)
                    return *this;
                strBuf[len++] = c;
                strBuf[len] = 0;
                return *this;
            }
            // Append an integer converted to decimal string. If there is no room for the full decimal representation
            // of the integer, including possible minus sign, the decimal number will be truncated at the end.
            template <typename T, typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
            SBuf & append(T n) noexcept {
                /* Note: ideally we'd just use C++17 std::to_chars here -- however on some compilers we target, the
                 * implementation is missing from libstdc++!  So.. we must roll our own here... */
                static_assert(sizeof(T) <= 16, "This function assumes <= 128 bit ints for T");
                constexpr unsigned TmpMaxLen = 64; // should be enough even for 128 bit values
                char tmpBuf[TmpMaxLen];
                unsigned tmpLen = 0;
                bool neg = false;
                if (std::is_signed_v<T> && n < 0) { // special handling for negatives.. prepend minus, normalize to positive value
                    neg = true;
                    if (UNLIKELY(n == std::numeric_limits<T>::min())) { // special case for most negative `n`
                        // add digit accounting for its negativeness, then divide n by 10 so that its absolute value
                        // can fit in a positive T
                        tmpBuf[tmpLen++] = '0' - n % 10;
                        n /= 10;
                    }
                    n = -n; // when we get here, `-n` is guaranteed to fit in a positive T
                }
                do {
                    tmpBuf[tmpLen++] = '0' + n % 10;
                    n /= 10;
                } while (n); /* <-- no need to check if looping past end of tmpBuf; 64 chars is enough for at least 128 bit; see above static_assert */
                if (neg) tmpBuf[tmpLen++] = '-'; // append negative at end
                const long nBytes = std::max(std::min(long(MaxLen) - long(len), long(tmpLen)), 0L);
                const auto rbegin = std::make_reverse_iterator(tmpBuf + tmpLen),
                           rend   = std::make_reverse_iterator(tmpBuf + (long(tmpLen) - nBytes)); // handle truncation in cases where it doesn't fit
                std::copy(rbegin, rend, strBuf.begin() + len); // append in reverse to strBuf
                len += nBytes;
                strBuf[len] = 0; // terminating nul (there is always room for this char)
                return *this;
            }
            constexpr operator const char *() const noexcept { return strBuf.data(); }
            constexpr operator std::string_view() const noexcept { return {strBuf.data(), len}; }
            SBuf &operator=(const std::string_view &sv) noexcept { clear(); return append(sv); }
            SBuf &operator+=(const std::string_view &sv) noexcept { return append(sv); }
        };

        /// Writes directly to file descriptor 2 on platforms that have this concept (Windows, OSX, Unix, etc).
        /// On other platforms is a no-op.  Use this with SBuf() to compose a string to output to stderr
        /// immediately.  If writeNewLine is true, then the platform-specific "\r\n" or "\n" will be also written
        /// in a second write all.
        void writeStdErr(const std::string_view &, bool writeNewLine = true) noexcept;

        /// A very rudimentary primitive for signaling a condition from a signal handler,
        /// which is intended to get picked-up later by a monitoring thread.
        ///
        /// This class is necessary because none of the C++ synchronization primitives are technically async signal
        /// safe and thus cannot be used inside signal handlers.
        ///
        /// Internally, this class uses a self-pipe technique on platforms that have pipe() (such as Windows & Unix).
        /// On unknown platforms this behavior is emulated (in a technically async signal unsafe way) via use of C++
        /// std::condition_variable. While this latter technique is not techincally safe -- it is only a fallback so
        /// that we compile and run on such hypothetical unknown platforms. In practice this fallback technique won't
        /// cause problems 99.9999999% of the time (what's more: it is not even used on any known platform).
        struct Sem
        {
            Sem() = default; ///< may throw InternalError if it could not allocate necessary resources
            /// Call this from a monitoring thread -- blocks until realease() is called from e.g. a signal handler
            /// or another thread.  Will return a non-empty optional containing an error message on error.
            std::optional<SBuf<>> acquire() noexcept;
            /// Call this from a signal handler or from a thread that wants to wake up the monitoring thread.
            /// Will return a non-empty optional containing an error message on error.
            std::optional<SBuf<>> release() noexcept;

        private:
#if defined(Q_OS_WIN) || defined(Q_OS_UNIX)
            // async signal safe self-pipe
            struct Pipe { int fds[2]; Pipe(); /* <-- may throw */  ~Pipe(); };
            // copying not supported
            Sem(const Sem &) = delete;
            Sem &operator=(const Sem &) = delete;
#else
            // emulated fallback for unknown platforms
            struct Pipe { std::condition_variable cond; };
#endif
            Pipe p;
        };
    } // end namespace AsyncSignalSafe

    struct MaxOpenFilesResult {
        enum Status {
            Ok = 0, NotRelevant, Error
        };
        Status status = Error;
        long oldLimit = 0, newLimit = 0;
        QString errMsg{};
    };
    /// Supported on Unix only (on other platforms the result will be NotRelevant). Will attempt to raise the
    /// POSIX RLIMIT_NOFILE limit from the soft limit to the hard limit.
    MaxOpenFilesResult raiseMaxOpenFilesToHardLimit();

    /// Parses a <host>:<port> or <ip>:<port> pair and returns the parsed data. Throws BadArgs if data is bad such as
    /// the port being non-numeric or out of range.
    ///
    /// If allowImplicitLoopback=true then "<port>" by itself is interpreted as "127.0.0.1:<port>"
    QPair<QString, quint16> ParseHostPortPair(const QString &hostColonPort, bool allowImplicitLoopback = false);

    /// Tells you the size of a QByteArray::QArrayData object which each QByteArray that is not null has a pointer to.
    /// This function basically tells you how much extra space a QByteArray takes up just by existing, beyond its base
    /// sizeof(QByteArray) + .size()+1.
    inline constexpr size_t qByteArrayPvtDataSize(bool isNull = false) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
        static_assert (sizeof(decltype(std::declval<QByteArray>().size())) == sizeof(int),
                       "Assumption here is that QByteArray uses ints for indexing (true in Qt5, not true in Qt6)");
        constexpr size_t padding = sizeof(void *) > sizeof(int) ? sizeof(void *) - sizeof(int) : 0;
        return isNull ? 0 // null uses a single shared object so basically 0 extra size
                      : sizeof(int)*3 + padding + sizeof(void *); // not null -- QArrayData has 3 ints and 1 pointer (but pointer offset is padded for alignment on 64-bit)
#else
        // Qt6 QByteArray private data pointer has 2 ints and a qsizetype
        return isNull ? 0 : sizeof(int) * 2 + sizeof(qsizetype);
#endif
    }

} // end namespace Util

/// Kind of like Go's "defer" statement. Call a lambda (for clean-up code) at scope end.
/// Note for performance, we don't use a std::function wrapper but instead wrap any passed-in lambda directly.
///
/// This is a tiny performance optimization as it avoids a std::function wrapper. You can, however, also use a
/// std::function, with this class -- just be sure it's valid (operator bool() == true), since we don't check for
/// validity on std::function before invoking.
template <typename VoidFuncT = Util::VoidFunc,
          std::enable_if_t<std::is_invocable_v<VoidFuncT>, int> = 0>
struct Defer
{
    using VoidFunc = VoidFuncT;
    Defer(VoidFunc && f) : func(std::move(f)) {}
    Defer(const VoidFunc & f) : func(f) {}
    /// move c'tor -- invalidate other, take its function.
    Defer(Defer && o) : func(std::move(o.func)), valid(o.valid) { o.valid = false; }
    /// d'tor -- call wrapped func. if we are still valid.
    ~Defer() { if (valid) func(); }

    /// Mark this instance as a no-op. After a call to disable, this Defer instance  will no longer call its wrapped
    /// function upon descruction.  This operation cannot be reversed.
    void disable() { valid = false; }
protected:
    VoidFunc func;
    bool valid = true;
};

/// Like `Defer`, except you specify a function to be called at creation (immediately). Intended to be used for code
/// clarity so that it's obvious to readers of code what initialization code goes with what cleanup code.
///
/// E.g.:
///
///     RAII r1 {
///         [&]{ someUniqPtr = foo(); },  // called immediately
///         [&]{ someUniqPtr.reset(); }   // called at r1 destruction
///     };
///
/// Is equivalient to:
///
///     someUniqPtr = foo();
///     Defer d1( [&]{ someUniqPtr.reset(); } );
///
/// But the RAII version above is more explicit about what code goes with what cleanup.
struct RAII : public Defer<> {
    /// initFunc called immediately, cleanupFunc called in this instance's destructor
    RAII(const VoidFunc & initFunc, const VoidFunc &cleanupFunc) : Defer(cleanupFunc) { if (initFunc) initFunc(); valid = bool(cleanupFunc); }
    /// initFunc called immediately, cleanupFunc called in this instance's destructor
    RAII(const VoidFunc & initFunc, VoidFunc && cleanupFunc) : Defer(std::move(cleanupFunc)) { if (initFunc) initFunc(); valid = bool(cleanupFunc); }
};


/// Used to time code. Takes a timestamp (via getTimeNS) when it is constructed. Provides various utility
/// methods to read back the elapsed time since construction.
class Tic {
    static constexpr auto Invalid = std::numeric_limits<qint64>::min();
    qint64 t0 = Util::getTimeNS(), tf = Invalid;
    static qint64 now() noexcept { return Util::getTimeNS(); }
    template <typename T>
    using T_if_is_arithmetic = std::enable_if_t<std::is_arithmetic_v<T>, T>; // SFINAE evaluates to T if T is an arithmetic type
    template <typename T>
    T_if_is_arithmetic<T> el(T factor) const noexcept {
        return T((when() - t0) / factor);
    }
    qint64 when() const { return tf != Invalid ? tf : now(); }

public:
    /// Return the time since construction in seconds (note the default return type here is double)
    template <typename T = double>
    T_if_is_arithmetic<T>
    /* T */ secs() const noexcept { return el(T(1e9)); }

    /// Return the number of seconds formatted as a floating point string
    QString secsStr(int precision = 3) const { return QString::number(secs(), 'f', precision); }

    /// " milliseconds (note the default return type here is qint64)
    template <typename T = qint64>
    T_if_is_arithmetic<T>
    /* T */ msec() const noexcept { return el(T(1e6)); }

    /// Return the number of milliseconds formatted as a floating point string
    QString msecStr(int precision = 3) const { return QString::number(msec<double>(), 'f', precision); }

    /// " microseconds (note the default return type here is qint64)
    template <typename T = qint64>
    T_if_is_arithmetic<T>
    /* T */ usec() const noexcept { return el(T(1e3)); }

    /// Return the number of microseconds formatted as a floating point string
    QString usecStr(int precision = 3) const { return QString::number(usec<double>(), 'f', precision); }

    /// " nanoseconds
    qint64 nsec() const noexcept { return el(qint64(1)); }

    /// Return the number of nanoseconds formatted as an integer string
    QString nsecStr() const { return QString::number(nsec()); }

    /// Save the current time. After calling this, secs(), ms(), and us() above will return the time from
    /// construction until this was called.
    void fin() noexcept { tf = now(); }
};

/// Atomic wrapper for any struct, for multiple readers, one writer.
template <class T>
class AtomicStruct
{
    T t;
    mutable std::shared_mutex rwlock;

    // return a reference to the data item t, along with a scoped lock guard
    auto lockExclusively() { return std::pair<T &, std::unique_lock<std::shared_mutex>>(t, rwlock); }
    auto lock() const { return std::pair<const T &, std::shared_lock<std::shared_mutex>>(t, rwlock); }

public:
    // load/store atomically
    T load() const { return lock().first; }
    void store(const T & o) { lockExclusively().first = o; }
    void store(T && o) { lockExclusively().first = std::move(o); }
};

// helper type for std::visit (currently unused in this code base due to lack of std::variant support)
template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;
