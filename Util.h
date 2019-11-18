#ifndef UTIL_H
#define UTIL_H

#include "Common.h"
#include <QtCore>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <optional>
#include <random>
#include <string>
#include <tuple>
#include <utility>

#define Q2C(qstr) ((qstr).toUtf8().constData())

class App;

/****
 * Loggers.
 * Declared first as some templates in Util use these.
 * Scroll down in this file for namespace Util..
 ****/
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

#define LIKELY(bool_expr)   EXPECT(bool(bool_expr), 1)
#define UNLIKELY(bool_expr) EXPECT(bool(bool_expr), 0)

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

    template <class T> Log & operator<<(const T & t) {  s << t; return *this;  }

    Log & setColor(Color c) { color = c; colorOverridden = true; return *this; }
    Color getColor() const { return color; }

protected:
    static QString colorString(Color c);
    QString colorify(const QString &, Color c);

    bool colorOverridden = false, useColor = true;
    int level = 0;
    Color color = Normal;
    QString str = "";
    QTextStream s = QTextStream(&str, QIODevice::WriteOnly);
};


// specialization to set the color.
template <> Log & Log::operator<<(const Color &);
// specialization for std::string
template <> inline Log& Log::operator<<(const std::string &t) { s << t.c_str(); return *this; }

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

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Debug(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};

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

#if defined(__GNUC__) && !defined(__clang__)
    // Grr.. GCC doesn't fully implement C++ 17 so we must do this. :(
    template <typename ...Args>
    explicit Trace(Args && ...args) : Log(std::forward<Args>(args)...) {}
#endif
};


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

namespace Util {
    extern QString basename(const QString &);

    qint64 getTime(); ///< returns a timestamp in milliseconds
    qint64 getTimeNS(); ///< returns a timestamp in nanoseconds
    double getTimeSecs(); ///< returns a timestamp in seconds
    bool isClockSteady(); ///< returns true if the above timestamp clock is steady (monotonic).

    template <typename Iterator>
    void shuffle(Iterator begin, Iterator end)
    {
        // We use Qt's implementation here because apparently MinGW on Windows using GCC before 9.2 uses a deterministic
        // RNG even if using std::random_device.  Qt's RNG does not have this problem.
        auto seed = QRandomGenerator::global()->generate();
        std::shuffle(begin, end, std::default_random_engine(seed));
    }

    template <typename Map>
    Map & updateMap(Map & map, const Map &updates) {
        for (auto it = updates.cbegin(); it != updates.cend(); ++it) {
            map.insert(it.key(), it.value());
        }
        return map;
    }

    namespace Json {
        /// Generic Json error (usually if expectMap is violated)
        struct Error : public Exception { using Exception::Exception; };
        /// More specific Json error -- usually if trying to parse malformed JSON text.
        struct ParseError : public Error { using Error::Error; };

        /// if expectmap, throws Error if not a dict. Otherwise throws Error if not a list.
        extern QVariant parseString(const QString &str, bool expectMap = true); ///< throws Error
        extern QVariant parseFile(const QString &file, bool expectMap = true); ///< throws Error
        extern QString toString(const QVariant &, bool compact = false); ///< throws Error
    }

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
                ret = data.takeFirst(); ct -= 1;
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
            ct += 1;
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

    /** Run a lambda in a thread.
     *
     * `work' will be called in the thread context of this QThread's run()
     * method. It should reference objects that remain alive until
     * `completion' is called (or the work completes).
     *
     * `completion' (if specified) will be called in the thread context of
     * the receiver's thread (or calling thread if receiver is nullptr) to
     * notify of thread completion.
     *
     * This object auto-deletes itself on completion by calling deleteLater().
     * As such, it is a programming error to allocate this object on the stack.
     * Because of that, access to this mechanism is via the factory static
     * function: 'Do' (all constructors have been made private to enforce
     * this).
     *
     * Caveats: If you hit CTRL-C to shutdown this app and the work is not yet
     * complete, the app wait for 5 seconds for all thrads and if they don't
     * finish, it will call C abort() with message:
     * 'QThread: Destroyed while thread is still running'.
     *
     */
    class RunInThread : public QThread
    {
        Q_OBJECT
    public:

        /// Note work should remain alive for the duration of this task!
        static RunInThread *
        Do ( const VoidFunc &work,  ///< called in thread's context to do work
             QObject *receiver = nullptr, ///< becomes this instance's child.  If not nullptr, should remain alive until work completes.
             const VoidFunc &completion = VoidFunc(), ///< called in receiver's thread on completion
             const QString & threadName = QString()) ///< advisory thread name used in Debug() and Log() print for code executing within the thread
        { return new RunInThread(work, receiver, completion, threadName); }

        /// Convenience for above.  Sets the receiver to 'nullptr' which puts the completion() function execution
        /// in the context of the calling thread.
        static RunInThread *
        Do ( const VoidFunc &work, const VoidFunc &completion = VoidFunc(),
             const QString & threadName = QString())
        { return new RunInThread(work, nullptr, completion, threadName); }

    protected:
        void run() override;

        friend class ::App;
        /// called by App on exit to indicate shutting down (blocks new threads from executing)
        static void setShuttingDown(bool b) { blockNew = b; }
        /// called by App on exit to wait for all work to complete.
        static bool waitForAll(unsigned long timeout_ms = ULONG_MAX, const QString &logMsgIfNeedsToWait=QString(),
                               int *numWorkers = nullptr);

    signals:
        void onCompletion();
    private:
        VoidFunc work;
        /// disabled public c'tor
        RunInThread(const VoidFunc &work,
                    QObject *receiver = nullptr,
                    const VoidFunc &completion = VoidFunc(),
                    const QString & threadName = QString());
        /// app exit cleanup handling
        static std::atomic_bool blockNew;
        static QSet<RunInThread *> extant;
        static QMutex mut;
        static QWaitCondition cond;
        void done();
    public:
        static void test(QObject *receiver = nullptr);
    };

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
                      // Pass any method pointer -- by default it's &value_type::toString (for BTC::Address and BTC::UTXO)
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

    /// Call lambda() in the thread context of obj's thread. Will block until completed.
    /// If timeout_ms is not specified or negative, will block forever until lambda returns,
    /// otherwise will block for timeout_ms ms.  Will throw TimeoutException if the timeout
    /// elapsed without lambda() having a result ready. Will throw ThreadNotRunning if the target
    /// object's thread is not running.
    template <typename RET>
    RET LambdaOnObject(const QObject *obj, const std::function<RET()> & lambda, int timeout_ms=-1)
    {
        if (QThread::currentThread() == obj->thread()) {
            // direct call to save on a copy c'tor
            return lambda();
        } else if (UNLIKELY(!obj->thread()->isRunning())) {
            throw ThreadNotRunning(QString("Target object's thread is not running (objectName: '%1')").arg(obj->objectName()));
        } else {
            auto taskp = std::make_shared< std::packaged_task<RET()> >(lambda);
            auto future = taskp->get_future();
            QTimer::singleShot(0, obj, [taskp] { (*taskp)(); });
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
            Warning() << __FUNCTION__ << ": " << e.what();
        } catch (const Exception &) {}
        return ret;
    }

    /// Like the above but for VoidFunc lambdas.  Returns true if the lambda was called before timeout,
    /// false otherwise. (Note lambda may still run later asynchronously).
    bool VoidFuncOnObjectNoThrow(const QObject *obj, const std::function<void()> & lambda, int timeout_ms=-1);

    /// This is an alternative to creating signal/slot pairs
    /// for calling a method on an object that runs in another thread.
    ///
    /// I got tired of repeating that pattern over and over again (e.g.
    /// creating myMethod() as a signal connected to a private slot
    /// _myMethod()).
    ///
    /// To save typing, this template can just allow you to directly call
    /// a method on an object in its thread (uses QTimer::singleShot).
    ///
    /// Arguments are capture-copied.
    ///
    /// Basically, it directly check the current thread versus object
    /// thread, and if they match, calls 'method' immediately.  If they do not
    /// match, enqeues the call using argument forwarding on a timer.
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
    /// optional with no value on failure/timeout.  Does not work if the RET type is void (optional<void> is disallowed).
    template <typename RET, typename QOBJ, typename METHOD, typename ... Args>
    std::optional<RET> CallOnObjectWithTimeoutNoThrow(int timeout_ms, QOBJ obj, METHOD method, Args && ...args) {
        std::optional<RET> ret;
        try {
            ret.emplace( CallOnObjectWithTimeout<RET>(timeout_ms, obj, method, std::forward<Args>(args)...) );
        } catch (const ThreadNotRunning & e) {
            Warning() << __FUNCTION__ << ": " << e.what();
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
            Warning() << __FUNCTION__ << ": " << e.what();
        } catch (const Exception &) {}
        return ret;
    }

} // end namespace Util

/// Kind of like Go's "defer" statement. Call a functor (for clean-up code) at scope end.
struct Defer
{
    using VoidFunc = std::function<void()>;
    VoidFunc func;

    Defer(const VoidFunc & f) : func(f) {}
    Defer(VoidFunc && f) : func(std::move(f)) {}
    Defer() {} ///< essentially a no-op. Intended for possibly specifying the function via `.func =` later.

    ~Defer() { if (func) func(); }
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
struct RAII : public Defer {
    /// initFunc called immediately, cleanupFunc called in this instance's destructor
    RAII(const VoidFunc & initFunc, const VoidFunc &cleanupFunc) : Defer(cleanupFunc) { if (initFunc) initFunc(); }
    /// initFunc called immediately, cleanupFunc called in this instance's destructor
    RAII(const VoidFunc & initFunc, VoidFunc && cleanupFunc) : Defer(std::move(cleanupFunc)) { if (initFunc) initFunc(); }
};

// helper type for std::visit (see RPC.cpp where we use this crazy C++17 thing)
template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> Overloaded(Ts...) -> Overloaded<Ts...>;

#endif // UTIL_H
