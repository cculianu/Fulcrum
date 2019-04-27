#ifndef UTIL_H
#define UTIL_H

#include "Common.h"
#include <QtCore>
#include <atomic>
#include <functional>
#include <random>
#include <algorithm>
#include <chrono>
#define Q2C(qstr) qstr.toUtf8().constData()

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

/// Super class of Debug, Warning, Error classes.
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


    // the following specialization sets the color:
    //  template <> Log & operator<<(const Color &c);

    Log & setColor(Color c) { color = c; colorOverridden = true; return *this; }
    Color getColor() const { return color; }

protected:
    static QString colorString(Color c);
    QString colorify(const QString &, Color c);

    bool colorOverridden = false, useColor = true;
    Color color = Normal;
    QString str = "";
    QTextStream s = QTextStream(&str, QIODevice::WriteOnly);
};


// specialization to set the color.
template <> Log & Log::operator<<(const Color &);

/** \brief Stream-like class to print a debug message to the app's logging facility
    Example:
   \code
        Debug() << "This is a debug message"; // would print a debug message to the logging facility
   \endcode
 */
class Debug : public Log
{
public:
    Debug() : Log() {}
    explicit Debug(Color c) : Log(c) {}
    explicit Debug(const char *fmt...) ATTR_PRINTF(2,3);
    virtual ~Debug();
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
    Error() : Log() {}
    explicit Error(Color c) : Log(c) {}
    explicit Error(const char *fmt...) ATTR_PRINTF(2,3);
    virtual ~Error();
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
    Warning() : Log() {}
    explicit Warning(Color c) : Log(c) {}
    explicit Warning(const char *fmt...) ATTR_PRINTF(2,3);
    virtual ~Warning();
};


namespace Util {
    extern QString basename(const QString &);

    qint64 getTime(); ///< returns a timestamp in milliseconds
    qint64 getTimeNS(); ///< returns a timestamp in nanoseconds
    double getTimeSecs(); ///< returns a timestamp in seconds

    template <typename Iterator>
    void shuffle(Iterator begin, Iterator end)
    {
        try {
            static std::random_device *rng = nullptr;
            if (!rng) {
                rng = new std::random_device();
            }
            std::shuffle(begin, end, *rng);
        } catch (const std::exception &e) {
            static bool didWarn = false;
            if (!didWarn) {
                Warning() << __FUNCTION__ << ": true random generator unavailable, proceeding with PRNG based on system clock (" << e.what() << ")";
                didWarn = true;
            }
            // default pseudo rng
            static unsigned seed = unsigned(std::chrono::system_clock::now().time_since_epoch().count());
            std::shuffle(begin, end, std::default_random_engine(seed));
        }
    }

    namespace Json {
        class Error : public Exception {
        public:
            using Exception::Exception;
        };

        /// if expectmap, then throw if not a dict. Otherwise throw if not a list.
        extern QVariant parseString(const QString &str, bool expectMap = true); ///< throws Error
        extern QVariant parseFile(const QString &file, bool expectMap = true); ///< throws Error
        extern QString toString(const QVariant &, bool compact = false); ///< throws Error
    }

    // Go channel work-alike for sharing data across threads
    // T must be copy constructible and copyable, also default constructible
    template <typename T> class Channel
    {
    public:
        Channel() {}
        ~Channel() { close(); }
        // returns T() on fail
        T get(unsigned long timeout_ms = ULONG_MAX) {
            T ret;
            if (killed) return ret;
            QMutexLocker ml(&mut);
            bool timedOut = true;
            if (!killed && data.isEmpty() && timeout_ms > 0)
                timedOut = !cond.wait(&mut, timeout_ms);
            if (!timedOut && !killed && !data.isEmpty()) {
                ret = data.front();  data.pop_front();
            }
            return ret;
        }
        void put(const T & t) {
            if (killed) return;
            QMutexLocker ml(&mut);
            data.push_back(t);
            cond.wakeOne();
        }
        void clear() { QMutexLocker ml(&mut); data.clear(); }
        void close() { QMutexLocker ml(&mut); killed = true; cond.wakeAll(); }
    private:
        std::atomic_bool killed = false;
        QList<T> data;
        QMutex mut;
        QWaitCondition cond;
    };

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
        typedef std::function<void(void)> VoidFunc;

        /// Note work should remain alive for the duration of this task!
        static RunInThread *
        Do ( const VoidFunc &work,  ///< called in thread's context to do work
             QObject *receiver = nullptr, ///< becomes this instance's parent.  If not nullptr, should remain alive until work completes.
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
        std::function<void(void)> work;
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
}

#endif // UTIL_H
