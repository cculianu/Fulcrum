#ifndef UTIL_H
#define UTIL_H

#include "Common.h"
#include <QtCore>
#include <atomic>
#define Q2C(qstr) qstr.toUtf8().constData()

namespace Util {
    extern QString basename(const QString &);

    qint64 getTime(); ///< returns a timestamp in milliseconds
    qint64 getTimeNS(); ///< returns a timestamp in nanoseconds
    double getTimeSecs(); ///< returns a timestamp in seconds

    namespace Json {
        class Error : public Exception {
        public:
            using Exception::Exception;
            ~Error();
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
}

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

    explicit Log(const char *fmt...) __attribute__((format(printf, 2, 3)));
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
    explicit Debug(const char *fmt...) __attribute__((format(printf, 2, 3)));
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
    explicit Error(const char *fmt...) __attribute__((format(printf, 2, 3)));
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
    explicit Warning(const char *fmt...) __attribute__((format(printf, 2, 3)));
    virtual ~Warning();
};

#endif // UTIL_H
