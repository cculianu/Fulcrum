#ifndef MIXINS_H
#define MIXINS_H

#include "Util.h"

#include <QObject>
#include <QThread>
#include <QMap>
#include <QTimer>
#include <functional>
#include <memory>

/// This helper mixin just returns a pointer to the QObject subclass at runtime, leveraging RTTI. Used by
/// ThreadObjectMixin, TimersByNameMixin, and StatsMixin below.
///
/// A note about C++ multiple inheritance, regarding dynamic_cast *down* (which we need here for qobj()):
///
/// 1. In order for the qobj() virtual function below to not fail, all direct derived classes of this base should
///    inherit from this class via virtual inheritence. This ensures only 1 implementation of this base will be attached
///    to all concrete derived classes.  This only affects directly inheriting children (ie all the Mixins in this
///    file).
/// 2. In addition, all inheritence must be public all the way down, otherwise dynamic_cast<QObject *>(this) will fail.
///    See: https://en.cppreference.com/w/cpp/language/dynamic_cast#Explanation.
///    Likely this is because qobj() in this class can't "see" the derived class inherits from it unless the whole
///    chain of inheritence leading down is public.  This makes sense, actually.
class QObjectMixin
{
public:
    virtual ~QObjectMixin();
    /// returns a dynamic_cast ptr to this, cast to QObject.
    /// WARNING: Will return nullptr if instance is not a QObject subclass.
    /// WARNING 2: See the notes above about how to inherit in order for this to work.
    virtual QObject *qobj() const;
};

/// To *only* be used with QObject derived classes as a pure mixin.
/// Provides a thread, a channel, and a standard interface
class ThreadObjectMixin : public virtual QObjectMixin
{
public:
    ThreadObjectMixin();
    virtual ~ThreadObjectMixin();

protected:
    QThread _thread, *origThread = nullptr;
    Util::VariantChannel chan;
    QList<QMetaObject::Connection> conns;

    virtual void start(); ///< derived classes should call super implementation
    virtual void stop(); ///< derived classes should call super implementation
    virtual void restart() { stop(); start(); }

    virtual void on_started(); ///< default impl does nothing
    /// Below is not always called if app is exiting, unfortunately, but is called if thread is stoppped while app is
    /// still running. Be sure to call this if you override. (does moveToThread(mainthread))
    virtual void on_finished();
};


constexpr quint64 NO_ID = 0;

/// Mixin for an object that has an app-global id associated with it.
/// Used by the various AbstractClient subclasses because we need to keep
/// track of who sent what when, and it's more useful to work with ids rather
/// than direct pointers, for various reasons (also ElectrumX itself uses Ids to identify
/// messages).
class IdMixin
{
public:
    //IdMixin() = delete; // <-- this is implicitly the case because we have a const data member.
    inline IdMixin(const quint64 id) : id(id) {}

    const quint64 id;  /// derived classes should set this at construction by calling our c'tor

    static quint64 newId(); /// convenience method: calls app()->newId()
};


/// Convenience mixin class for a QObject that wishes to call a lambda sometime
/// in the future to do periodic maintenance tasks from a timer. Each named
/// timer is used to create a new QTimer object.  Repeated calls to the same timer
/// that has not yet fired will have no effect.  The functor provided should return
/// true if it wants the timer to fire again in the future, or false to delete it
/// using deleteLater.  The typical pattern for this is to queue up a maintenance task
/// on a named timer -- a task that may be queued up many times rapidly but you only
/// need it to run periodically (eg expiring a cache, etc).  See EXMgr.cpp and Controller.cpp
class TimersByNameMixin : public virtual QObjectMixin
{
public:
    TimersByNameMixin();
    virtual ~TimersByNameMixin();

protected:

    using _TimerMap = QMap<QString, std::shared_ptr<QTimer> >;
    _TimerMap _timerMap;

    /// the utility function that is the point of this class.
    void callOnTimerSoon(
        int timeout_milliseconds, ///< what interval to set for the timer. If timer is already active, nothing will change.
        const QString & timerName, ///< timer name. these should be unique. If same named timer is active, function will return immediately, func will be discarded.
        const std::function<bool()> & func, ///< function to call on timeout. If function returns true, timer is not stopped. Otherwise, it is removed from the map, stopped, and deleted later.
        bool forceTimerRestart = false, ///< if true, will force the timer to immediately be restarted now. This will *not* enqueue the new functor if a timer exited, just restart the timer on the pre-existing functor.
        Qt::TimerType = Qt::TimerType::CoarseTimer
    );
    /// Identical to above, except takes a pure voidfunc. It's as if the above returned false (so will not keep going).
    void callOnTimerSoonNoRepeat(
        int timeout_milliseconds,
        const QString & timerName,
        const std::function<void()> & singleShotFunc,
        bool forceTimerRestart = false,
        Qt::TimerType = Qt::TimerType::CoarseTimer
    );

    /// Returns true iff timer `name` exists
    inline bool isTimerByNameActive(const QString & name) const { return _timerMap.contains(name); }
    /// Calls setInterval for you on the named timer, if it exists, and returns true. Returns false otherwise.
    inline bool resetTimerInterval(const QString & name, int interval_ms) {
        if (auto timer = _timerMap.value(name); timer) {
            timer->setInterval(interval_ms);
            return true;
        }
        return false;
    }
    /// Calls setTimerType for you on the named timer, if it exists, and returns true. Returns false otherwise.
    inline bool resetTimerType(const QString & name, Qt::TimerType tt) {
        if (auto timer = _timerMap.value(name); timer) {
            timer->setTimerType(tt);
            return true;
        }
        return false;
    }
    inline int timerInterval(const QString & name) const {
        if (auto timer = _timerMap.value(name); timer) {
            return timer->interval();
        }
        return -1;
    }
    /// provided for stats/debug
    QStringList activeTimers() const { return _timerMap.keys(); }

    /// Stops the named timer and immediately deletes it.
    inline bool stopTimer(const QString &name) { auto timer = _timerMap.take(name); return bool(timer); }

};


/// A mixin for Mgr and AbstractConnection and other classes that can return stats.
class StatsMixin : public virtual QObjectMixin
{
public:
    virtual ~StatsMixin();

    using Stats = QVariant;
    using StatsParams = QMap<QString, QString>;

    static constexpr int kDefaultTimeout = 3000; ///< in milliseconds

    /// thread-safe wrapper around stats().
    Stats statsSafe(int timeout_ms = kDefaultTimeout) const;
    /// thread-safe wrapper around debug()
    Stats debugSafe(const StatsParams &, int timeout_ms = kDefaultTimeout) const;
protected:
    /// Return object-specific stats -- to be used by subsystems such as the /stats HTTP endpoint.
    /// This base class implementation returns an empty map, so you should override it.
    ///
    /// Note this function is unsafe and meant to be called within the Mgr's thread.
    /// Outside client code should use public statsSafe(), which wraps the below call in a
    /// thread-safe call, so that derived classes don't have to worry about thread safety and
    /// can just implement this function by examining their own private data to populate the map
    /// without locks.
    virtual Stats stats() const;
    virtual Stats debug(const StatsParams &) const;
};


/// A mixin for a QObject that may need to call process() on itself repeatedly.
/// The utility function AGAIN() is provided to schedule process() to run in the
/// event loop ASAP.
/// Used in Controller.h
class ProcessAgainMixin : virtual public QObjectMixin
{
public:
    virtual ~ProcessAgainMixin() override;
protected:
    virtual void process() = 0;
    void AGAIN(int when_ms=0) { QTimer::singleShot(qMax(0, when_ms), qobj(), [this]{process();}); }
};

#endif // MIXINS_H
