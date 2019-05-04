#ifndef SHUFFLEUP_MIXINS_H
#define SHUFFLEUP_MIXINS_H

#include "Util.h"

#include <QObject>
#include <QThread>
#include <QMap>
#include <QSharedPointer>
#include <QTimer>
#include <functional>

/// To *only* be used with QObject derived classes as a pure mixin.
/// Provides a thread, a channel, and a standard interface
class ThreadObjectMixin
{
public:
    ThreadObjectMixin();
    virtual ~ThreadObjectMixin();

protected:
    QThread _thread, *origThread = nullptr;
    Util::VariantChannel chan;
    QList<QMetaObject::Connection> conns;

    virtual QObject *qobj() = 0; ///< reimplement in subclasses to return the QObject pointer (this)
    virtual void start(); ///< derived classes should call super implementation
    virtual void stop(); ///< derived classes should call super implementation
    virtual void restart() { stop(); start(); }

    virtual void on_started(); ///< default impl does nothing
    virtual void on_finished(); ///< be sure to call this if you override. (does moveToThread(mainthread))
};


constexpr qint64 NO_ID = -1;

/// Mixin for an object that has an app-global id associated with it.
/// Used by the various AbstractClient subclasses because we need to keep
/// track of who sent what when, and it's more useful to work with ids rather
/// than direct pointers, for various reasons (also ElectrumX itself uses Ids to identify
/// messages).
class IdMixin
{
public:
    //IdMixin() = delete; // <-- this is implicitly the case because we have a const data member.
    inline IdMixin(const qint64 id) : id(id) {}

    const qint64 id;  /// derived classes should set this at construction by calling our c'tor

    static qint64 newId(); /// convenience method: calls app()->newId()
};


/// Convenience mixin class for a QObject that wishes to call a lambda sometime
/// in the future to do periodic maintenance tasks from a timer. Each named
/// timer is used to create a new QTimer object.  Repeated calls to the same timer
/// that has not yet fired will have no effect.  The functor provided should return
/// true if it wants the timer to fire again in the future, or false to delete it
/// using deleteLater.  The typical pattern for this is to queue up a maintenance task
/// on a named timer -- a task that may be queued up many times rapidly but you only
/// need it to run periodically (eg expiring a cache, etc).  See EXMgr.cpp and Controller.cpp
class TimersByNameMixin
{
public:
    TimersByNameMixin();
    virtual ~TimersByNameMixin();
protected:
    virtual QObject *qobj() = 0;

    typedef QMap<QString, QSharedPointer<QTimer> > _TimerMap;
    _TimerMap _timerMap;

    /// the utility function that is the point of this class.
    void callOnTimerSoon(
        int timeout_milliseconds, ///< what interval to set for the timer. If timer is already active, nothing will change.
        const QString & timerName, ///< timer name. these should be unique. If same named timer is active, function will return immediately, func will be discarded.
        const std::function<bool(void)> & func ///< function to call on timeout. If function returns true, timer is not stopped. Otherwise, it is removed from the map, stopped, and deleted later.
    );
};

#endif // SHUFFLEUP_MIXINS_H
