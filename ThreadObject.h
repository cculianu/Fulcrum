#ifndef THREADOBJECT_H
#define THREADOBJECT_H

#include <QObject>
#include <QThread>
#include "Util.h"

/// To *only* be used with QObject derived classes as a pure mixin.
/// Provides a thread, a channel, and a standard interface
class ThreadObjectMixin
{
public:
    ThreadObjectMixin();
    virtual ~ThreadObjectMixin();
    virtual QString prettyName() const;

    QObject *qobj() const { return dynamic_cast<QObject *>(const_cast<ThreadObjectMixin *>(this)); }

protected:
    QThread _thread;
    Util::Channel<QString> chan;
    QList<QMetaObject::Connection> conns;

    virtual void start(); ///< derived classes should call super implementation
    virtual void stop(); ///< derived classes should call super implementation
    virtual void restart() { stop(); start(); }
protected slots:
    virtual void on_started(); ///< default impll does nothing
    virtual void on_finished(); ///< be sure to chain to this if you override and call it.
};

#endif // THREADOBJECT_H
