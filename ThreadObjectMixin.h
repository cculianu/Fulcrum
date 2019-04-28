#ifndef THREADOBJECT_MIXIN_H
#define THREADOBJECT_MIXIN_H

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

protected:
    QThread _thread, *origThread = nullptr;
    Util::Channel<QString> chan;
    QList<QMetaObject::Connection> conns;

    virtual QObject *qobj() = 0; ///< reimplement in subclasses to return the QObject pointer (this)
    virtual void start(); ///< derived classes should call super implementation
    virtual void stop(); ///< derived classes should call super implementation
    virtual void restart() { stop(); start(); }
protected slots:
    virtual void on_started(); ///< default impl does nothing
    virtual void on_finished(); ///< be sure to call this if you override. (does moveToThread(mainthread))
};

#endif // THREADOBJECT_MIXIN_H
