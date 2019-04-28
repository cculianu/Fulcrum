#ifndef SHUFFLEUP_MIXINS_H
#define SHUFFLEUP_MIXINS_H

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
    Util::VariantChannel chan;
    QList<QMetaObject::Connection> conns;

    virtual QObject *qobj() = 0; ///< reimplement in subclasses to return the QObject pointer (this)
    virtual void start(); ///< derived classes should call super implementation
    virtual void stop(); ///< derived classes should call super implementation
    virtual void restart() { stop(); start(); }

    virtual void on_started(); ///< default impl does nothing
    virtual void on_finished(); ///< be sure to call this if you override. (does moveToThread(mainthread))
};


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

#endif // SHUFFLEUP_MIXINS_H
