#include "App.h"
#include "Mixins.h"

QObjectMixin::~QObjectMixin() {}
QObject *QObjectMixin::qobj() const
{
    QObject *ret = dynamic_cast<QObject *>(const_cast<QObjectMixin *>(this));
    if (!ret) {
        Error() << __PRETTY_FUNCTION__ << ": Cannot cast this to QObject! App will likely crash now!";
    }
    return ret;
}

ThreadObjectMixin::ThreadObjectMixin()
{
}

ThreadObjectMixin::~ThreadObjectMixin()
{
    stop(); // paranoia.  Ideally child classes call this on d'tor to call their derived stop() methods.
}


void ThreadObjectMixin::start()
{
    if (_thread.isRunning())  return;
    Debug() << qobj()->objectName() << " starting thread";
    chan.clear();
    origThread = qobj()->thread();
    conns += origThread->connect(origThread, &QThread::finished, qApp, [this, which=conns.size()] {
        Warning() << "ThreadObjectMixin: original thread for " << qobj()->objectName() << " ended! Setting 'original thread' to main thread! FIXME!";
        origThread = qApp->thread();
        QObject::disconnect(conns.takeAt(which));
    });
    qobj()->moveToThread(&_thread);
    conns += QObject::connect(&_thread, &QThread::started, qobj(), [this]{on_started();});
    conns += QObject::connect(&_thread, &QThread::finished, qobj(), [this]{on_finished();});
    _thread.start();
}

void ThreadObjectMixin::stop()
{
    if (_thread.isRunning()) {
        Debug() << _thread.objectName() << " thread is running, joining thread";
        _thread.quit();
        _thread.wait();
    }
    int ct = 0;
    for (const auto & c : conns) {
        QObject::disconnect(c);
        ++ct;
    }
    conns.clear();
    if (ct)
        Debug() << _thread.objectName() << " cleaned up " << ct << " signsl/slot connections";
}


void ThreadObjectMixin::on_started()
{
}

void ThreadObjectMixin::on_finished()
{
    qobj()->moveToThread(origThread);
    origThread = nullptr;
}


/*static*/
quint64 IdMixin::newId() { return app()->newId(); }


TimersByNameMixin::TimersByNameMixin() {}
TimersByNameMixin::~TimersByNameMixin() {}

void TimersByNameMixin::callOnTimerSoon(int ms, const QString &name, const std::function<bool()> &func, bool force, Qt::TimerType ttype)
{
    if (auto it = _timerMap.find(name); it != _timerMap.end()) {
        if (force) {
            it->get()->stop(); // immediately stop timer
            _timerMap.erase(it);
            it = _timerMap.end(); // force delete QTimer since refs will go away
            callOnTimerSoon(ms, name, func, false, ttype); // immediately call self recursively once to re-enqueue timer
        }
        // timer was already active with force=false.. or was just re-enqueued with force=true.
        // return right away in either case
        return;
    }
    std::shared_ptr<QTimer> timer(new QTimer(qobj()), [](QTimer *t){ t->deleteLater(); });
    timer->setSingleShot(false);
    timer->setTimerType(ttype);
    QObject::connect(timer.get(), &QTimer::timeout, qobj(), [this, func, name]{
        const bool keepGoing = func();
        if (!keepGoing) {
            auto timer =  _timerMap.take(name);
            if (timer)
                timer->stop();
            // timer will go out of scope here and deleteLater() will be called.
        }
    });
    _timerMap[name] = timer;
    timer->setObjectName(name);
    timer->start(ms);
    //Debug() << "timerByName: " << name << " started, ms = " << ms;
}

/// Identical to above, except takes a pure voidfunc. It's as if the above returned false (so will not keep going).
void TimersByNameMixin::callOnTimerSoonNoRepeat(int ms, const QString &name, const std::function<void()> & fn, bool force, Qt::TimerType ttype)
{
    callOnTimerSoon(ms, name, [fn]() -> bool { fn(); return false; }, force, ttype);
}


/// --- StatsMixin
StatsMixin::~StatsMixin() {}

// unsafe in subclasses (safe here)
auto StatsMixin::stats() const -> Stats { return Stats(); }

// thread-safe
auto StatsMixin::statsSafe(int timeout_ms) const -> Stats
{
    Stats ret;
    try {
        ret = Util::LambdaOnObject<Stats>(qobj(), [this]{ return stats(); }, timeout_ms);
    } catch (const std::exception & e) {
        Debug() << "Safe stats get failed: " << e.what();
    }
    return ret;
}

ProcessAgainMixin::~ProcessAgainMixin() {}
