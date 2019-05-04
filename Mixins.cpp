#include "Mixins.h"
#include "App.h"

ThreadObjectMixin::ThreadObjectMixin()
{
    origThread = QThread::currentThread();
    origThread->connect(origThread, &QThread::finished, [this]{
        Warning() << "ThreadObjectMixin " << qobj()->objectName() << ": original thread ended! Settings original thread to main thread! FIXME!";
        origThread = qApp->thread();
    });
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
    qobj()->moveToThread(&_thread);
    conns.push_back(QObject::connect(&_thread, &QThread::started, qobj(), [this](){on_started();}));
    conns.push_back(QObject::connect(&_thread, &QThread::finished, qobj(), [this](){on_finished();}));
    _thread.start();
}

void ThreadObjectMixin::stop()
{
    if (_thread.isRunning()) {
        Debug() << _thread.objectName() << " thread is running, joining thread";
        _thread.quit();
        _thread.wait();
    }
    for (const auto & c : conns) {
        QObject::disconnect(c);
    }
    conns.clear();
}


void ThreadObjectMixin::on_started()
{
}

void ThreadObjectMixin::on_finished()
{
    qobj()->moveToThread(origThread);
}


/*static*/
qint64 IdMixin::newId() { return app()->newId(); }


TimersByNameMixin::TimersByNameMixin() {}
TimersByNameMixin::~TimersByNameMixin() {}

void TimersByNameMixin::callOnTimerSoon(int ms, const QString &name, const std::function<bool (void)> &func)
{
    if (_timerMap.contains(name))
        // timer already active
        return;
    QSharedPointer<QTimer> timer(new QTimer(qobj()), [](QTimer *t){ t->deleteLater(); });
    timer->setSingleShot(false);
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
    timer->start(ms);
    //Debug() << "timerByName: " << name << " started, ms = " << ms;
}

/// Identical to above, except takes a pure voidfunc. It's as if the above returned false (so will not keep going).
void TimersByNameMixin::callOnTimerSoonNoRepeat(int ms, const QString &name, const std::function<void (void)> & fn)
{
    callOnTimerSoon(ms, name, [fn]() -> bool { fn(); return false; });
}
