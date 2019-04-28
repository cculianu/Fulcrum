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
    for (auto c : conns) {
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
