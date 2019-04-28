#include "ThreadObjectMixin.h"

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
    stop(); // this is here for paranoia reasons. In normal app function derived class should make sure it's stopped before we get here. This should be a NO-OP!
}


void ThreadObjectMixin::start()
{
    if (_thread.isRunning())  return;
    Debug() << qobj()->objectName() << " starting thread";
    chan.clear();
    qobj()->moveToThread(&_thread);
    conns.push_back(qobj()->connect(&_thread, &QThread::started, qobj(), [this](){on_started();}));
    conns.push_back(qobj()->connect(&_thread, &QThread::finished, qobj(), [this](){on_finished();}));
    _thread.start();
}

void ThreadObjectMixin::stop()
{
    if (_thread.isRunning()) {
        Debug() << qobj()->objectName() << " thread is running, joining thread";
        _thread.quit();
        _thread.wait();
    }
    for (auto c : conns) {
        qobj()->disconnect(c);
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
