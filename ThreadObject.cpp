#include "ThreadObject.h"

ThreadObjectMixin::ThreadObjectMixin()
{
    Q_ASSERT(qobj());
}

ThreadObjectMixin::~ThreadObjectMixin()
{}

QString ThreadObjectMixin::prettyName() const
{
    return QString(qobj()->objectName().isNull() ? "(ThreadObject)" : qobj()->objectName());
}


void ThreadObjectMixin::start()
{
    if (_thread.isRunning())
        return;
    chan.clear();
    qobj()->moveToThread(&_thread);
    conns.push_back(qobj()->connect(&_thread, &QThread::started, qobj(), [this](){on_started();}));
    conns.push_back(qobj()->connect(&_thread, &QThread::finished, qobj(), [this](){on_finished();}));
    _thread.start();
}

void ThreadObjectMixin::stop()
{
    if (_thread.isRunning()) {
        Debug() << prettyName() << " thread is running, joining thread";
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
    qobj()->moveToThread(qApp->thread());
}
