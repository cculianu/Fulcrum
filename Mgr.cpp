#include "Mgr.h"
#include "Util.h"
#include <QTimer>
#include <QThread>
#include <memory>

Mgr::Mgr(QObject *parent)
    : QObject(parent)
{
}

Mgr::~Mgr()
{
}


// unsafe
auto Mgr::stats() const -> Stats
{
    return Stats();
}

// thread-safe
auto Mgr::statsSafe(int timeout_ms) const -> Stats
{
    Stats ret;
    try {
        ret = Util::CallOnObjectWithTimeout<Stats>(timeout_ms, this, &Mgr::stats); // NB: this will actually call the subclass's virtual function because C++ is awesome.
    } catch (const std::exception & e) {
        Debug() << "Safe stats get failed: " << e.what();
    }
    return ret;
}
