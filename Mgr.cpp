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
Mgr::Stats Mgr::statsSafe() const
{
    auto ret = std::make_shared<Stats>();
    auto weak = decltype(ret)::weak_type(ret);
    Util::LambdaOnObject(this, [weak, this]{
        auto ret = weak.lock();
        if (ret)
            *ret = stats();
    }, 1000);
    return *ret;
}
