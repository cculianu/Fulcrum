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
Mgr::Stats
Mgr::stats() const
{
    return Stats();
}

// thread-safe
Mgr::Stats Mgr::statsSafe() const
{
    Stats ret;
    if (QThread::currentThread() == thread()) {
        ret = stats();
    } else if (thread()->isRunning()) {
        struct Shared {
            Util::VariantChannel chan;
            Stats stats;
        };
        std::shared_ptr<Shared> shared(new Shared, [](Shared *p){
            delete p;
            Debug() << "statsSafe shared ptr deleted ok!";
        });
        Util::VariantChannel & chan ( shared->chan );
        auto weak = std::weak_ptr<Shared>(shared);
        QTimer::singleShot(0, this, [this,weak] {
            auto shared = weak.lock();
            if (shared) {
                shared->stats = stats();
                shared->chan.put("ok");
            }
        });
        chan.get<QString>(1000); // wait up to 1 second for stats results
        ret = shared->stats;
        // note if the timer didn't fire in 1 second -- it's not exactly clear what is supposed to happen here
        // We try to mitigate a potential crash if the timer fires later after we exit from this function
        // by using the weak pointer approach above.
    }
    return ret;
}
