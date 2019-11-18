#include "Controller.h"

Controller::Controller(const std::shared_ptr<Options> &o)
    : Mgr(nullptr), options(o)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
}

Controller::~Controller() { Debug(__FUNCTION__); cleanup(); }

auto Controller::stats() const -> Stats
{
    auto st = srvmgr->statsSafe();
    Util::updateMap(st, bitcoindmgr->statsSafe());
    return st;
}

void Controller::startup()
{
    bitcoindmgr = std::make_unique<BitcoinDMgr>(options->bitcoind.first, options->bitcoind.second, options->rpcuser, options->rpcpassword);
    {
        // some setup code that waits for bitcoind to be ready before kicking off our "process" method
        static auto constexpr waitTimer = "wait4bitcoind";
        callOnTimerSoon(10000, waitTimer, []{ Log("Waiting for bitcoind..."); return true; }, true, Qt::TimerType::VeryCoarseTimer);
        // connection to kick off our 'process' method once the first auth is received
        auto connPtr = std::make_shared<QMetaObject::Connection>();
        *connPtr = connect(bitcoindmgr.get(), &BitcoinDMgr::authenticated, this, [this, connPtr](qint64 id) mutable {
            if (connPtr) {
                stopTimer(waitTimer);
                if (!disconnect(*connPtr)) Fatal() << "Failed to disconnect 'authenticated' signal! FIXME!"; // this should never happen but if it does, app quits.
                connPtr.reset();
                Debug() << "first auth recvd from bicoind with id: " << id << ", proceeding with processing ...";
                QTimer::singleShot(100, this, &Controller::process);
            }
        });
    }

    bitcoindmgr->startup(); // may throw

    srvmgr = std::make_unique<SrvMgr>(options->interfaces, nullptr /* we are not parent so it won't follow us to our thread*/);
    srvmgr->startup(); // may throw Exception, waits for servers to bind

    start();  // start our thread
}

void Controller::cleanup()
{
    stop();
    if (srvmgr) { Log("Stopping SrvMgr ... "); srvmgr->cleanup(); srvmgr.reset(); }
    if (bitcoindmgr) { Log("Stopping BitcoinDMgr ... "); bitcoindmgr->cleanup(); bitcoindmgr.reset(); }
    sm.reset();
}



struct Controller::StateMachine
{
    // TODO: put state stuff here
};

void Controller::process()
{
    Debug() << "Process called...";
    if (!sm) sm = std::make_unique<StateMachine>(); // create statemachine if doest not exist

}
