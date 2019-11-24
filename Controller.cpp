#include "BTC.h"
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
        auto waitForBitcoinD = [this] {
            auto constexpr waitTimer = "wait4bitcoind", callProcessTimer = "callProcess";
            int constexpr msgPeriod = 10000, // 10sec
                          smallDelay = 100;
            stopTimer(callProcessTimer);
            callOnTimerSoon(msgPeriod, waitTimer, []{ Log("Waiting for bitcoind..."); return true; }, false, Qt::TimerType::VeryCoarseTimer);
            // connection to kick off our 'process' method once the first auth is received
            auto connPtr = std::make_shared<QMetaObject::Connection>();
            *connPtr = connect(bitcoindmgr.get(), &BitcoinDMgr::gotFirstGoodConnection, this, [this, connPtr](quint64 id) mutable {
                if (connPtr) {
                    stopTimer(waitTimer);
                    if (!disconnect(*connPtr)) Fatal() << "Failed to disconnect 'authenticated' signal! FIXME!"; // this should never happen but if it does, app quits.
                    connPtr.reset(); // clear connPtr right away to 1. delte it asap and 2. so we are guaranteed not to reenter this block for this connection should there be a spurious signal emitted.
                    Debug() << "Auth recvd from bicoind with id: " << id << ", proceeding with processing ...";
                    callOnTimerSoonNoRepeat(smallDelay, callProcessTimer, [this]{process();}, true);
                }
            });
        };
        waitForBitcoinD();
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::allConnectionsLost, this, waitForBitcoinD);
        conns += connect(bitcoindmgr.get(), &BitcoinDMgr::inWarmUp, this, [last = -1.0](const QString &msg) mutable {
            // just print a message to the log as to why we keep dropping conn. -- if bitcoind is still warming up
            auto now = Util::getTimeSecs();
            if (now-last >= 1.0) { // throttled to not spam log
                last = now;
                Log() << "bitcoind is still warming up: " << msg;
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
    enum State {
        Begin, GetBlockHashes, End, Finished
    };
    State state = Begin;
    int bl = 0;
    int ht = -1;
    int cur = 0;
    static constexpr int maxcur = 16;//BitcoinDMgr::N_CLIENTS*4; // fixme: tune this
    Util::VoidFunc AGAIN;
    std::vector<QByteArray> blockHeaders;
};

void Controller::process()
{
    Debug() << "Process called...";

    static const int HEADER_SIZE = int(BTC::GetBlockHeaderSize());

    // TESTING...
    // TODO: This doesn't deal at all well with failures. After tuning this, figure out a
    // better way to recover from failure and keep retrying, etc.  This is just a first
    // stab to test communication, really.
    using S = StateMachine::State;
    if (!sm) {
        sm = std::make_unique<StateMachine>(); // create statemachine if doest not exist
        sm->AGAIN = [this]{ QTimer::singleShot(0, this, [this]{process();});};
    }
    static const auto BOILERPLATE_ERR =  [](const RPC::Message & resp){
        Warning() << resp.method << ": error response: " << resp.toJsonString();
    };
    static const auto BOILERPLATE_FAIL = [](auto id, auto msg) {
        Warning() << id.toString() << ": FAIL: " << msg;
    };
    if (sm->state == S::Begin) {
        bitcoindmgr->submitRequest(this, IdMixin::newId(), "getblockcount", {}, [this](const RPC::Message & resp){ // testing
            QVariant var = resp.result();
            Trace() << resp.method << ": result reply: " << var.toInt();
            if (var.canConvert<int>()) {
                int oldVal = sm->ht;
                const int newVal = var.toInt();
                if (newVal != oldVal) {
                    sm->ht = newVal;
                    sm->state = S::GetBlockHashes;
                    sm->blockHeaders.reserve(size_t(sm->ht+1)); // make sure there is space in our vector as we prepare to dl headers
                    while (sm->cur < sm->maxcur && oldVal++ < newVal) { // fixme: should be ngoodclients
                        sm->AGAIN();
                        ++sm->cur;
                    }
                } else {
                    Log() << "Headers up to date at height: " << sm->ht;
                    sm->state = S::Finished;
                    return;
                }
            } else {
                Warning() << resp.method << ": response not int!";
            }
        }, BOILERPLATE_ERR, BOILERPLATE_FAIL);
    } else if (sm->state == S::GetBlockHashes) {
        if (sm->bl > sm->ht) {
            // it's nonsensical to request block past known height -- todo: find out if this conditional is even needed. ideally it would never happen
            return;
        }
        unsigned bnum = unsigned(sm->bl++);
        bitcoindmgr->submitRequest(this, IdMixin::newId(), "getblockhash", {bnum}, [this, bnum](const RPC::Message & resp){ // testing
            QVariant var = resp.result();
            const auto hash = QByteArray::fromHex(var.toByteArray());
            if (hash.length() == bitcoin::uint256::width()) {
                bitcoindmgr->submitRequest(this, IdMixin::newId(), "getblockheader", {var, false}, [this, bnum, hash](const RPC::Message & resp){ // testing
                    sm->cur = qMax(0, sm->cur-1); // decrement current q ct
                    QVariant var = resp.result();
                    const auto header = QByteArray::fromHex(var.toByteArray());
                    QByteArray chkHash;
                    if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                        if (bnum && !(bnum % 1000)) {
                            Log("Processed block %u", bnum);
                        }
                        if (Trace::isEnabled()) Trace() << resp.method << ": header for height: " << bnum << " len: " << header.length();
                        // save header and hash when both are correct
                        if (sm->blockHeaders.size() < bnum+1)
                            sm->blockHeaders.resize(bnum+1);
                        sm->blockHeaders[bnum] = header;
                        while (sm->cur < sm->maxcur && sm->bl + sm->cur <= sm->ht) { // fixme: should be ngoodclients? maybe?
                            // queue up more requests
                            sm->AGAIN();
                            ++sm->cur;
                        }
                        if (sm->bl > sm->ht && sm->cur == 0) {
                            // we just got the last reply -- flag state to "end" to check headers received
                            sm->state = S::End;
                            sm->AGAIN();
                        }
                    } else if (!sizeOk) {
                        Warning() << resp.method << ": at height " << bnum << " header not valid (decoded size: " << header.length() << ")";
                    } else {
                        Warning() << resp.method << ": at height " << bnum << " header not valid (expected hash: " << hash.toHex() << ", got hash: " << chkHash.toHex() << ")";
                    }
                }, BOILERPLATE_ERR, BOILERPLATE_FAIL);
            } else {
                Warning() << resp.method << ": at height " << bnum << " hash not valid (decoded size: " << hash.length() << ")";
            }
        }, BOILERPLATE_ERR, BOILERPLATE_FAIL);
    } else if (sm->state == S::End) {
        Log() << "Downloaded " << sm->blockHeaders.size() << " headers (for height: " << sm->ht << "), verifying...";
        QTimer::singleShot(0, this, [this]{
            int bad = 0;
            for (const auto & ba : sm->blockHeaders) {
                if (ba.length() != HEADER_SIZE)
                    ++bad;
            }
            // TESTING
            if (bad)
                Log() << bad << " headers have the wrong length on either hash or header";
            else
                Log() << "All headers ok";
            sm->blockHeaders.reserve(sm->blockHeaders.size()); // tighten the vector back down against the data in case
            // trigger one last check for last few headers that may have come in -- this is still for testing.
            // ideally these two processes (height check & header dl) will be separated and signal each other.
            // on their progress and as information comes in, etc.
            sm->state = S::Begin;
            sm->AGAIN();
        });
    }

    /*
    bitcoindmgr->submitRequest(this, IdMixin::newId(), "getmempoolinfo", {}, [](auto resp){ // testing
        Trace() << resp.id.toString() << ": result reply: " << resp.toJsonString();
    }, [](auto resp){
        Trace() << resp.id.toString() << ": error response: " << resp.toJsonString();
    }, [](auto id, auto msg) {
        Warning() << id.toString() << ": FAIL: " << msg;
    });
    */
}
