#include "BTC.h"
#include "Controller.h"

#include <cassert>
#include <iterator>
#include <list>
#include <map>

Controller::Controller(const std::shared_ptr<Options> &o)
    : Mgr(nullptr), options(o)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
}

Controller::~Controller() { Debug("%s", __FUNCTION__); cleanup(); }

void Controller::startup()
{
    storage = std::make_unique<Storage>(options);
    storage->startup(); // may throw here

    bitcoindmgr = std::make_unique<BitcoinDMgr>(options->bitcoind.first, options->bitcoind.second, options->rpcuser, options->rpcpassword);
    {
        // some setup code that waits for bitcoind to be ready before kicking off our "process" method
        auto waitForBitcoinD = [this] {
            auto constexpr waitTimer = "wait4bitcoind", callProcessTimer = "callProcess";
            int constexpr msgPeriod = 10000, // 10sec
                          smallDelay = 100;
            stopTimer(pollTimerName);
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

    // We defer listening for connections until we hit the "upToDate" state at least once, to prevent problems
    // for clients.
    auto connPtr = std::make_shared<QMetaObject::Connection>();
    *connPtr = connect(this, &Controller::upToDate, this, [this, connPtr] {
        if (connPtr) disconnect(*connPtr);
        if (!srvmgr) {
            if (!origThread) {
                Fatal() << "INTERNAL ERROR: Controller's creation thread is null; cannot start SrvMgr, exiting!";
                return;
            }
            srvmgr = std::make_unique<SrvMgr>(options->interfaces);
            // this object will live on our creation thread (normally the main thread)
            srvmgr->moveToThread(origThread);
            // now, start it up on our creation thread (normally the main thread)
            Util::VoidFuncOnObjectNoThrow(srvmgr.get(), [this]{
                // creation thread (normally the main thread)
                try {
                    srvmgr->startup(); // may throw Exception, waits for servers to bind
                } catch (const Exception & e) {
                    // exit app on bind/listen failure.
                    Fatal() << e.what();
                }
            }); // wait for srvmgr's thread (usually the main thread)
        }
    }, Qt::QueuedConnection);

    start();  // start our thread
}

void Controller::cleanup()
{
    stop();
    if (srvmgr) { Log("Stopping SrvMgr ... "); srvmgr->cleanup(); srvmgr.reset(); }
    if (bitcoindmgr) { Log("Stopping BitcoinDMgr ... "); bitcoindmgr->cleanup(); bitcoindmgr.reset(); }
    if (storage) { Log("Closing storage ..."); storage->cleanup(); storage.reset(); }
    sm.reset();
}

/// Encapsulates basically the data returned from bitcoind by the getblockchaininfo RPC method.
/// This has been separated out into its own struct for future use to detect blockchain changes.
/// TODO: Refactor this out to storage, etc to detect when blockchain changed.
struct ChainInfo {
    QString toString() const;

    QString chain = "";
    int blocks = 0, headers = -1;
    QByteArray bestBlockhash; ///< decoded bytes
    double difficulty = 0.0;
    int64_t mtp = 0;
    double verificationProgress = 0.0;
    bool initialBlockDownload = false;
    QByteArray chainWork; ///< decoded bytes
    size_t sizeOnDisk = 0;
    bool pruned = false;
    QString warnings;
};

struct GetChainInfoTask : public CtlTask
{
    GetChainInfoTask(Controller *ctl_) : CtlTask(ctl_, "Task.GetChainInfo") {}
    void process() override;

    ChainInfo info;
};

void GetChainInfoTask::process()
{
    submitRequest("getblockchaininfo", {}, [this](const RPC::Message & resp){
        const auto Err = [this, id=resp.id.toInt()](const QString &thing) {
            const auto msg = QString("Failed to parse %1").arg(thing);
            errorCode = id;
            errorMessage = msg;
            throw Exception(msg);
        };
        try {
            bool ok = false;
            const auto map = resp.result().toMap();

            if (map.isEmpty()) Err("response; expected map");

            info.blocks = map.value("blocks").toInt(&ok);
            if (!ok || info.blocks < 0) Err("blocks"); // enforce positive blocks number

            info.chain = map.value("chain").toString();
            if (info.chain.isEmpty()) Err("chain");

            info.headers = map.value("headers").toInt(); // error ignored here

            info.bestBlockhash = Util::ParseHexFast(map.value("bestblockhash").toByteArray());
            if (info.bestBlockhash.size() != bitcoin::uint256::width()) Err("bestblockhash");

            info.difficulty = map.value("difficulty").toDouble(); // error ignored here
            info.mtp = map.value("mediantime").toLongLong(); // error ok
            info.verificationProgress = map.value("verificationprogress").toDouble(); // error ok

            if (auto v = map.value("initialblockdownload"); v.canConvert<bool>())
                info.initialBlockDownload = v.toBool();
            else
                Err("initialblockdownload");

            info.chainWork = Util::ParseHexFast(map.value("chainwork").toByteArray()); // error ok
            info.sizeOnDisk = map.value("size_on_disk").toULongLong(); // error ok
            info.pruned = map.value("pruned").toBool(); // error ok
            info.warnings = map.value("warnings").toString(); // error ok

            if (Trace::isEnabled()) Trace() << info.toString();

            emit success();
        } catch (const Exception & e) {
            Error() << "INTERNAL ERROR: " << e.what();
            emit errored();
        }
    });
}

QString ChainInfo::toString() const
{
    QString ret;
    {
        QTextStream ts(&ret, QIODevice::WriteOnly|QIODevice::Truncate);
        ts << "(ChainInfo"
           << " chain: \"" << chain << "\""
           << " blocks: " << blocks
           << " headers: " << headers
           << " bestBlockHash: " << bestBlockhash.toHex()
           << " difficulty: " << QString::number(difficulty, 'f', 9)
           << " mtp: " << mtp
           << " verificationProgress: " << QString::number(verificationProgress, 'f', 6)
           << " ibd: " << initialBlockDownload
           << " chainWork: " << chainWork.toHex()
           << " sizeOnDisk: " << sizeOnDisk
           << " pruned: " << pruned
           << " warnings: \"" << warnings << "\""
           << ")";
    }
    return ret;
}

struct DownloadHeadersTask : public CtlTask
{
    DownloadHeadersTask(unsigned from, unsigned to, Controller *ctl, const QString &shortName = "Headers");
    void process() override;


    const unsigned from = 0, to = 0;
    unsigned next = 0;
    unsigned goodCt = 0;
    bool maybeDone = false;
    std::vector<QByteArray> headers;

    int q_ct = 0;
    static constexpr int max_q = BitcoinDMgr::N_CLIENTS+1; // todo: tune this

    static const int HEADER_SIZE;

    virtual void do_get(unsigned height);

    // thread safe, this is a rough estimate and not 100% accurate
    size_t nSoFar() const {  return size_t(qRound(((to-from)+1) * lastProgress)); }
};

struct DownloadBlocksTask : public DownloadHeadersTask
{
    DownloadBlocksTask(unsigned from_, unsigned to_, Controller *ctl_, const QString &shortName = "Blocks")
        : DownloadHeadersTask(from_, to_, ctl_, shortName) {}
    void do_get(unsigned height) override;
};

/*static*/ const int DownloadHeadersTask::HEADER_SIZE = int(BTC::GetBlockHeaderSize());

DownloadHeadersTask::DownloadHeadersTask(unsigned from, unsigned to, Controller *ctl_, const QString &shortName)
    : CtlTask(ctl_, QString("Task.%3 %1 -> %2").arg(from).arg(to).arg(shortName)), from(from), to(to)
{
    assert(to >= from); assert(ctl_);
    next = from;
    headers.reserve((to-from) + 1);
}

void DownloadHeadersTask::process()
{
    if (next > to) {
        if (maybeDone) {
            int bad = 0;
            for (size_t index = 0; index < headers.size(); ++index) {
                if (headers[index].length() != HEADER_SIZE) {
                    ++bad;
                    errorCode = int(index + from); // height
                    break;
                }
            }
            if (!bad) {
                emit success();
            } else {
                errorMessage = QString("header length incorrect for height %1").arg(errorCode);
                emit errored();
            }
        }
        return;
    }

    do_get(next++);
}

void DownloadHeadersTask::do_get(unsigned int bnum)
{
    submitRequest("getblockhash", {bnum}, [this, bnum](const RPC::Message & resp){ // testing
        QVariant var = resp.result();
        const auto hash = Util::ParseHexFast(var.toByteArray());
        if (hash.length() == bitcoin::uint256::width()) {
            submitRequest("getblockheader", {var, false}, [this, bnum, hash](const RPC::Message & resp){ // testing
                QVariant var = resp.result();
                const auto header = Util::ParseHexFast(var.toByteArray());
                QByteArray chkHash;
                if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                    const auto expectedCt = (to-from)+1;
                    const size_t index = bnum - from;
                    ++goodCt;
                    q_ct = qMax(q_ct-1, 0);
                    if (!(index % 1000) && index) {
                        emit progress(double(bnum-from) / double(expectedCt));
                    }
                    if (Trace::isEnabled()) Trace() << resp.method << ": header for height: " << bnum << " len: " << header.length();
                    // save header and hash when both are correct
                    if (headers.size() < index+1)
                        headers.resize(index+1);
                    headers[index] = header;
                    if (goodCt >= expectedCt) {
                        // flag state to maybeDone to do checks when process() called again
                        maybeDone = true;
                        AGAIN();
                        return;
                    }
                    while (goodCt + unsigned(q_ct) < expectedCt && q_ct < max_q) {
                        // queue multiple at once
                        AGAIN();
                        ++q_ct;
                    }
                } else if (!sizeOk) {
                    Warning() << resp.method << ": at height " << bnum << " header not valid (decoded size: " << header.length() << ")";
                    errorCode = int(bnum);
                    errorMessage = QString("bad size for height %1").arg(bnum);
                    emit errored();
                } else {
                    Warning() << resp.method << ": at height " << bnum << " header not valid (expected hash: " << hash.toHex() << ", got hash: " << chkHash.toHex() << ")";
                    errorCode = int(bnum);
                    errorMessage = QString("hash mismatch for height %1").arg(bnum);
                    emit errored();
                }
            });
        } else {
            Warning() << resp.method << ": at height " << bnum << " hash not valid (decoded size: " << hash.length() << ")";
            errorCode = int(bnum);
            errorMessage = QString("invalid hash for height %1").arg(bnum);
            emit errored();
        }
    });
}

void DownloadBlocksTask::do_get(unsigned int bnum)
{
    submitRequest("getblockhash", {bnum}, [this, bnum](const RPC::Message & resp){ // testing
        QVariant var = resp.result();
        const auto hash = Util::ParseHexFast(var.toByteArray());
        if (hash.length() == bitcoin::uint256::width()) {
            submitRequest("getblock", {var, false}, [this, bnum, hash](const RPC::Message & resp){ // testing
                QVariant var = resp.result();
                const auto rawblock = Util::ParseHexFast(var.toByteArray());
                const auto header = rawblock.left(HEADER_SIZE); // we need a deep copy of this anyway so might as well take it now.
                QByteArray chkHash;
                if (bool sizeOk = header.length() == HEADER_SIZE; sizeOk && (chkHash = BTC::HashRev(header)) == hash) {
                    bitcoin::CBlock block = BTC::DeserializeBlock(rawblock); // test deser speed
                    if (Trace::isEnabled()) Trace() << "block " << bnum << " size: " << rawblock.size() << " nTx: " << block.vtx.size();
                    const auto expectedCt = (to-from)+1;
                    const size_t index = bnum - from;
                    ++goodCt;
                    q_ct = qMax(q_ct-1, 0);
                    if (!(index % 1000) && index) {
                        emit progress(double(bnum-from) / double(expectedCt));
                    }
                    if (Trace::isEnabled()) Trace() << resp.method << ": header for height: " << bnum << " len: " << header.length();
                    // save header and hash when both are correct
                    if (headers.size() < index+1)
                        headers.resize(index+1);
                    headers[index] = header;
                    if (goodCt >= expectedCt) {
                        // flag state to maybeDone to do checks when process() called again
                        maybeDone = true;
                        AGAIN();
                        return;
                    }
                    while (goodCt + unsigned(q_ct) < expectedCt && q_ct < max_q) {
                        // queue multiple at once
                        AGAIN();
                        ++q_ct;
                    }
                } else if (!sizeOk) {
                    Warning() << resp.method << ": at height " << bnum << " header not valid (decoded size: " << header.length() << ")";
                    errorCode = int(bnum);
                    errorMessage = QString("bad size for height %1").arg(bnum);
                    emit errored();
                } else {
                    Warning() << resp.method << ": at height " << bnum << " header not valid (expected hash: " << hash.toHex() << ", got hash: " << chkHash.toHex() << ")";
                    errorCode = int(bnum);
                    errorMessage = QString("hash mismatch for height %1").arg(bnum);
                    emit errored();
                }
            });
        } else {
            Warning() << resp.method << ": at height " << bnum << " hash not valid (decoded size: " << hash.length() << ")";
            errorCode = int(bnum);
            errorMessage = QString("invalid hash for height %1").arg(bnum);
            emit errored();
        }
    });
}


struct Controller::StateMachine
{
    enum State {
        Begin=0, GetBlockHeaders, FinishedDL, End, Failure, IBD
    };
    State state = Begin;
    int ht = -1;
    std::map<unsigned, std::vector<QByteArray> > blockHeaders; // mapping of from_height -> headers
    std::map<std::pair<unsigned, unsigned>, unsigned> failures; // mapping of from,to -> failCt

    // todo: tune this
    const size_t DL_CONCURRENCY = Util::getNPhysicalProcessors();//size_t(qMin(qMax(int(Util::getNPhysicalProcessors())-BitcoinDMgr::N_CLIENTS, BitcoinDMgr::N_CLIENTS), 32));

    static constexpr unsigned maxErrCt = 3;

    const char * stateStr() const {
        static constexpr const char *stateStrings[] = { "Begin", "GetBlockHeaders", "FinishedDL", "End", "Failure", "IBD",
                                                        "Unknown" /* this should always be last */ };
        auto idx = qMin(size_t(state), std::size(stateStrings)-1);
        return stateStrings[idx];
    }
};

void Controller::rmTask(CtlTask *t)
{
    if (auto it = tasks.find(t); it != tasks.end()) {
        tasks.erase(it); // will delete object immediately
        return;
    }
    Error() << __FUNCTION__ << ": Task '" << t->objectName() << "' not found! FIXME!";
}

bool Controller::isTaskDeleted(CtlTask *t) const { return tasks.count(t) == 0; }

void Controller::add_DLHeaderTask(unsigned int from, unsigned int to, size_t nTasks)
{
    DownloadBlocksTask *t = newTask<DownloadBlocksTask>(false, unsigned(from), unsigned(to), this);
    connect(t, &CtlTask::success, this, [t, this, nTasks]{
        if (UNLIKELY(!sm || isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        Debug() << "Got all headers from: " << t->objectName() << " headerCt: "  << t->headers.size();
        sm->blockHeaders[t->from].swap(t->headers); // constant time copy
        if (sm->blockHeaders.size() == nTasks) {
            sm->state = StateMachine::State::FinishedDL;
            AGAIN();
        }
    });
    connect(t, &CtlTask::errored, this, [t, this, nTasks]{
        if (UNLIKELY(!sm || isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        if (sm->state == StateMachine::State::Failure) return; // silently ignore if we are already in failure
        // Handle failures with retries for the specific task -- failures are unlikely so it's ok to do it on this level
        if (auto ct = ++sm->failures[std::make_pair(t->from, t->to)]; ct < sm->maxErrCt) {
            Warning() << "Task errored: " << t->objectName() << ", error: " << t->errorMessage << ", retrying # " << ct << " ...";
            add_DLHeaderTask(t->from, t->to, nTasks);
        } else {
            Error() << "Task errored: " << t->objectName() << ", error: " << t->errorMessage << ", failed after " << ct << " tries, giving up";
            genericTaskErrored();
        }
    });
    connect(t, &CtlTask::progress, t, [t, this](double prog){
        if (UNLIKELY(!sm || isTaskDeleted(t))) return; // task was stopped from underneath us, this is stale.. abort.
        Log() << "Downloaded height: " << t->from + unsigned(qRound(prog*((t->to-t->from)+1))) << ", " << QString::number(prog*1e2, 'f', 1) << "%";
    }, Qt::DirectConnection);
}

void Controller::genericTaskErrored()
{
    if (sm && sm->state != StateMachine::State::Failure) {
        sm->state = StateMachine::State::Failure;
        AGAIN();
    }
}

template <typename CtlTaskT, typename ...Args, typename /* enable_if... */>
CtlTaskT *Controller::newTask(bool connectErroredSignal, Args && ...args)
{
    CtlTaskT *task = new CtlTaskT(std::forward<Args>(args)...);
    tasks.emplace(task, task);
    if (connectErroredSignal)
        connect(task, &CtlTask::errored, this, &Controller::genericTaskErrored);
    QTimer::singleShot(0, this, [task, this] {
        if (!isTaskDeleted(task))
            task->start();
    });
    return task;
}

void Controller::process(bool beSilentIfUpToDate)
{
    bool enablePollTimer = false;
    auto polltimeout = polltime_ms;
    stopTimer(pollTimerName);
    Debug() << "Process called...";
    if (!sm) sm = std::make_unique<StateMachine>();
    using State = StateMachine::State;
    if (sm->state == State::Begin) {
        auto task = newTask<GetChainInfoTask>(true, this);
        connect(task, &CtlTask::success, this, [this, task, beSilentIfUpToDate]{
            if (UNLIKELY(!sm || isTaskDeleted(task))) return; // task was stopped from underneath us, this is stale.. abort.
            if (task->info.initialBlockDownload) {
                sm->state = State::IBD;
                AGAIN();
                return;
            }
            if (const auto dbchain = storage->getChain(); dbchain.isEmpty() && !task->info.chain.isEmpty()) {
                storage->setChain(task->info.chain);
            } else if (dbchain != task->info.chain) {
                Fatal() << "Bitcoind reports chain: \"" << task->info.chain << "\", which differs from our database: \""
                        << dbchain << "\". You may have connected to the wrong bitcoind. To fix this issue either "
                        << "connect to a different bitcoind or delete this program's datadir to resynch.";
                return;
            }
            // TODO: detect reorgs here -- to be implemented later after we figure out data model more, etc.
            const auto old = int(storage->headers().first.size())-1;
            sm->ht = task->info.blocks;
            if (old == sm->ht) {
                if (!beSilentIfUpToDate) {
                    Log() << "Block height " << sm->ht << ", up-to-date";
                    emit upToDate();
                }
                sm->state = State::End;
            } else if (old > sm->ht) {
                Fatal() << "We have height " << old << ", but bitcoind reports height " << sm->ht << ". "
                        << "Possible reasons: A massive reorg, your node is acting funny, you are on the wrong chain "
                        << "(testnet vs mainnet), or there is a bug in this program. Cowardly giving up and exiting...";
                return;
            } else {
                Log() << "Block height " << sm->ht << ", downloading new headers ...";
                emit synchronizing();
                sm->state = State::GetBlockHeaders;
            }
            AGAIN();
        });
    } else if (sm->state == State::GetBlockHeaders) {
        const size_t base = storage->headers().first.size();
        const size_t num = size_t(sm->ht+1) - base;
        const size_t nTasks = qMax(size_t(1), num < 1000 ? size_t(1) : sm->DL_CONCURRENCY);
        const size_t headersPerTask = num / nTasks, rem = num % nTasks;
        for (size_t i = 0; i < nTasks; ++i) {
            auto N = i+1 < nTasks ? headersPerTask : headersPerTask+rem;
            auto from = unsigned(base + i*headersPerTask), to = unsigned((from + N) - 1);
            add_DLHeaderTask(from, to, nTasks);
        }
    } else if (sm->state == State::FinishedDL) {
        size_t ctr = 0;
        for (const auto & pair : sm->blockHeaders) {
            ctr += pair.second.size();
        }
        Log() << "Downloaded " << ctr << " new " << Util::Pluralize("header", ctr) << ", verifying ...";
        ctr = 0;
        {
            // Verify header chain makes sense (by checking hashes, using the shared header verifier)
            QString verifErr;
            auto [verif, lock] = storage->headerVerifier(); // lock needs to be held while we use this shared verifier
            const auto verifUndo = verif; // keep a copy for undo purposes in case this fails
            for (auto & [num, hdrs] : sm->blockHeaders) {
                Log() << "Verifying from " << num << " ...";
                for (const auto & hdr : hdrs) {
                    if ( !verif(hdr, &verifErr) ) {
                        // XXX possible reorg point. FIXME TODO
                        // reorg here? TODO: deal with this better.
                        Error() << verifErr;
                        sm->state = State::Failure;
                        verif = verifUndo; // undo header verifier state
                        AGAIN();
                        return;
                    }
                    ++ctr;
                }
            }
        }
        auto [headers, lock] = storage->mutableHeaders(); // write lock held until scope end
        if (const auto size = headers.size(); size + ctr < headers.capacity())
            headers.reserve(size + ctr); // reserve space for new headers in 1 go to save on copying
        ctr = 0;
        for (auto & [num, hdrs] : sm->blockHeaders) {
            Debug() << "Copying from " << num << " ...";
            headers.insert(headers.end(), hdrs.begin(), hdrs.end());
            ctr += hdrs.size();
            hdrs.clear();
        }
        headers.shrink_to_fit(); // make sure no memory is wasted since we don't push_back but rather reserve ahead of time each time.
        Log() << "Verified & copied " << ctr << " new " << Util::Pluralize("header", ctr) << " ok";
        sm.reset(); // go back to "Begin" state to check if any new headers arrived in the meantime
        AGAIN();
        storage->save(Storage::SaveItem::Hdrs); // enqueue a header commit to db ...
    } else if (sm->state == State::Failure) {
        // We will try again later via the pollTimer
        Error() << "Failed to download headers";
        sm.reset();
        enablePollTimer = true;
        emit synchFailure();
    } else if (sm->state == State::End) {
        sm.reset();  // great success!
        enablePollTimer = true;
    } else if (sm->state == State::IBD) {
        sm.reset();
        enablePollTimer = true;
        Warning() << "bitcoind is in initial block download, will try again in 1 minute";
        polltimeout = 60 * 1000; // try again every minute
        emit synchFailure();
    }

    if (enablePollTimer)
        callOnTimerSoonNoRepeat(polltimeout, pollTimerName, [this]{if (!sm) process(true);});
}


// -- CtlTask
CtlTask::CtlTask(Controller *ctl, const QString &name)
    : QObject(nullptr), ctl(ctl)
{
    setObjectName(name);
    _thread.setObjectName(name);
    connect(this, &CtlTask::progress, this, [this](double prog) { lastProgress = prog; });
}

CtlTask::~CtlTask() {
    Debug("%s (%s)", __FUNCTION__, objectName().isEmpty() ? "" : objectName().toUtf8().constData());
    stop();
}

void CtlTask::on_started()
{
    ThreadObjectMixin::on_started();
    conns += connect(this, &CtlTask::success, ctl, [this]{stop();});
    conns += connect(this, &CtlTask::errored, ctl, [this]{stop();});
    conns += connect(this, &CtlTask::finished, ctl, [this]{ctl->rmTask(this);});
    process();
    emit started();
}

void CtlTask::on_finished()
{
    ThreadObjectMixin::on_finished();
    emit finished();
}

void CtlTask::on_error(const RPC::Message &resp)
{
    Warning() << resp.method << ": error response: " << resp.toJsonString();
    errorCode = resp.errorCode();
    errorMessage = resp.errorMessage();
    emit errored();
}
void CtlTask::on_failure(const RPC::Message::Id &id, const QString &msg)
{
    Warning() << id.toString() << ": FAIL: " << msg;
    errorCode = id.toInt();
    errorMessage = msg;
    emit errored();
}
quint64 CtlTask::submitRequest(const QString &method, const QVariantList &params, const BitcoinDMgr::ResultsF &resultsFunc)
{
    quint64 id = IdMixin::newId();
    ctl->bitcoindmgr->submitRequest(this, id, method, params,
                                    resultsFunc,
                                    [this](const RPC::Message &r){on_error(r);},
                                    [this](const RPC::Message::Id &id, const QString &msg){on_failure(id, msg);});
    return id;
}



// --- Controller stats
auto Controller::stats() const -> Stats
{
    // "Servers"
    auto st = QVariantMap{{ "Servers", srvmgr ? srvmgr->statsSafe() : QVariant() }};

    // "BitcoinD's"
    st["Bitcoin Daemon"] = bitcoindmgr->statsSafe();

    // "Controller" (self)
    QVariantMap m;
    m["Headers"] = int(storage->headers().first.size());
    if (sm) {
        QVariantMap m2;
        m2["State"] = sm->stateStr();
        m2["Height"] = sm->ht;
        if (const auto nDL = nHeadersDownloadedSoFar(); nDL > 0)
            m2["Headers_Downloaded_This_Run"] = int(nDL);
        m["StateMachine"] = m2;
    } else
        m["StateMachine"] = QVariant(); // null
    QVariantMap timerMap;
    for (const auto & timer: _timerMap) {
        timerMap.insert(timer->objectName(), timer->interval());
    }
    m["activeTimers"] = timerMap;
    QVariantList l;
    { // task list
        const auto now = Util::getTime();
        for (const auto & [task, ign] : tasks) {
            Q_UNUSED(ign)
            l.push_back(QVariantMap{{ task->objectName(), QVariantMap{
                {"age", QString("%1 sec").arg(double((now-task->ts)/1e3))} ,
                {"progress" , QString("%1%").arg(QString::number(task->lastProgress*100.0, 'f', 1)) }}
            }});
        }
        Util::updateMap(m, QVariantMap{{"tasks" , l}});
    }
    st["Controller"] = m;
    return st;
}

size_t Controller::nHeadersDownloadedSoFar() const
{
    size_t ret = 0;
    for (const auto & [task, ign] : tasks) {
        Q_UNUSED(ign)
        auto t = dynamic_cast<DownloadHeadersTask *>(task);
        if (t)
            ret += t->nSoFar();
    }
    return ret;
}
