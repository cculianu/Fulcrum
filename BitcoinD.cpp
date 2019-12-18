#include <QPointer>

#include "bitcoin/rpc/protocol.h"

#include "BitcoinD.h"

BitcoinDMgr::BitcoinDMgr(const QHostAddress &host, quint16 port,
                         const QString &user, const QString &pass)
    : Mgr(nullptr), IdMixin(newId()), host(host), port(port), user(user), pass(pass)
{
    setObjectName("BitcoinDMgr");
    _thread.setObjectName(objectName());
}

BitcoinDMgr::~BitcoinDMgr() {  cleanup(); }

void BitcoinDMgr::startup() {
    Log() << objectName() << ": starting " << N_CLIENTS << " " << Util::Pluralize("bitcoin rpc client", N_CLIENTS) << " ...";

    for (auto & client : clients) {
        client = std::make_unique<BitcoinD>(host, port, user, pass);

        // connect client to us -- TODO: figure out workflow: how requests for work and results will get dispatched
        connect(client.get(), &BitcoinD::gotMessage, this, &BitcoinDMgr::on_Message);
        connect(client.get(), &BitcoinD::gotErrorMessage, this, &BitcoinDMgr::on_ErrorMessage);
        connect(client.get(), &BitcoinD::authenticated, this, [this](BitcoinD *b){
            // guard against stale/old signal
            if (!b->isGood()) {
                Debug() << "got authenticated for id:" << b->id << " but isGood() is false!";
                return; // false/stale signal
            }
            const bool wasEmpty = goodSet.empty();
            goodSet.insert(b->id);
            if (wasEmpty)
                emit gotFirstGoodConnection(b->id);
        });
        connect(client.get(), &BitcoinD::lostConnection, this, [this](AbstractConnection *c){
            // guard against stale/old signal
            if (c->isGood()) {
                Debug() << "got lostConnection for id:" << c->id << " but isGood() is true!";
                return; // false/stale signal
            }
            goodSet.erase(c->id);
            auto constexpr chkTimer = "checkNoMoreBitcoinDs";
            // we throttle the spamming of the allConnectionsLost signal via this mechanism
            callOnTimerSoonNoRepeat(miniTimeout, chkTimer, [this]{
                if (goodSet.empty())
                    emit allConnectionsLost();
            }, true);
        });

        client->start();
    }

    start();

    Log() << objectName() << ": started ok";
}

void BitcoinDMgr::cleanup() {
    stop();

    for (auto & client : clients) {
        client.reset(); /// implicitly calls client->stop()
    }
    goodSet.clear();

    Debug() << "BitcoinDMgr cleaned up";
}

void BitcoinDMgr::on_Message(quint64 bid, const RPC::Message &msg)
{
    if (Trace::isEnabled()) Trace() << "Msg from: " << bid << " method=" << msg.method;
}
void BitcoinDMgr::on_ErrorMessage(quint64 bid, const RPC::Message &msg)
{
    Debug() << "ErrMsg from: " << bid << " error=" << msg.errorMessage();
    if (msg.errorCode() == bitcoin::RPCErrorCode::RPC_IN_WARMUP) {
        emit inWarmUp(msg.errorMessage());
    }
}


auto BitcoinDMgr::stats() const -> Stats
{
    QVariantList l;
    constexpr int timeout = kDefaultTimeout/qMax(N_CLIENTS,1);
    for (const auto & client : clients) {
        if (!client) continue;
        auto map = client->statsSafe(timeout).toMap();
        auto name = map.take("name").toString();
        l += QVariantMap({{ name, map }});
    }
    return l;
}


BitcoinD *BitcoinDMgr::getBitcoinD()
{
    BitcoinD *ret = nullptr;
    unsigned which = 0;
    if (unsigned n = quint32(goodSet.size()); n > 1)
        which = QRandomGenerator::system()->bounded(n); // pick a random client in the set (which is an index of the "good clients")
    if (!goodSet.empty()) {
        // linear search for a bitcoind that is not lastBitcoinDUsed
        unsigned i = 0;
        for (auto & client : clients) {
            if (goodSet.count(client->id) && i++ == which && client->isGood()) {
                ret = client.get();
                break;
            }
        }
    }
    return ret;
}

/// this is safe to call from any thread. internally it dispatches messages to this obejct's thread.
/// may throw (TODO list exceptions it may throw). Results/Error/Fail functions are called in the context of the sender's thread.
/// Returns the BitcoinD->id that was given the message.
void BitcoinDMgr::submitRequest(QObject *sender, const RPC::Message::Id &rid, const QString & method, const QVariantList & params,
                                const ResultsF & resf, const ErrorF & errf, const FailF & failf)
{
    using namespace BitcoinDMgrHelper;
    constexpr bool debugDeletes = false; // set this to true to print debug messages tracking all the below object deletions (tested: no leaks!)
    auto context = std::shared_ptr<ReqCtxObj>(new ReqCtxObj, [](ReqCtxObj *context){
        if constexpr (debugDeletes) {
            Debug() << context->objectName() << " shptr deleter";
            connect(context, &QObject::destroyed, qApp, [n=context->objectName()]{ Debug() << n << " destroyed"; }, Qt::DirectConnection);
        }
        context->deleteLater();
    });
    context->setObjectName(QString("context for '%1' request id: %2").arg(sender ? sender->objectName() : "").arg(rid.toString()));
    auto replied = std::make_shared<std::atomic_bool>(false); // guards against spurious lostConnection arriving after reply msg
    connect(context.get(), &ReqCtxObj::results, sender, [context, resf, replied](const RPC::Message &response) {
        if (!replied->exchange(true) && resf)
            resf(response);
        context->disconnect(); // kills all lambdas and shared ptr, should cause deleter to execute
    });
    connect(context.get(), &ReqCtxObj::error, sender, [context, errf, replied](const RPC::Message &response) {
        if (!replied->exchange(true) && errf)
            errf(response);
        context->disconnect(); // kills all lambdas and shared ptr, should cause deleter to execute
    });
    connect(context.get(), &ReqCtxObj::fail, sender, [context, failf, replied](const RPC::Message::Id &origId, const QString & failureReason) {
        if (!replied->exchange(true) && failf)
            failf(origId, failureReason);
        context->disconnect(); // kills all lambdas and shared ptr, should cause deleter to execute
    });
    context->moveToThread(this->thread());

    // schedule this ASAP
    QTimer::singleShot(0, this, [this, context, rid, method, params] {
        auto bd = getBitcoinD();
        if (UNLIKELY(!bd)) {
            emit context->fail(rid, "Unable to find a good BitcoinD connection");
            return;
        }
        using ConnList = QList<QMetaObject::Connection>;
        constexpr auto mkConnsPtr = [](const QString &n) {
            if constexpr (debugDeletes) {
                return std::shared_ptr<ConnList>(new ConnList, [n](ConnList * p){
                    Debug() << " list for " << n << " of size " << p->size() << " deleter";
                    delete p;
                });
            } else {
                return std::make_shared<ConnList>();
            }
        };
        auto conns = mkConnsPtr(context->objectName());
        static const auto killConns = [](decltype (conns) conns /* paranoia: pass by value just in case */) {
            for (const auto & conn : *conns) {
                QObject::disconnect(conn);
            }
            conns->clear();
        };
        *conns +=
        connect(bd, &BitcoinD::gotMessage, context.get(), [context, rid, conns](quint64, const RPC::Message &reply){
             if (reply.id == rid) {// filter out messages not for us
                emit context->results(reply);
                killConns(conns); // to kill lambdas, shared ptr captures
             }
        });
        *conns +=
        connect(bd, &BitcoinD::gotErrorMessage, context.get(), [context, rid, conns](quint64, const RPC::Message &errMsg){
             if (errMsg.id == rid) { // filter out error messages not for us
                 emit context->error(errMsg);
                 killConns(conns); // to kill lambdas, shared ptr captures
             }
        });
        *conns +=
        connect(bd, &BitcoinD::lostConnection, context.get(), [context, rid, conns](AbstractConnection *){
            emit context->fail(rid, "connection lost");
            killConns(conns); // to kill lambdas, shared ptr captures
        });
        *conns +=
        connect(bd, &QObject::destroyed, context.get(), [context, rid, conns](QObject *){
            emit context->fail(rid, "bitcoind client deleted");
            killConns(conns); // to kill lambdas, shared ptr captures
        });

        bd->sendRequest(rid, method, params);
    });

    // .. aand.. return right away
}

namespace BitcoinDMgrHelper {
    ReqCtxObj::~ReqCtxObj() {} /// weak vtable warning prevention
}

/* --- BitcoinD --- */
auto BitcoinD::stats() const -> Stats
{
    auto m = RPC::HttpConnection::stats().toMap();
    m["lastPeerError"] = badAuth ? "Auth Failure" : lastPeerError;
    m.remove("nErrorsSent"); // should always be 0
    m.remove("nNotificationsSent"); // again, 0
    m.remove("nResultsSent"); // again, 0
    return m;
}

BitcoinD::BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass, qint64 maxBuffer)
    : RPC::HttpConnection(RPC::MethodMap{}, newId(), nullptr, maxBuffer), host(host), port(port)
{
    static int N = 1;
    setObjectName(QString("BitcoinD.%1").arg(N++));
    _thread.setObjectName(objectName());

    setAuth(user, pass);
    setV1(true); // bitcoind uses jsonrpc v1
    pingtime_ms = 10000;
    stale_threshold = pingtime_ms * 2;

    connectMiscSignals();
}


BitcoinD::~BitcoinD()
{
    stop();
}

void BitcoinD::connectMiscSignals()
{
    connect(this, &BitcoinD::gotMessage, this, [this]{
        // this hook emits "authenticated" as soon as we get a good result message via 'do_ping' initiated from 'on_connected' below
        if (needAuth || badAuth) {
            needAuth = badAuth = false;
            emit authenticated(this);
        }
    });
}

bool BitcoinD::isGood() const
{
    return !badAuth && !needAuth && RPC::HttpConnection::isGood();
}

void BitcoinD::on_started()
{
    ThreadObjectMixin::on_started();

    { // setup the "reconnect timer"
        constexpr auto reconnectTimer = "reconnectTimer";
        const auto SetTimer = [this] {
            callOnTimerSoon(5000, reconnectTimer, [this]{
                if (!isGood()) {
                    Debug() << prettyName() << " reconnecting...";
                    reconnect();
                    return true; // keep the timer alive
                }
                return false; // kill timer
            });
        };
        conns += connect(this, &BitcoinD::lostConnection, this, [SetTimer]{
            Log() << "Lost connection to bitcoind, will retry every 5 seconds ...";
            SetTimer();
        });
        conns += connect(this, &BitcoinD::authFailure, this, [SetTimer, this] {
            Error() << "Authentication to bitcoind rpc failed. Please check the rpcuser and rpcpass are correct and restart!";
            badAuth = true;
            SetTimer();
        });
        conns += connect(this, &BitcoinD::authenticated, this, [this] { stopTimer(reconnectTimer); });

        SetTimer();
    }

    reconnect();
}

void BitcoinD::reconnect()
{
    if (socket) delete socket;
    socket = new QTcpSocket(this);
    socketConnectSignals();
    socket->connectToHost(host, port);
}

void BitcoinD::on_connected()
{
    RPC::HttpConnection::on_connected();
    lastGood = Util::getTime();
    nSent = nReceived = 0;
    lastPeerError.clear();
    lastSocketError.clear();
    badAuth = false;
    needAuth = true;
    emit connected(this);
    // note that the 'authenticated' signal is only emitted after good auth is confirmed via the reply from the do_ping below
    do_ping();
}

void BitcoinD::do_ping()
{
    if (isStale()) {
        Debug() << "Stale connection, reconnecting.";
        reconnect();
    } else
        emit sendRequest(newId(), "ping");
}
