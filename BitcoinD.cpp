#include <QPointer>

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
    Log() << objectName() << ": starting " << N_CLIENTS << " bitcoin rpc clients ...";

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
    Debug() << "Msg from: " << bid << " method=" << msg.method;
}
void BitcoinDMgr::on_ErrorMessage(quint64 bid, const RPC::Message &msg)
{
    Debug() << "ErrMsg from: " << bid << " error=" << msg.errorMessage();
}


auto BitcoinDMgr::stats() const -> Stats
{
    Stats ret;
    QVariantList l;
    constexpr int timeout = kDefaultTimeout/qMax(N_CLIENTS,1);
    for (const auto & client : clients) {
        if (!client) continue;
        auto map = client->statsSafe(timeout);
        auto name = map.take("name").toString();
        l += QVariantMap({{ name, map }});
    }
    ret["Bitcoin Daemon"] = l;
    return ret;
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
    QPointer<QObject> context(new QObject(sender)); // this is a weak ref that gets killed when sender is killed. This way stuff just "goes away" if sender dies.
    context->setObjectName(QString("context for '%1' request id: %2").arg(sender ? sender->objectName() : "").arg(rid.toString()));
    auto killContext = [context, this] {
        if (LIKELY(context)) { // need to check context because race conditions
            Util::VoidFuncOnObjectNoThrow(this, [context, this] { if (LIKELY(context)) disconnect(this, &QObject::destroyed, context, nullptr);  }, 0);
            Util::VoidFuncOnObjectNoThrow(context, [context] { if (LIKELY(context)) context->deleteLater(); }, 0);
        }
    };
    connect(this, &QObject::destroyed, context, killContext);  // make sure that if we die, to kill the context too to clean up resources.

    // schedule this ASAP
    QTimer::singleShot(0, this, [this, context, resf, errf, failf, rid, method, params, killContext] {
        if (UNLIKELY(!context))
            // sender parent must have been deleted before we got a chance to run
            return;
        auto replied = std::make_shared<std::atomic_bool>(false); // guards against spurious lostConnection arriving after reply msg
        // this is called from either context thread or this thread
        auto do_fail = [failf, context, killContext, rid, replied](const QString & reason){
            if (LIKELY(!replied->exchange(true) && failf && context)) {
                Util::VoidFuncOnObjectNoThrow(context, [context, failf, rid, reason]{
                    if (LIKELY(context)) // need to check context again because race conditions
                        failf(rid, reason);
                }); // fixme: this has an infinite timeout
            }
            killContext();
        };
        auto bd = getBitcoinD();
        if (UNLIKELY(!bd)) {
            do_fail("Unable to find a good BitcoinD connection");
            return;
        }
        connect(bd, &BitcoinD::gotMessage, context, [resf, replied, rid, killContext](quint64, const RPC::Message &reply){
             if (reply.id == rid) {// filter out messages not for us
                 if (!replied->exchange(true) && resf)
                     resf(reply);
                 killContext();
             }
        });
        connect(bd, &BitcoinD::gotErrorMessage, context, [errf, replied, rid, killContext](quint64, const RPC::Message &errMsg){
             if (errMsg.id == rid) { // filter out error messages not for us
                 if (!replied->exchange(true) && errf)
                     errf(errMsg);
                 killContext();
             }
        });
        connect(bd, &BitcoinD::lostConnection, context, [do_fail, rid](AbstractConnection *){
            do_fail("connection lost");
        });

        bd->sendRequest(rid, method, params);
    });

    // .. aand.. return right away
}

/* --- BitcoinD --- */
auto BitcoinD::stats() const -> Stats
{
    Stats m = RPC::HttpConnection::stats();
    m["lastPeerError"] = badAuth ? "Auth Failure" : lastPeerError;
    m.remove("nErrorsSent"); // should always be 0
    m.remove("nNotificationsSent"); // again, 0
    m.remove("nResultsSent"); // again, 0
    return m;
}

BitcoinD::BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass)
    : RPC::HttpConnection(RPC::MethodMap{}, newId(), nullptr), host(host), port(port)
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
