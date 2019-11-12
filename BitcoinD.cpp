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
    Debug() << "BitcoinDMgr cleaned up";
}

QObject *BitcoinDMgr::qobj() { return this; }

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
    for (const auto & client : clients) {
        if (!client) continue;
        l += Util::LambdaOnObjectNoThrow<QVariantMap>(client.get(), [c=client.get()]{ return c->getStats(); }, 250).value_or(QVariantMap());
    }
    ret["Bitcoin Daemon"] = l;
    return ret;
}

QVariantMap BitcoinD::getStats() const
{
    QVariantMap m;
    m["connectedTime"] = isGood() ? QVariant(double(Util::getTime() - connectedTS)/1e3) : QVariant();
    m["nBytesSent"] = nSent.load();
    m["nBytesReceived"] = nReceived.load();
    m["host:port"] = QString("%1:%2").arg(host.toString()).arg(port);
    m["idleTime"] = isGood() ? QVariant(double(Util::getTime() - lastGood)/1e3) : QVariant();
    m["lastPeerError"] = badAuth ? "Auth Failure" : lastPeerError;
    m["lastSocketError"] = lastSocketError;
    m["nDisconnects"] = nDisconnects.load();
    m["nSocketErrors"] = nSocketErrors.load();
    return QVariantMap{ {objectName(), m} };
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
}


BitcoinD::~BitcoinD()
{
    stop();
}

QObject * BitcoinD::qobj() { return this; }

void BitcoinD::on_started()
{
    ThreadObjectMixin::on_started();

    { // setup the "reconnect timer"
        const auto SetTimer = [this] {
            callOnTimerSoon(5000, "reconnectTimer", [this]{
                if (!isGood()) {
                    Debug() << prettyName() << " reconnecting...";
                    reconnect();
                    return true;
                }
                return false;
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
        conns += connect(this, &BitcoinD::connected, this, [this] { stopTimer("reconnectTimer"); });
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
    emit connected(this);
    do_ping();
}

void BitcoinD::do_ping()
{
    if (isStale()) {
        Debug() << "Stale connection, reconnecting.";
        reconnect();
    } else
        emit sendRequest(newId(), "getblockcount");
}
