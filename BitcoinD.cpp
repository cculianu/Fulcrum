#include "BitcoinD.h"

BitcoinDMgr::BitcoinDMgr(const QHostAddress &host, quint16 port,
                         const QString &user, const QString &pass)
    : Mgr(nullptr), IdMixin(newId()), host(host), port(port), user(user), pass(pass)
{
    _thread.setObjectName("BitcoinDMgr");
    setObjectName("BitcoinDMgr");
}

BitcoinDMgr::~BitcoinDMgr() {  cleanup(); }

void BitcoinDMgr::startup() {
    Log() << objectName() << ": starting " << N_CLIENTS << " bitcoin rpc clients ...";

    start();

    Log() << objectName() << ": started ok";
}

void BitcoinDMgr::cleanup() {
    stop();
}

void BitcoinDMgr::on_started()
{
    ThreadObjectMixin::on_started();
    for (auto & client : clients) {
        client = std::make_unique<BitcoinD>(host, port, user, pass);
        client->start();
    }
}

void BitcoinDMgr::on_finished()
{
    ThreadObjectMixin::on_finished();
    for (auto & client : clients) {
        client.reset(); /// implicitly calls client->stop()
    }
}

QObject * BitcoinDMgr::qobj() { return this; }

auto BitcoinDMgr::stats() const -> Stats
{
    Stats ret;
    ret["Bitcoin Daemon"] = "** Stats Unimplemented -- TODO! **";
    return ret;
}


BitcoinD::BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass)
    : RPC::HttpConnection(RPC::MethodMap{}, newId(), nullptr), host(host), port(port)
{
    static int N = 1;
    setObjectName(QString("BitcoinD %1").arg(N++));
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
        conns += connect(this, &BitcoinD::authFailure, this, [SetTimer] {
            Error() << "Authentication to bitcoind rpc failed. Please check the rpcuser and rpcpass are correct and restart!";
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
