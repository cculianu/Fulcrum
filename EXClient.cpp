#include "EXClient.h"
#include "EXMgr.h"
#include "Util.h"
#include <QtNetwork>


EXClient::EXClient(EXMgr *mgr, qint64 id, const QString &host, quint16 tport, quint16 sport)
    : RPC::Connection(mgr->rpcMethods(), id, nullptr), host(host), tport(tport), sport(sport), mgr(mgr)
{
    Debug() << __FUNCTION__ << " host:" << host << " t:" << tport << " s:" << sport;
    _thread.setObjectName(QString("%1 %2").arg("EXClient").arg(host));
    setObjectName(host);
}

EXClient::~EXClient()
{
    Debug() << __FUNCTION__ << " " << objectName();
    stop(); ///< need to be sure to call this here rather than rely on ThreadObjectMixin, as by the time it runs, we lost our vtable
}

/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString EXClient::prettyName(bool dontTouchSocket) const
{
    if (_thread.isRunning() && QThread::currentThread() != &_thread) {
        Warning() << __PRETTY_FUNCTION__ << " called from another thread! FIXME!";
        dontTouchSocket = true;
    }
    return RPC::Connection::prettyName(dontTouchSocket);
}

bool EXClient::isGood() const
{
    return RPC::Connection::isGood() && _thread.isRunning() && info.isValid();
}


// runs in thread
void EXClient::on_started()
{
    Debug() << "started";
    reconnect();
}

// runs in thread
void EXClient::on_finished()
{
    killSocket();
    ThreadObjectMixin::on_finished(); // calls moveToThread
    Debug() << objectName() << " finished.";
}

void EXClient::killSocket()
{
    if (socket && socket->state() != QAbstractSocket::UnconnectedState) {
        Debug() << host << " aborting connection";
        do_disconnect();
    }
    delete socket; socket = nullptr;  // delete of nullptr ok
    status = NotConnected;
}

void EXClient::reconnect()
{
    killSocket();
    lastConnectionAttempt = Util::getTime();
    if (sport && QSslSocket::supportsSsl()) {
        QSslSocket *ssl;
        socket = ssl = new QSslSocket(this);
        auto conf = ssl->sslConfiguration();
        conf.setPeerVerifyMode(QSslSocket::VerifyNone);
        ssl->setSslConfiguration(conf);
        connect(ssl, &QSslSocket::encrypted, this, [this]{
            Debug() << prettyName() << " connected encrypted";
            on_connected();
        });
        socketConnectSignals();
        ssl->connectToHostEncrypted(host, static_cast<quint16>(sport));
    } else if (tport) {
        socket = new QTcpSocket(this);
        connect(socket, &QAbstractSocket::connected, this, [this]{
            Debug() << prettyName() << " connected";
            on_connected();
        });
        socketConnectSignals();
        socket->connectToHost(host, static_cast<quint16>(tport));
    } else {
        Error() << "Cannot connect to " << host << "; no TCP port defined and SSL is disabled on this install";
    }
}


void EXClient::do_ping()
{
    emit sendRequest(mgr->newId(), "server.ping");
}

void EXClient::on_connected()
{
    // runs in thread
    RPC::Connection::on_connected();
    connectedConns.push_back(
        connect(this, &RPC::Connection::gotMessage, this,
                [this](qint64 id_in, const RPC::Message &m)
            {
                 if (this->id == id_in)  emit EXClient::gotMessage(this, m); /// re-emits as EXClient * signal (different C++ signature)
                 else Error() << "id mismatch for gotMessage fwd! FIXME!";
            })
    ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
    connectedConns.push_back(
        connect(this, &RPC::Connection::gotErrorMessage, this,
                [this](qint64 id_in, const RPC::Message &m)
            {
                 if (this->id == id_in)  emit EXClient::gotErrorMessage(this, m); /// re-emits as EXClient * signal (different C++ signature)
                 else Error() << "id mismatch for gotErrorMessage fwd! FIXME!";
            })
    ); // connection will be auto-disconnected on socket disconnect in superclass  on_disconnected impl.
    emit newConnection(this);
}

void EXClient::on_disconnected()
{
    RPC::Connection::on_disconnected();
    emit lostConnection(this); /// re-emits as EXClient * signal (different method in C++)
}
