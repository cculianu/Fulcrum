#include "AbstractClient.h"
#include "Util.h"
#include <QTcpSocket>
#include <QSslSocket>
#include <QHostAddress>


AbstractClient::AbstractClient(qint64 id, QObject *parent)
    : QObject(parent), IdMixin(id)
{}


/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString AbstractClient::prettyName(bool dontTouchSocket) const
{
    QString type = socket && !dontTouchSocket ? (dynamic_cast<QSslSocket *>(socket) ? "SSL" : "TCP") : "(NoSocket)";
    QString port = socket && !dontTouchSocket && socket->peerPort() ? QString(":%1").arg(socket->peerPort()) : "";
    QString ip = socket && !dontTouchSocket && !socket->peerAddress().isNull() ? socket->peerAddress().toString() : "";
    return QString("%1 %2 (id: %3) %4%5").arg(type).arg(!objectName().isNull()?objectName():"(AbstractSocket)").arg(id).arg(ip).arg(port);
}


bool AbstractClient::isGood() const
{
    return status == Connected;
}

bool AbstractClient::isStale() const
{
    return isGood() && Util::getTime() - lastGood > stale_threshold;
}

void AbstractClient::boilerplate_disconnect()
{
    status = status == Bad ? Bad : NotConnected;  // try and keep Bad status around so EXMgr can decide when to reconnect based on it
    if (socket) socket->abort();  // this will set status too because state change, but we set it first above to be paranoid
}

void AbstractClient::socketConnectSignals()
{
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
    socket->setSocketOption(QAbstractSocket::KeepAliveOption, true);  // from Qt docs: required on Windows
}

bool AbstractClient::do_write(const QByteArray & data)
{
    QString err = "";
    if (!socket) {
        err = " called with no socket! FIXME!";
    } else if (QThread::currentThread() != thread()) {
        err = " called from another thread! FIXME!";
    }
    if (!err.isEmpty()) {
        Error() << __FUNCTION__ << " (" << objectName() << ") " << err << " id=" << id;
        return false;
    }
    auto data2write = writeBackLog + data;
    qint64 written = socket->write(data2write);
    if (written < 0) {
        Error() << __FUNCTION__ << " error on write " << socket->error() << " (" << socket->errorString() << ") id=" << id;
        boilerplate_disconnect();
        return false;
    } else if (written < data2write.length()) {
        writeBackLog = data2write.mid(int(written));
    }
    nSent += written;
    if (writeBackLog.length() > MAX_BUFFER) {
        Error() << __FUNCTION__ << " MAX_BUFFER reached on write (" << MAX_BUFFER << ") id=" << id;
        boilerplate_disconnect();
        return false;
    }
    return true;
}

void AbstractClient::kill_pingTimer()
{
    if (pingTimer) { delete pingTimer; pingTimer = nullptr; }
}

void AbstractClient::start_pingTimer()
{
    kill_pingTimer();
    pingTimer = new QTimer(this);
    pingTimer->setSingleShot(false);
    connect(pingTimer, SIGNAL(timeout()), this, SLOT(on_pingTimer()));
    pingTimer->start(pingtime_ms/* 1 minute */ / 2);
}

void AbstractClient::on_pingTimer()
{
    if (Util::getTime() - lastGood > pingtime_ms)
        // only ping if we've been idle for longer than 1 minute
        do_ping();
}

void AbstractClient::on_connected()
{
    // runs in our thread's context
    Debug() << __FUNCTION__;
    connect(this, &AbstractClient::send, this, &AbstractClient::do_write);
    connect(socket, SIGNAL(readyRead()), this, SLOT(on_readyRead()));
    if (dynamic_cast<QSslSocket *>(socket)) {
        // for some reason Qt can't find this old-style signal for QSslSocket so we do the below.
        // Additionally, bytesWritten is never emitted for QSslSocket, violating OOP! Thanks Qt. :P
        connect(socket, SIGNAL(encryptedBytesWritten(qint64)), this, SLOT(on_bytesWritten()));
    } else {
        connect(socket, SIGNAL(bytesWritten(qint64)), this, SLOT(on_bytesWritten()));
    }
    connect(socket, &QAbstractSocket::disconnected, this, [this]{
        Debug() << prettyName() << " socket disconnected";
        disconnect(this, &AbstractClient::send, this, &AbstractClient::do_write);
        kill_pingTimer();
        emit lostConnection(this);
        // todo: put stuff to queue up a reconnect sometime later?
    });
    start_pingTimer();
}

void AbstractClient::on_socketState(QAbstractSocket::SocketState s)
{
    Debug() << prettyName() << " socket state: " << s;
    switch (s) {
    case QAbstractSocket::ConnectedState:
        status = Connected;
        break;
    case QAbstractSocket::HostLookupState:
    case QAbstractSocket::ConnectingState:
        status = Connecting;
        break;
    case QAbstractSocket::UnconnectedState:
    case QAbstractSocket::ClosingState:
    default:
        status = NotConnected;
        break;
    }
}

void AbstractClient::on_bytesWritten()
{
    Debug() << __FUNCTION__;
    if (!writeBackLog.isEmpty() && status == Connected && socket) {
        Debug() << prettyName() << " writeBackLog size: " << writeBackLog.length();
        do_write();
    }
}

void AbstractClient::do_ping()
{
    Debug() << __FUNCTION__ << " stub ...";
}

void AbstractClient::on_error(QAbstractSocket::SocketError err)
{
    Warning() << prettyName() << ": error " << err << " (" << (socket ? socket->errorString() : "(null)") << ")";
    boilerplate_disconnect();
}

