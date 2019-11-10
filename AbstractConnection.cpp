#include "AbstractConnection.h"
#include "Util.h"
#include <QTcpSocket>
#include <QSslSocket>
#include <QHostAddress>


AbstractConnection::AbstractConnection(qint64 id, QObject *parent, qint64 maxBuffer)
    : QObject(parent), IdMixin(id), MAX_BUFFER(maxBuffer)
{}


/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString AbstractConnection::prettyName(bool dontTouchSocket) const
{
    QString type = socket && !dontTouchSocket ? (dynamic_cast<QSslSocket *>(socket) ? "SSL" : "TCP") : "(NoSocket)";
    QString port = socket && !dontTouchSocket && socket->peerPort() ? QString(":%1").arg(socket->peerPort()) : "";
    QString ip = socket && !dontTouchSocket && !socket->peerAddress().isNull() ? socket->peerAddress().toString() : "";
    return QString("%1 %2 (id: %3) %4%5").arg(type).arg(!objectName().isNull()?objectName():"(AbstractSocket)").arg(id).arg(ip).arg(port);
}


bool AbstractConnection::isGood() const
{
    return status == Connected;
}

bool AbstractConnection::isStale() const
{
    return isGood() && Util::getTime() - lastGood > stale_threshold;
}

void AbstractConnection::do_disconnect(bool graceful)
{
    status = status == Bad ? Bad : NotConnected;  // try and keep Bad status around so EXMgr can decide when to reconnect based on it
    if (socket) {
        if (!graceful) {
            Debug() << __FUNCTION__ << " (abort)";
            socket->abort();  // this will set status too because state change, but we set it first above to be paranoid
        } else {
            socket->disconnectFromHost();
            Debug() << __FUNCTION__ << " (graceful)";
        }
    }
}

void AbstractConnection::socketConnectSignals()
{
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
    socket->setSocketOption(QAbstractSocket::KeepAliveOption, true);  // from Qt docs: required on Windows
}

bool AbstractConnection::do_write(const QByteArray & data)
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
        do_disconnect();
        return false;
    } else if (written < data2write.length()) {
        writeBackLog = data2write.mid(int(written));
    }
    nSent += written;
    if (writeBackLog.length() > MAX_BUFFER) {
        Error() << __FUNCTION__ << " MAX_BUFFER reached on write (" << MAX_BUFFER << ") id=" << id;
        do_disconnect();
        return false;
    }
    return true;
}

void AbstractConnection::kill_pingTimer()
{
    delete pingTimer; pingTimer = nullptr; // delete of nullptr always ok
}

void AbstractConnection::start_pingTimer()
{
    kill_pingTimer();
    pingTimer = new QTimer(this);
    pingTimer->setSingleShot(false);
    connect(pingTimer, SIGNAL(timeout()), this, SLOT(on_pingTimer()));
    pingTimer->start(pingtime_ms/* 1 minute */ / 2);
}

void AbstractConnection::on_pingTimer()
{
    if (Util::getTime() - lastGood > pingtime_ms)
        // only call do_ping if we've been idle for longer than 1 minute
        do_ping();
}

void AbstractConnection::slot_on_readyRead() { on_readyRead(); }

void AbstractConnection::on_connected()
{
    // runs in our thread's context
    Debug() << __FUNCTION__;
    connectedConns.push_back(connect(this, &AbstractConnection::send, this, &AbstractConnection::do_write));
    connectedConns.push_back(connect(socket, SIGNAL(readyRead()), this, SLOT(slot_on_readyRead())));
    if (dynamic_cast<QSslSocket *>(socket)) {
        // for some reason Qt can't find this old-style signal for QSslSocket so we do the below.
        // Additionally, bytesWritten is never emitted for QSslSocket, violating OOP! Thanks Qt. :P
        connectedConns.push_back(connect(socket, SIGNAL(encryptedBytesWritten(qint64)), this, SLOT(on_bytesWritten())));
    } else {
        connectedConns.push_back(connect(socket, SIGNAL(bytesWritten(qint64)), this, SLOT(on_bytesWritten())));
    }
    connectedConns.push_back(
        connect(socket, &QAbstractSocket::disconnected, this, [this]{
            Debug() << prettyName() << " socket disconnected";
            for (const auto & connection : connectedConns) {
                QObject::disconnect(connection);
            }
            connectedConns.clear(); // be sure to empty the list out when we are done!
            kill_pingTimer();
            on_disconnected();
            emit lostConnection(this);
            // todo: put stuff to queue up a reconnect sometime later?
        })
    );
    start_pingTimer();
}

void AbstractConnection::on_disconnected()
{
    /* nothing, here; for derived classes to override if they wish. */
}

void AbstractConnection::on_socketState(QAbstractSocket::SocketState s)
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

void AbstractConnection::on_bytesWritten()
{
    Trace() << __FUNCTION__;
    if (!writeBackLog.isEmpty() && status == Connected && socket) {
        Debug() << prettyName() << " writeBackLog size: " << writeBackLog.length();
        do_write();
    }
}

void AbstractConnection::do_ping()
{
    Debug() << __FUNCTION__ << " " << prettyName() << " stub ...";
}

void AbstractConnection::on_error(QAbstractSocket::SocketError err)
{
    Warning() << prettyName() << ": error " << err << " (" << (socket ? socket->errorString() : "(null)") << ")";
    do_disconnect();
}

