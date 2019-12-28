//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#include "AbstractConnection.h"
#include "Util.h"
#include <QTcpSocket>
#include <QSslSocket>
#include <QHostAddress>

#include <cassert>

AbstractConnection::AbstractConnection(quint64 id_in, QObject *parent, qint64 maxBuffer)
    : QObject(parent), IdMixin(id_in), MAX_BUFFER(maxBuffer)
{
    assert(qobj()); // Runtime check that derived class followed the rules outlined at the top of Mixins.h
}


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

// The below 4 will only return valid results if this->thread() == QThread::currentThread(), and if socket != nullptr
QHostAddress AbstractConnection::localAddress() const
{
    QHostAddress ret;
    if (thread() == QThread::currentThread() && socket) {
        ret = socket->localAddress();
    }
    return ret;
}
quint16 AbstractConnection::localPort() const
{
    quint16 ret{};
    if (thread() == QThread::currentThread() && socket) {
        ret = socket->localPort();
    }
    return ret;
}
QHostAddress AbstractConnection::peerAddress() const
{
    QHostAddress ret;
    if (thread() == QThread::currentThread() && socket) {
        ret = socket->peerAddress();
    }
    return ret;
}
quint16 AbstractConnection::peerPort() const
{
    quint16 ret{};
    if (thread() == QThread::currentThread() && socket) {
        ret = socket->peerPort();
    }
    return ret;
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

namespace {
void setSockOpts(QAbstractSocket *socket) {
    if (socket) {
        // don't we want to disable KeepAliveOption ?  it appears to eat some bandwidth .. 1 packet per second on Windows.
        //socket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);  // from Qt docs: required on Windows before connection
        socket->setSocketOption(QAbstractSocket::SocketOption::LowDelayOption, 1); // disable Nagling for lower latency
    }
}
}

void AbstractConnection::socketConnectSignals()
{
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
    connect(socket, &QAbstractSocket::connected, this, [this]{on_connected();});
    setSockOpts(socket);  // from Qt docs: required on Windows before connection
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

void AbstractConnection::slot_on_readyRead() { on_readyRead(); }

void AbstractConnection::on_connected()
{
    // runs in our thread's context
    Debug() << __FUNCTION__;
    connectedTS = Util::getTime();
    setSockOpts(socket); // ensure nagling disabled
    socket->setReadBufferSize(MAX_BUFFER); // ensure memory exhaustion from peer can't happen in case we're too busy to read.
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
            stopTimer(pingTimer); // kill the ping timer (method from TimersByNameMixin)
            on_disconnected();
            emit lostConnection(this);
            // todo: put stuff to queue up a reconnect sometime later?
        })
    );
    {  // set up the "pingTimer"
        auto on_pingTimer = [this]{
            if (Util::getTime() - lastGood > pingtime_ms)
                // only call do_ping if we've been idle for longer than pingtime_ms
                do_ping();
            return true;
        };
        const int period_ms = pingtime_ms/* 1 minute */ / 2;
        callOnTimerSoon(period_ms, pingTimer, on_pingTimer, true, Qt::TimerType::VeryCoarseTimer); // method inherited from TimersByNameMixin
    }
}

void AbstractConnection::on_disconnected()
{
    ++nDisconnects;
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
    Warning() << prettyName() << ": error " << err << " (" << (lastSocketError = (socket ? socket->errorString() : "(null)")) << ")";
    ++nSocketErrors;
    do_disconnect();
}

/// call this only from this object's thread
auto AbstractConnection::stats() const -> Stats
{
    QVariantMap m;
    m["name"] = objectName();
    m["id"] = id;
    m["connectedTime"] = isGood() ? QVariant(double(Util::getTime() - connectedTS)/1e3) : QVariant();
    m["nBytesSent"] = nSent.load();
    m["nBytesReceived"] = nReceived.load();
    m["idleTime"] = isGood() ? QVariant(double(Util::getTime() - lastGood)/1e3) : QVariant();
    m["lastSocketError"] = lastSocketError;
    m["nDisconnects"] = nDisconnects.load();
    m["nSocketErrors"] = nSocketErrors.load();
    m["writeBackLog"] = writeBackLog.size();
    m["readBytesAvailable"] = socket ? socket->bytesAvailable() : 0;
    auto atl = activeTimers();
    QVariantMap timerMap;
    for (const auto & name : atl)
        timerMap[name] = timerInterval(name);
    m["activeTimers"] = timerMap;
    m["remote"] = [this]() -> QVariant {
        if (QString addr; socket && !(addr=socket->peerAddress().toString()).isNull()) {
            return QString("%1:%2").arg(addr).arg(socket->peerPort());
        }
        return QVariant(); // null
    }();
    m["local"] = [this]() -> QVariant {
        if (QString addr; socket && !(addr=socket->localAddress().toString()).isNull()) {
            return QString("%1:%2").arg(addr).arg(socket->localPort());
        }
        return QVariant(); // null
    }();
    return m;
}
