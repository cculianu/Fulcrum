//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
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
#include "Compat.h"
#include "Options.h"
#include "Util.h"
#include <QTcpSocket>
#include <QSslSocket>
#include <QHostAddress>
#include <QNetworkProxy>

#include <algorithm>
#include <cassert>

AbstractConnection::AbstractConnection(IdMixin::Id id_in, QObject *parent, qint64 maxBuffer_)
    : QObject(parent), IdMixin(id_in)
{
    assert(qobj()); // Runtime check that derived class followed the rules outlined at the top of Mixins.h
    setMaxBuffer(maxBuffer_);
}


/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString AbstractConnection::prettyName(bool dontTouchSocket, bool showId) const
{
    QString type = socket && !dontTouchSocket
                   ? (isSsl() ? (isWebSocket() ? QStringLiteral("WSS") : QStringLiteral("SSL"))
                              : (isWebSocket() ? QStringLiteral("WS")  : QStringLiteral("TCP")))
                   : QStringLiteral("(NoSocket)");
    QString port = socket && !dontTouchSocket && socket->peerPort() ? QStringLiteral(":%1").arg(socket->peerPort()) : QString();
    QString ip = socket && !dontTouchSocket && !socket->peerAddress().isNull() ? socket->peerAddress().toString() : QString();
    QString idStr = showId ? QStringLiteral(" (id: %1)").arg(id) : QString();
    return QStringLiteral("%1 %2%3 %4%5").arg(type).arg(!objectName().isNull()?objectName():QStringLiteral("(AbstractSocket)")).arg(idStr).arg(ip).arg(port);
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

bool AbstractConnection::isSsl() const
{
    bool ret{};
    if (thread() == QThread::currentThread() && socket) {
        ret = dynamic_cast<QSslSocket *>(socket) != nullptr;
    }
    return ret;
}

bool AbstractConnection::isWebSocket() const
{
    return false;
}

bool AbstractConnection::isUsingCustomProxy() const
{
    bool ret{};
    if (thread() == QThread::currentThread() && socket) {
        ret = socket->proxy().type() != QNetworkProxy::DefaultProxy;
    }
    return ret;
}
void AbstractConnection::setMaxBuffer(qint64 maxBytes)
{
    MAX_BUFFER = Options::clampMaxBufferSetting(int(maxBytes));
    if (socket && thread() == QThread::currentThread()) {
        socket->setReadBufferSize(MAX_BUFFER);
        DebugM(prettyName(), " set max_buffer to ", MAX_BUFFER, ", socket says: ", socket->readBufferSize());
    }
}

void AbstractConnection::do_disconnect(bool graceful)
{
    status = status == Bad ? Bad : NotConnected;  // try and keep Bad status around so PeerMgr can decide when to reconnect based on it? TODO: remove this concept from the codebase
    if (socket) {
        if (!graceful) {
            DebugM(__func__, " (abort) ", id);
            socket->abort();  // this will set status too because state change, but we set it first above to be paranoid
        } else {
            socket->disconnectFromHost();
            DebugM(__func__, " (graceful) ", id);
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
    connect(socket, Compat::SocketErrorSignalFunctionPtr<QTcpSocket>(), this, &AbstractConnection::on_error);
    connect(socket, &QTcpSocket::stateChanged, this, &AbstractConnection::on_socketState);
    if (QSslSocket *ssl = dynamic_cast<QSslSocket *>(socket); ssl)
        connect(ssl, &QSslSocket::encrypted, this, [this]{on_connected();});
    else
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
        Error() << __func__ << " (" << objectName() << ") " << err << " id=" << id;
        return false;
    }
    if (writeBackLog > MAX_BUFFER) {
        Warning(Log::Magenta) << __func__ << ": " << prettyName() << " -- MAX_BUFFER reached on write (" << MAX_BUFFER << "), disconnecting client";
        do_disconnect();
        return false;
    }
    // Note: we temorarily allow the writeBackLog to grow beyond MAX_BUFFER here.  If we run through this function
    // again in the future before bytes were actually written to the socket and we are over MAX_BUFFER, only then will
    // the above error be triggered.
    const auto n2write = data.length();
    writeBackLog += n2write;
    const qint64 written = socket->write(data);
    if (Q_UNLIKELY(written < 0)) {
        Error() << __func__ << ": " << prettyName() << " -- error on write " << socket->error() << " (" << socket->errorString() << ")";
        do_disconnect();
        return false;
    } else if (Q_UNLIKELY(written < n2write)) {
        // This branch should never happen since QTcpSocket uses an inifinite internal write buffer and always returns
        // mmediately with the full write request's `byteswritten` as a result.  We still keep this check around,
        // however, in case some day this predicate is violated by a Qt API change.
        //
        // See: https://code.woboq.org/qt5/qtbase/src/network/socket/qabstractsocket.cpp.html#_ZN15QAbstractSocket9writeDataEPKcx
        Error() << __func__ << ": " << prettyName() << " -- short write count; expected to write " << n2write
                << " bytes, but wrote " << written << " bytes instead. This should never happen! FIXME!";
        return false;
    }
    nSent += written;
    return true;
}

void AbstractConnection::slot_on_readyRead() { on_readyRead(); }

void AbstractConnection::on_connected()
{
    // runs in our thread's context
    DebugM(__func__, " ", id);
    connectedTS = Util::getTime();
    setSockOpts(socket); // ensure nagling disabled
    socket->setReadBufferSize(MAX_BUFFER); // ensure memory exhaustion from peer can't happen in case we're too busy to read.
    connectedConns.push_back(connect(this, &AbstractConnection::send, this, &AbstractConnection::do_write));
    connectedConns.push_back(connect(socket, &QTcpSocket::readyRead, this, &AbstractConnection::slot_on_readyRead));
    connectedConns.push_back(connect(socket, &QTcpSocket::bytesWritten, this, &AbstractConnection::on_bytesWritten));
    connectedConns.push_back(
        connect(socket, &QAbstractSocket::disconnected, this, [this]{
            DebugM(prettyName(), " socket disconnected");
            for (const auto & connection : connectedConns) {
                QObject::disconnect(connection);
            }
            connectedConns.clear(); // be sure to empty the list out when we are done!
            stopTimer(pingTimer); // kill the ping timer (method from TimersByNameMixin)
            on_disconnected();
            emit lostConnection(this);
        })
    );
    {  // set up the "pingTimer"
        auto on_pingTimer = [this]{
            if (Util::getTime() - lastGood > pingtime_ms)
                // only call do_ping if we've been idle for longer than pingtime_ms
                do_ping();
            return true;
        };
        const int period_ms = pingtime_ms/* default: 1 minute */ / 2;
        callOnTimerSoon(period_ms, pingTimer, on_pingTimer, true, Qt::TimerType::VeryCoarseTimer); // method inherited from TimersByNameMixin
    }
}

void AbstractConnection::on_disconnected()
{
    writeBackLog = 0;
    ++nDisconnects;
}

void AbstractConnection::on_socketState(QAbstractSocket::SocketState s)
{
    DebugM(prettyName(), " socket state: ",  int(s));
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

void AbstractConnection::on_bytesWritten(qint64 nBytes)
{
    TraceM(__func__);
    writeBackLog -= nBytes;
    if (writeBackLog > 0 && status == Connected && socket) {
        DebugM(prettyName(), " writeBackLog size: ", writeBackLog, " (wrote just now: ", nBytes, ")");
    }
}

void AbstractConnection::do_ping()
{
    DebugM(__func__, " ", prettyName(), " stub ...");
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
    m["writeBackLog"] = writeBackLog;
    m["readBytesAvailable"] = socket ? socket->bytesAvailable() : 0;
    m["activeTimers"] = activeTimerMapForStats();
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
    m["maxBuffer"] = MAX_BUFFER;
    m["isProxied"] = [this]() -> QVariant {
        if (socket)
            return QVariant(isUsingCustomProxy());
        return QVariant();
    }();
    m["isSsl"] = [this]() -> QVariant {
        if (socket)
            return QVariant(isSsl());
        return QVariant();
    }();
    return m;
}
