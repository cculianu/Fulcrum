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
#pragma once

#include "Common.h"
#include "Mixins.h"

#include <QVariantMap>
#include <QObject>
#include <QTcpSocket>

#include <atomic>

class QTimer;

class AbstractConnection : public QObject, public IdMixin, public TimersByNameMixin, public StatsMixin
{
    Q_OBJECT
public:
    static constexpr qint64 DEFAULT_MAX_BUFFER = 64*1024*1024; ///< 64MB, may change default in derived classes by setting maxBuffer in c'tor TODO: tune this.

    explicit AbstractConnection(IdMixin::Id id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);

    /// true if we are connected
    virtual bool isGood() const;
    /// true if we are connected but haven't received any response in some time
    virtual bool isStale() const;
    /// true if we got a malformed reply from the server
    inline bool isBad() const { return status == Bad; }

    // The below 6 can only be called from the same thread that this instance lives in.
    // They will only return valid results if this->thread() == QThread::currentThread(), and if socket != nullptr.
    // Otherwise, default-constructed values are returned.
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    quint16 peerPort() const;
    /// Returns true if this->socket and this->socket->proxy() is not DefaultProxy. Call this from this->thread().
    bool isUsingCustomProxy() const;
    /// Returns the current maxBuffer setting
    qint64 maxBuffer() const { return MAX_BUFFER; }
    /// Attempts to set the new max buffer. Can only be called from this object's thread. Clamps the specified value
    /// to [Options::maxBufferMin, Options::maxBufferMax].
    void setMaxBuffer(qint64 maxBytes);

    /// Returns true if the connection is via SSL. The default implementation of this function attempts to dynamic_cast
    /// `socket` to QSslSocket, and if it succeeds, assumes the connection is SSL and returns true.  False is returned
    /// if the dynamic_cast fails.  This will always return false if called from a thread other than the one in which
    /// this instance lives.
    virtual bool isSsl() const;
    /// Default implementation returns false.  If the connection is an ElectrumConnection (derived class), it may
    /// return true if it is being handled via the WebSocket::Wrapper class.
    virtual bool isWebSocket() const;

signals:
    void lostConnection(AbstractConnection *);
    /// call (emit) this to send data to the other end. connected to do_write() when socket is in the connected state.
    /// This is a low-level function subclasses should create their own high-level protocol-level signals / methods;
    void send(QByteArray);

protected:
    /// this should be called only from this object's thread. Outside code should use statsSafe() (inherited from StatsMixin)
    Stats stats() const override; // (override from StatsMixin)

    virtual void on_readyRead() = 0; /**< Implement in subclasses -- required to read data */

    enum Status {
        NotConnected = 0,
        Connecting,
        Connected,
        Bad
    };

    void socketConnectSignals(); ///< call this from derived classes to connect socket error and stateChanged to this

    qint64 MAX_BUFFER; // only read this from this thread.

    std::atomic<Status> status = NotConnected;
    /// timestamp in ms from Util::getTime() when the server was last good
    /// (last communicated a sensible message, pinged, etc)
    std::atomic<qint64> connectedTS = 0LL, ///< timestamp in ms when this connection called on_connected()
                        lastGood = 0LL; ///< update this in derived classes. Represents the "last good" communication

    std::atomic<qint64> nSent = 0ULL, ///< this get updated in this class in do_write()
                        nReceived = 0ULL;  ///< update this in derived classes in your on_readyRead()

    std::atomic<int> nDisconnects = 0, nSocketErrors = 0;

    static constexpr int default_pingtime_ms = 60*1000;  ///< this is the period of the pingTimer which calls do_ping() every minute.
    static constexpr qint64 default_stale_threshold = 2*60*1000; /// connection considered stale if no activity for 2 mins
    int pingtime_ms = default_pingtime_ms;
    qint64 stale_threshold = default_stale_threshold;
    QTcpSocket *socket = nullptr; ///< this should only ever be touched in our thread (also: socket should live in same thread as this instance)
    qint64 writeBackLog = 0; ///< if this grows beyond a certain size, we should kill the connection
    QString lastSocketError; ///< the last socket error seen.
    QList<QMetaObject::Connection> connectedConns; /// signal/slot connections for the connected state. this gets populated when the socket connects in on_connected. signal connections will be disconnected on socket disconnect.

    virtual QString prettyName(bool dontTouchSocket=false, bool showId=true) const; ///< called only from our thread otherwise it may crash because it touches 'socket'

    virtual void do_ping(); /**< Reimplement in subclasses to send a ping. Default impl. does nothing. */

    virtual void on_connected(); ///< overrides should call this base implementation and chain to it. It is required to chain as this method does important setup.
    virtual void on_disconnected(); ///< overrides can chain to this as well

    bool do_write(const QByteArray & = "");
    /// does a socket->abort, sets status. Chain to this if you want on override. Named this way so as not to clash with QObject::disconnect
    virtual void do_disconnect(bool graceful = false);

    static constexpr auto pingTimer = "+Ping Timer";  ///< this is the internal pingTimer which calls do_ping() periodically.

private slots:
    void on_bytesWritten(qint64);
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
    void slot_on_readyRead(); ///< calls virtual method on_readyRead for us -- I was paranoid about Qt signal/slot binding semantics and prefer to call from within a function explicitly, hence this redundant method.
};
