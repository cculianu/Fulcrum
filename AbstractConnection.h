#ifndef ABSTRACTCONN_H
#define ABSTRACTCONN_H

#include "Common.h"
#include "Mixins.h"

#include <QObject>
#include <QTcpSocket>

#include <atomic>

class QTimer;

class AbstractConnection : public QObject, public IdMixin
{
    Q_OBJECT
public:
    static constexpr qint64 DEFAULT_MAX_BUFFER = 20000000; ///< 20MB, may change default in derived classes by setting maxBuffer in c'tor TODO: tune this.

    explicit AbstractConnection(quint64 id, QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);

    const qint64 MAX_BUFFER;

    /// true if we are connected
    virtual bool isGood() const;
    /// true if we are connected but haven't received any response in some time
    virtual bool isStale() const;
    /// true if we got a malformed reply from the server
    virtual bool isBad() const { return status == Bad; }

signals:
    void lostConnection(AbstractConnection *);
    /// call (emit) this to send data to the other end. connected to do_write() when socket is in the connected state.
    /// This is a low-level function subclasses should create their own high-level protocol-level signals / methods;
    void send(QByteArray);

protected:

    virtual void on_readyRead() = 0; /**< Implement in subclasses -- required to read data */

    enum Status {
        NotConnected = 0,
        Connecting,
        Connected,
        Bad
    };

    void socketConnectSignals(); ///< call this from derived classes to connect socket error and stateChanged to this

    std::atomic<Status> status = NotConnected;
    /// timestamp in ms from Util::getTime() when the server was last good
    /// (last communicated a sensible message, pinged, etc)
    std::atomic<qint64> connectedTS = 0LL, ///< timestamp in ms when this connection called on_connected()
                        lastGood = 0LL; ///< update this in derived classes. Represents the "last good" communication

    std::atomic<qint64> nSent = 0ULL, ///< this get updated in this class in do_write()
                        nReceived = 0ULL;  ///< update this in derived classes in your on_readyRead()

    static constexpr int default_pingtime_ms = 60*1000;  ///< this is the period of the pingTimer which calls do_ping() every minute.
    static constexpr qint64 default_stale_threshold = 2*60*1000; /// connection considered stale if no activity for 2 mins
    int pingtime_ms = default_pingtime_ms;
    qint64 stale_threshold = default_stale_threshold;
    QTcpSocket *socket = nullptr; ///< this should only ever be touched in our thread
    QByteArray writeBackLog = ""; ///< if this grows beyond a certain size, we should kill the connection
    QTimer *pingTimer = nullptr;
    QString lastSocketError; ///< the last socket error seen.
    QList<QMetaObject::Connection> connectedConns; /// signal/slot connections for the connected state. this gets populated when the socket connects in on_connected. signal connections will be disconnected on socket disconnect.

    virtual QString prettyName(bool dontTouchSocket=false) const; ///< called only from our thread otherwise it may crash because it touches 'socket'

    virtual void do_ping(); /**< Reimplement in subclasses to send a ping. Default impl. does nothing. */

    virtual void on_connected(); ///< overrides should call this base implementation and chain to it. It is required to chain as this method does important setup.
    virtual void on_disconnected(); ///< overrides can chain to this as well

    bool do_write(const QByteArray & = "");
    /// does a socket->abort, sets status. Chain to this if you want on override. Named this way so as not to clash with QObject::disconnect
    virtual void do_disconnect(bool graceful = false);

private slots:
    void on_pingTimer();
    void on_bytesWritten();
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
    void slot_on_readyRead(); ///< calls virtual method on_readyRead for us -- I was paranoid about Qt signal/slot binding semantics and prefer to call from within a function explicitly, hence this redundant method.
private:
    void start_pingTimer();
    void kill_pingTimer();
};

#endif // ABSTRACTCONN_H
