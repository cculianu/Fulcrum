#ifndef ABSTRACTCLIENT_H
#define ABSTRACTCLIENT_H

#include <QObject>
#include <atomic>
#include "Common.h"
#include <QTcpSocket>

class QTimer;

class AbstractClient : public QObject
{
    Q_OBJECT
public:
    explicit AbstractClient(qint64 id, QObject *parent = nullptr);

    static const qint64 MAX_BUFFER; // 20MB

    const qint64 id;

    /// true if we are connected, have received a serverVersion, have received a height
    virtual bool isGood() const;
    /// true if we are connected but haven't received any response in some time
    virtual bool isStale() const;
    /// true if we got a malformed reply from the server
    virtual bool isBad() const { return status == Bad; }

signals:
    void lostConnection(AbstractClient *);
    /// call (emit) this to send data to the other end. connected to do_write(). This is a low-level function
    /// subclasses should create their own high-level protocol-level signals.
    void send(QByteArray);

public slots:

protected slots:

protected:

    enum Status {
        NotConnected = 0,
        Connecting,
        Connected,
        Bad
    };

    std::atomic<Status> status = NotConnected;
    std::atomic<qint64> lastGood = 0LL; ///< timestamp in ms from Util::getTime() when the server was last good (last communicated a sensible message, pinged, etc)

    std::atomic<qint64> nSent = 0ULL, nReceived = 0ULL;

    static const qint64 reconnectTime = 2*60*1000; /// retry every 2 mins

    static const int pingtime_ms = 60*1000;  /// send server.ping if idle for >1 min
    static const qint64 stale_threshold = reconnectTime;
    QTcpSocket *socket = nullptr; ///< this should only ever be touched in our thread
    QByteArray writeBackLog = ""; ///< if this grows beyond a certain size, we should kill the connection
    QTimer *pingTimer = nullptr;

    virtual QString prettyName(bool dontTouchSocket=false) const; ///< called only from our thread otherwise it may crash because it touches 'socket'

    virtual void do_ping(); /**< Reimplement in subclasses to send a ping. Default impl. does nothing. */

    virtual void on_connected(); ///< overrides should call this base implementation and chain to it

    void start_pingTimer();
    void kill_pingTimer();
    bool do_write(const QByteArray & = "");
protected slots:
    virtual void on_readyRead() = 0; /**< Implement in subclasses -- required to read data */
    void on_bytesWritten();
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
private slots:
    void on_pingTimer();
private:
    void boilerplate_disconnect();
};

#endif // ABSTRACTCLIENT_H
