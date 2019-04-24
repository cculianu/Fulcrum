#ifndef EXCLIENT_H
#define EXCLIENT_H

#include <QObject>
#include <QThread>
#include <QTcpSocket>
#include <QVariant>
#include <atomic>
#include <QTimer>
#include <QPair>
#include "Common.h"


struct EXResponse
{
    static EXResponse fromJson(const QString &json); ///< may throw Exception

    void validate(); ///< checks the QVariant is the expected format for each method. throws BadServerReply if it's not

    QString toString() const;

    QString jsonRpcVersion;
    qint64 id;
    QString method;
    QVariant result;

    int errorCode = 0;
    QString errorMessage = "";
};

Q_DECLARE_METATYPE(EXResponse);

class EXMgr;

class EXClient : public QObject
{
    Q_OBJECT
public:
    explicit EXClient(EXMgr *mgr,
                      const QString & host,
                      quint16 tcpPort, quint16 sslPort);
    ~EXClient();

    struct Info {
        QPair<QString, QString> serverVersion = { "", "" };
        int height = 0;
        QString header;
        bool isValid() const { return !serverVersion.first.isEmpty() && !serverVersion.second.isEmpty() && height > 0; }
        void clear() { serverVersion = { "", ""}; height = 0; header = ""; }
    };

    Info info; ///< this is managed by the main thread

    /// true if we are connected, have received a serverVersion, have received a height
    bool isGood() const;
    /// true if we are connected but haven't received any response in some time
    bool isStale() const;
    /// true if we got a malformed reply from the server
    bool isBad() const { return status == Bad; }

signals:
    void gotResponse(EXClient *, EXResponse);
    void newConnection(EXClient *);
    void lostConnection(EXClient *);
    /// call (emit) this to send a requesst to the server
    void sendRequest(const QString &method, const QVariantList & params = QVariantList());

public slots:

protected slots:
    /// actual implentation that prepares the request. Is connected to sendRequest() above. Runs in thread.
    qint64 _sendRequest(const QString &method, const QVariantList & params = QVariantList());

protected:
    friend class EXMgr;

    enum Status {
        NotConnected = 0,
        Connecting,
        Connected,
        Bad
    };

    std::atomic<Status> status = NotConnected;
    std::atomic<qint64> lastGood = 0LL, ///< timestamp in ms from Util::getTime() when the server was last good (last communicated a sensible message, pinged, etc)
                        lastConnectionAttempt = 0LL;  ///< the last time we tried to reconnect

    std::atomic<qint64> nSent = 0ULL, nReceived = 0ULL;

    static const qint64 reconnectTime = 3*60*1000; /// retry every 3 mins

    QThread thread;

    void start(); ///< call from main thread
    void stop(); ///< call from main thread
    void restart() { stop(); start(); } ///< call from main thread

    QString host;
    quint16 tport = 0, sport = 0;

private:
    static const int pingtime_ms = 60*1000;  /// send server.ping every 1 min
    static const qint64 stale_threshold = reconnectTime;
    EXMgr *mgr = nullptr;
    QTcpSocket *socket = nullptr; ///< this should only ever be touched in our thread
    std::atomic<qint64> reqid = 0;
    QMap<qint64, QString> idMethodMap;
    QByteArray writeBackLog = ""; ///< if this grows beyond a certain size, we should kill the connection
    QTimer *pingTimer = nullptr;

    /// returns utf-8 encoded JSON data for a request
    static QByteArray makeRequestData(qint64 id, const QString &method, const QVariantList & params = QVariantList());

    QString hostPrettyName() const; ///< called only from our thread otherwise it may crash

    void on_started();
    void on_finished();
    void killSocket();
    void reconnect();
    void on_connected();
    void start_pingTimer();
    void kill_pingTimer();
    bool do_write(const QByteArray & = "");
    void boilerplate_disconnect();
private slots:
    void on_readyRead();
    void on_bytesWritten();
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
    void on_pingTimer();
};

#endif // EXCLIENT_H
