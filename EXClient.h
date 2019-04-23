#ifndef EXCLIENT_H
#define EXCLIENT_H

#include <QObject>
#include <QThread>
#include <QTcpSocket>
#include <QVariant>
#include <atomic>
#include <QTimer>
#include "Common.h"

class BadServerReply : public Exception {
public:
    BadServerReply(const QString &what) : Exception(what) {}
    ~BadServerReply();
};

struct EXResponse
{
    static EXResponse fromJson(const QString &json); ///< may throw Exception

    void validate(); ///< checks the QVariant is the expected format for each method. throws BadServerReply if it's not

    QString toString() const;

    QString jsonRpcVersion;
    int id;
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

    QString hostPrettyName() const;

    struct Info {
        QString serverVersion[2] = { "", "" };
        int height = 0;
        QString header;
    };

    Info info;

    /// true if we are connected, have received a serverVersion, have received a height
    bool isGood() const;
    /// true if we are connected but haven't received any response in some time
    bool isStale() const;
    /// true if we got a malformed reply from the server
    bool isBad() const { return status == Bad; }

signals:
    void gotResponse(EXResponse);
    void newConnection();
    void lostConnection();
    void sendRequest(const QString &method, const QVariantList & params = QVariantList());

public slots:

protected slots:
    int _sendRequest(const QString &method, const QVariantList & params = QVariantList());

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

    static const qint64 reconnectTime = 10*60*1000; /// retry every 10 mins

    QThread thread;

    void start();
    void stop();
    void restart() { stop(); start(); }

    QString host;
    quint16 tport = 0, sport = 0;

    std::atomic_int reqid = 0;
private:
    static const int pingtime_ms = 60*1000;  /// send server.ping every 1 min
    static const qint64 stale_threshold = 5*pingtime_ms;
    EXMgr *mgr = nullptr;
    QTcpSocket *socket = nullptr;
    QMap<int, QString> idMethodMap;
    QTimer *keepAliveTimer = nullptr;

    /// returns utf-8 encoded JSON data for a request
    static QByteArray makeRequestData(int id, const QString &method, const QVariantList & params = QVariantList());

    void on_started();
    void on_finished();
    void killSocket();
    void reconnect();
    void on_connected();
    void start_keepAlive();
    void kill_keepAlive();
private slots:
    void on_readyRead();
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
    void on_keepAlive();
};

#endif // EXCLIENT_H
