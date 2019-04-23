#ifndef EXCLIENT_H
#define EXCLIENT_H

#include <QObject>
#include <QThread>
#include <QTcpSocket>
#include <QVariant>
#include <atomic>
#include "Common.h"

class BadServerReply : public Exception {
public:
    BadServerReply(const QString &what) : Exception(what) {}
    ~BadServerReply();
};

struct EXResponse
{
    static EXResponse fromJson(const QString &json); ///< may throw Exception

    void chkValid() const; ///< checks the QVariant is the expected format for each method. throws BadServerReply if it's not

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

    int sendRequest(const QString &method, const QVariantList & params = QVariantList());

protected:
    friend class EXMgr;

    enum Status {
        NotConnected = 0,
        Connecting,
        Connected,
        Bad
    };

    Status status = NotConnected;
    qint64 lastGood = 0LL; // timestamp in ms from Util::getTime() when the server was last good (last communicated a sensible message, pinged, etc)

    QThread thread;

    void start();
    void stop();

    QString host;
    quint16 tport = 0, sport = 0;

    std::atomic_int reqid = 0;
signals:
    void gotResponse(EXResponse);
public slots:

private:
    EXMgr *mgr = nullptr;
    QTcpSocket *socket = nullptr;
    QMap<int, QString> idMethodMap;

    /// returns utf-8 encoded JSON data for a request
    static QByteArray makeRequestData(int id, const QString &method, const QVariantList & params = QVariantList());

    void on_started();
    void on_finished();
    void killSocket();
    void reconnect();
    void on_connected();
private slots:
    void on_readyRead();
    void on_error(QAbstractSocket::SocketError);
    void on_socketState(QAbstractSocket::SocketState);
};

#endif // EXCLIENT_H
