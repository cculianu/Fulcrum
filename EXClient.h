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
#include "AbstractClient.h"
#include "ThreadObjectMixin.h"

struct EXResponse
{
    static EXResponse fromJson(const QString &json); ///< may throw Exception

    void validate(); ///< checks the QVariant is the expected format for each method. throws BadServerReply if it's not

    QString toString() const;

    QString jsonRpcVersion;
    qint64 id;
    QString method;
    QVariant result; // 'params' also gets put here

    int errorCode = 0;
    QString errorMessage = "";
};

Q_DECLARE_METATYPE(EXResponse);

class EXMgr;

class EXClient : public AbstractClient, protected ThreadObjectMixin
{
    Q_OBJECT
public:
    explicit EXClient(EXMgr *mgr,  qint64 id,
                      const QString & host,
                      quint16 tcpPort, quint16 sslPort);
    ~EXClient() override;

    struct Info {
        QPair<QString, QString> serverVersion = { "", "" };
        int height = 0;
        QString header;
        bool isValid() const { return !serverVersion.first.isEmpty() && !serverVersion.second.isEmpty() && height > 0; }
        void clear() { serverVersion = { "", ""}; height = 0; header = ""; }
    };

    Info info; ///< this is managed by the main thread

    /// true if we are connected, have received a serverVersion, have received a height
    bool isGood() const override;

signals:
    void gotResponse(EXClient *, EXResponse);
    void newConnection(EXClient *);
    void lostConnection(EXClient *); ///< overrides lostConnection(AbstractClient *) by dynamic_casting it down and re-emitting
    /// call (emit) this to send a requesst to the server
    void sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());

protected slots:
    /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in thread.
    bool _sendRequest(qint64 reqid, const QString &method, const QVariantList & params = QVariantList());

    /// called from socket connection
    void on_readyRead() override;
protected:
    friend class EXMgr;

    std::atomic<qint64> lastConnectionAttempt = 0LL;  ///< the last time we tried to reconnect

    void start() override; ///< call from main thread
    void stop() override; ///< call from main thread

    QString host;
    quint16 tport = 0, sport = 0;

    QString prettyName(bool dontTouchSocket = false) const override;
    void do_ping() override;
    void on_connected() override;

private:
    EXMgr *mgr = nullptr;
    QMap<qint64, QString> idMethodMap;

    /// returns utf-8 encoded JSON data for a request
    static QByteArray makeRequestData(qint64 id, const QString &method, const QVariantList & params = QVariantList());

    void on_started() override;
    void on_finished() override;
    QObject *qobj() override { return this; }
    void killSocket();
    void reconnect();
};

#endif // EXCLIENT_H
