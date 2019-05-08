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
#include "AbstractConnection.h"
#include "Mixins.h"
#include "RPC.h"

class EXMgr;

class EXClient : public RPC::Connection, protected ThreadObjectMixin
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

    Info info; ///< this is managed by the EXMgr thread (which is currently the main thread)

    /// true if we are connected, have received a serverVersion, have received a height
    bool isGood() const override;

signals:
    void newConnection(EXClient *);
    void lostConnection(EXClient *); ///< overrides lostConnection(AbstractConnection *) by dynamic_casting it down and re-emitting
    void gotMessage(EXClient *, const RPC::Message &); ///< overrides gotMessage(id,..) by re-emitting with ptr type (this is safe here becase EXClients live for lifetime of app)
    void gotErrorMessage(EXClient *, const RPC::Message &); ///< overrides gotErrorMessage(id,..) by re-emitting with ptr type

protected:
    friend class EXMgr;

    std::atomic<qint64> lastConnectionAttempt = 0LL;  ///< the last time we tried to reconnect

    QString host;
    quint16 tport = 0, sport = 0;

    QString prettyName(bool dontTouchSocket = false) const override;
    void do_ping() override;
    void on_connected() override;
    void on_disconnected() override;

private:
    EXMgr *mgr = nullptr;

    void on_started() override;
    void on_finished() override;
    QObject *qobj() override { return this; }
    void killSocket();
    void reconnect();
};

#endif // EXCLIENT_H
