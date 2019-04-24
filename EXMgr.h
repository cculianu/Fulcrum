#ifndef ECMGR_H
#define ECMGR_H

#include "EXClient.h"
#include <QObject>
#include <QList>
#include <atomic>
class EXClient;

class EXMgr : public QObject
{
    Q_OBJECT
public:
    explicit EXMgr(const QString & serversFile, QObject *parent = nullptr);
    virtual ~EXMgr();

    qint64 newReqId() { return ++reqid; }

signals:

public slots:

protected slots:
    void onNewConnection(EXClient *);
    void onLostConnection(EXClient *);
    void onResponse(EXClient *, EXResponse);

private slots:
    void checkClients();

private:
    const QString serversFile;
    void loadServers();
    std::atomic<qint64> reqid = 0;

    QList<EXClient *> clients;
    QTimer *checkClientsTimer = nullptr;
};

#endif // ECMGR_H
