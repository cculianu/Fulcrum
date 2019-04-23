#ifndef ECMGR_H
#define ECMGR_H

#include <QObject>
#include <QList>
#include "EXClient.h"
class EXClient;

class EXMgr : public QObject
{
    Q_OBJECT
public:
    explicit EXMgr(const QString & serversFile, QObject *parent = nullptr);
    virtual ~EXMgr();
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
    QList<EXClient *> clients;
    QTimer *checkClientsTimer = nullptr;
};

#endif // ECMGR_H
