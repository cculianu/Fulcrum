#ifndef SRVMGR_H
#define SRVMGR_H

#include "Mgr.h"
#include "Options.h"
#include <QList>

class TcpServer;

class SrvMgr : public Mgr
{
    Q_OBJECT
public:
    explicit SrvMgr(const QList<Options::Interface> &interfaces, QObject *parent = nullptr);
    ~SrvMgr() override;
    void startup() override; // may throw on error
    void cleanup() override;
signals:

public slots:

private:
    void startServers();
    QList<Options::Interface> interfaces;
    QList<TcpServer *> servers;
};

#endif // SRVMGR_H
