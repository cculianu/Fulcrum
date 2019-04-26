#ifndef SRVMGR_H
#define SRVMGR_H

#include "Controller.h"
#include "Options.h"
#include <QList>

class TcpServer;

class SrvMgr : public Controller
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
