#ifndef SRVMGR_H
#define SRVMGR_H

#include "Mgr.h"
#include "Options.h"
#include <QList>

class Server;

class SrvMgr : public Mgr
{
    Q_OBJECT
public:
    explicit SrvMgr(const QList<Options::Interface> &interfaces, QObject *parent = nullptr);
    ~SrvMgr() override;
    void startup() override; // may throw on error
    void cleanup() override;

    int nServers() const { return servers.size(); }

public slots:

protected:
    Stats stats() const override;

private:
    void startServers();
    QList<Options::Interface> interfaces;
    QList<Server *> servers;
};

#endif // SRVMGR_H
