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
signals:
    // NB: assumption is Server instance lives for lifetime of this object. If this invariant changes,  please update this code.
    // This signal is emitted when a new server is created. The future "Controller" object may hook into this to attach its slots
    // to each server it sees.
    void newServer(Server *);

public slots:

private:
    void startServers();
    QList<Options::Interface> interfaces;
    QList<Server *> servers;
};

#endif // SRVMGR_H
