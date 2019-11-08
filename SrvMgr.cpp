#include "SrvMgr.h"
#include "Util.h"
#include "TcpServer.h"

SrvMgr::SrvMgr(const QList<Options::Interface> & ifaces, QObject *parent)
    : Mgr(parent), interfaces(ifaces)
{

}

SrvMgr::~SrvMgr()
{
    Debug() << __FUNCTION__ ;
    cleanup();
}

// will throw Exception on error from within TcpServer::tryStart
void SrvMgr::startup()
{
    if (servers.isEmpty()) {
        startServers();
    } else {
        Error() << __PRETTY_FUNCTION__ << " called with servers already active! FIXME!";
    }
}

void SrvMgr::cleanup()
{
    for (auto srv : servers) {
        delete srv; // will wait for threads to finish
    }
    servers.clear();
}

// throw Exception on error
void SrvMgr::startServers()
{
    Log() << "SrvMgr: starting " << interfaces.length() << " service(s) ...";
    for (auto iface : interfaces) {
        auto srv = new Server(iface.first, iface.second);
        servers.push_back(srv); // save server in list unconditionally so we may delete later because tryStart may throw
        srv->tryStart();
        emit newServer(srv);
    }
}
