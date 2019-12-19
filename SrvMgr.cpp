#include "SrvMgr.h"

#include "BitcoinD.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <utility>

SrvMgr::SrvMgr(const QList<Options::Interface> & ifaces, std::shared_ptr<Storage> s, std::shared_ptr<BitcoinDMgr> bdm,
               QObject *parent)
    : Mgr(parent), interfaces(ifaces), storage(std::move(s)), bitcoindmgr(std::move(bdm))
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
    const auto num = interfaces.length();
    Log() << "SrvMgr: starting " << num << " " << Util::Pluralize("service", num) << " ...";
    for (auto iface : interfaces) {
        auto srv = new Server(iface.first, iface.second, storage, bitcoindmgr);
        servers.push_back(srv); // save server in list unconditionally so we may delete later because tryStart may throw
        srv->tryStart();

        // connet blockchain.headers.subscribe signal
        connect(this, &SrvMgr::newHeader, srv, &Server::newHeader);
    }
}

auto SrvMgr::stats() const -> Stats
{
    QVariantList serverList;
    auto servers = this->servers; // copy
    const int timeout = kDefaultTimeout / qMax(servers.size(), 1);
    for (auto server : servers) {
        using Pair = std::pair<QString, QVariant>;
        auto result = Util::LambdaOnObjectNoThrow<Pair>(server, [server] {
            return Pair(server->prettyName(), server->stats());
        }, timeout); // <-- limited timeout just in case
        if (result) {
            QVariantMap m;
            m[result->first] = result->second;
            serverList.push_back(m);
        }
    }
    return serverList;
}
