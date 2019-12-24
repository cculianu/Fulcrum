#include "SrvMgr.h"

#include "BitcoinD.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <utility>

SrvMgr::SrvMgr(const std::shared_ptr<Options> & options,
               std::shared_ptr<Storage> s, std::shared_ptr<BitcoinDMgr> bdm, QObject *parent)
    : Mgr(parent), options(options), storage(std::move(s)), bitcoindmgr(std::move(bdm))
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
    if (servers.empty()) {
        startServers();
    } else {
        Error() << __PRETTY_FUNCTION__ << " called with servers already active! FIXME!";
    }
}

void SrvMgr::cleanup()
{
    servers.clear(); // unique_ptrs auto-delete all servers
}

// throw Exception on error
void SrvMgr::startServers()
{
    const auto num = options->interfaces.length() + options->sslInterfaces.length();
    Log() << "SrvMgr: starting " << num << " " << Util::Pluralize("service", num) << " ...";
    for (auto iface : options->interfaces) {
        servers.emplace_back(std::make_unique<Server>(iface.first, iface.second, storage, bitcoindmgr));
        Server *srv = servers.back().get();
        srv->tryStart();

        // connet blockchain.headers.subscribe signal
        connect(this, &SrvMgr::newHeader, srv, &Server::newHeader);
    }
    for (auto iface : options->sslInterfaces) {
        servers.emplace_back(std::make_unique<ServerSSL>(options->sslCert, options->sslKey, iface.first, iface.second, storage, bitcoindmgr));
        Server *srv = servers.back().get();
        srv->tryStart();

        // connet blockchain.headers.subscribe signal
        connect(this, &SrvMgr::newHeader, srv, &Server::newHeader);
    }
}

auto SrvMgr::stats() const -> Stats
{
    QVariantList serverList;
    const int timeout = kDefaultTimeout / qMax(int(servers.size()), 1);
    for (auto & serverptr : servers) {
        using Pair = std::pair<QString, QVariant>;
        auto server = serverptr.get();
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
