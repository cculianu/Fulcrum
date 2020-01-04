//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#include "SrvMgr.h"

#include "BitcoinD.h"
#include "Servers.h"
#include "Storage.h"
#include "Util.h"

#include <utility>

SrvMgr::SrvMgr(const std::shared_ptr<Options> & options,
               const std::shared_ptr<Storage> & s,
               const std::shared_ptr<BitcoinDMgr> & bdm,
               QObject *parent)
    : Mgr(parent), options(options), storage(s), bitcoindmgr(bdm)
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
    const auto firstSsl = options->interfaces.size();
    int i = 0;
    for (const auto & iface : options->interfaces + options->sslInterfaces) {
        if (i < firstSsl)
            // TCP
            servers.emplace_back(std::make_unique<Server>(iface.first, iface.second, options, storage, bitcoindmgr));
        else
            // SSL
            servers.emplace_back(std::make_unique<ServerSSL>(iface.first, iface.second, options, storage, bitcoindmgr));
        Server *srv = servers.back().get();
        srv->tryStart();

        // connet blockchain.headers.subscribe signal
        connect(this, &SrvMgr::newHeader, srv, &Server::newHeader);
        ++i;
    }
}

auto SrvMgr::stats() const -> Stats
{
    QVariantMap m;
    m["donationAddress"] = options->donationAddress;
    m["bannerFile"] = options->bannerFile.toUtf8(); // so we get a nice 'null' if not specified
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
    m["Servers"] = serverList;
    return m;
}
