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
#pragma once

#include "Mgr.h"
#include "Options.h"

#include <QMultiHash>

#include <list>
#include <memory>

class BitcoinDMgr;
class PeerMgr;
class Server;
class Storage;

class SrvMgr : public Mgr
{
    Q_OBJECT
public:
    explicit SrvMgr(const std::shared_ptr<const Options> & options,
                    const std::shared_ptr<Storage> & storage,
                    const std::shared_ptr<BitcoinDMgr> & bitcoindmgr,
                    QObject *parent = nullptr);
    ~SrvMgr() override;
    void startup() override; // may throw on error
    void cleanup() override;

    int nServers() const { return int(servers.size()); }

signals:
    /// Notifies all blockchain.headers.subscribe'd clients for the entire server about a new header.
    /// (normally connected to the Controller::newHeader signal).
    void newHeader(unsigned height, const QByteArray &header);

    /// Emitted once upon client connect (from the clientConnected() slot) if the new client in question ends up
    /// exceeding the connection limit for its IP.  The "Server" (and its subclasses) are connected to this signal
    /// and immediately kill the connection for such clients.  The clients-per-ip limit is set by the
    /// "max_clients_per_ip"  config variable (see Options.h)
    void clientExceedsConnectionLimit(IdMixin::Id);

protected:
    Stats stats() const override;

protected slots:
    /// Server subclasses are connected to this slot, which is used to notify this instance of new client connections
    void clientConnected(IdMixin::Id, const QHostAddress &);
    /// Server subclasses are connected to this slot, which is used to notify this instance of client disconnections
    void clientDisconnected(IdMixin::Id, const QHostAddress &);

private:
    void startServers();
    const std::shared_ptr<const Options> options;
    std::shared_ptr<Storage> storage;
    std::shared_ptr<BitcoinDMgr> bitcoindmgr;
    std::list<std::unique_ptr<Server>> servers;
    std::unique_ptr<PeerMgr> peermgr; ///< will be nullptr if options->peerDiscovery is false

    QMultiHash<QHostAddress, IdMixin::Id> addrIdMap;
};

Q_DECLARE_METATYPE(QHostAddress);
