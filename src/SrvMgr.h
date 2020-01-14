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
#include <mutex>

class AdminServer;
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

    std::size_t txBroadcasts() const { return numTxBroadcasts.load(); }
    std::size_t txBroadcastBytes() const { return txBroadcastBytesTotal.load(); }

    /// Must be called in this object's thread -- does a blocking call to all the Server instances that are started
    /// (timeout_ms, specify timeout_ms <= 0 to block forever), and prepares the QVariantList RPC response appropriate
    /// to send back to the FulcrumAdmin script.  May throw Utils::TimeoutException, or Util::ThreadNotRunning if called
    /// with the servers stopped.
    QVariantList adminRPC_getClients_blocking(int timeout_ms) const;
    /// Called by the admin server (and also the ::stats method). This is thread-safe as it takes a lock.
    /// Returns a map suitable for serializing to JSON or printing ot the /stats port.
    QVariantMap adminRPC_banInfo_threadSafe() const;

    /// Returns true if the specified address is in the ban table.  This method is thread-safe.
    bool isIPBanned(const QHostAddress &, bool incrementCounter = true) const;

signals:
    /// Notifies all blockchain.headers.subscribe'd clients for the entire server about a new header.
    /// (normally connected to the Controller::newHeader signal).
    void newHeader(unsigned height, const QByteArray &header);

    /// Emitted once upon client connect (from the clientConnected() slot) if the new client in question ends up
    /// exceeding the connection limit for its IP.  The "Server" (and its subclasses) are connected to this signal
    /// and immediately kill the connection for such clients.  The clients-per-ip limit is set by the
    /// "max_clients_per_ip"  config variable (see Options.h)
    void clientExceedsConnectionLimit(IdMixin::Id);

    /// Emitted one upon client connect (from the clientConnected() slot) if the new client in question is banneed
    /// (bans are currently by-IP).  Like clientExceedsConnectionLimit above, the Server (and its subclasses) are
    /// connected to this signal. The ban table is the banMap private member.
    void clientIsBanned(IdMixin::Id);

    /// Emitted by this instance to signify all servers have been started.  PeerMgr is connected to this to start
    /// its own processing once all servers are up.
    void allServersStarted();

    /// Connected to each Server instance's `killClient` slot.  Each client has a unique Id, so if the client is still
    /// connected, one of the extant Server instances will pick up the request and disconnect the client immediately.
    void kickById(IdMixin::Id);
    /// Connected to each Server instance's `killClientsByAddress` slot.  All clients (if any) that exactly match the
    /// specified address will be immediately disconnected.
    void kickByAddress(const QHostAddress &);

    /// Any object or thread can emit this signal, which is connected to the protected on_banIP slot, which then
    /// goes ahead and updates the ban table and issues an immediate kick by IP to the server instances.
    /// AdminServer emits this.
    void banIP(const QHostAddress &);
    /// This is also emitted by the AdminServer, connected to on_banID, which tries to find the given ID by doing
    /// a linear search in the addrIdMap.  May not always succeed if the client is no longer connected when the
    /// on_banID slot is called.
    void banID(IdMixin::Id);

    /// Emitted by the AdminServer, connected to a slot which will run in our thread, on_liftIPBan.
    void liftIPBan(const QHostAddress &);

protected:
    Stats stats() const override;

protected slots:
    /// Server subclasses are connected to this slot, which is used to notify this instance of new client connections
    void clientConnected(IdMixin::Id, const QHostAddress &);
    /// Server subclasses are connected to this slot, which is used to notify this instance of client disconnections
    void clientDisconnected(IdMixin::Id, const QHostAddress &);
    /// Connected to the banIP signal declared above -- effects the ban.
    void on_banIP(const QHostAddress &);
    /// Connected to the banIP signal declared above -- effects the ban, but may not always succeed if the client
    /// disconnected before this runs, because we "forget" their id immediately.
    /// TODO: FIX THIS by remembering Ids for recently-disconnected clients for a time...
    void on_banID(IdMixin::Id);
    /// Connected to the liftIPBan signal
    void on_liftIPBan(const QHostAddress &);

private:
    void startServers();
    const std::shared_ptr<const Options> options;
    std::shared_ptr<Storage> storage;
    std::shared_ptr<BitcoinDMgr> bitcoindmgr;
    std::list<std::unique_ptr<Server>> servers;
    std::list<std::unique_ptr<AdminServer>> adminServers;
    std::shared_ptr<PeerMgr> peermgr; ///< will be nullptr if options->peerDiscovery is false

    QMultiHash<QHostAddress, IdMixin::Id> addrIdMap;

    std::atomic_size_t numTxBroadcasts = 0, txBroadcastBytesTotal = 0;

    // -- the below is shared with other threads and guarded by banMut.
    struct BanInfo {
        QHostAddress address;
        int64_t ts = 0U; ///< when banned, in msec, from Util::getTime()
        mutable unsigned rejectedConnectionCount = 0U; ///< the number of times a connection was rejected matching this ban
    };
    QHash<QHostAddress, BanInfo> banMap;
    mutable std::mutex banMut;
};

Q_DECLARE_METATYPE(QHostAddress);
