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

#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"
#include "ServerMisc.h"
#include "Version.h"

#include <QHash>
#include <QHostAddress>
#include <QList>

#include <mutex>
#include <shared_mutex>

struct Options;
class Storage;
struct PeerInfo;
class PeerClient;

using PeerInfoList = QList<PeerInfo>;

class PeerMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin, public ProcessAgainMixin
{
    Q_OBJECT
public:
    PeerMgr(const std::shared_ptr<Storage> & , const std::shared_ptr<const Options> &);
    ~PeerMgr() override;

    void startup() noexcept(false) override; ///< may throw
    void cleanup() override;

    /// some time intervals we use, in seconds
    static constexpr double kDNSTimeout = 15.0, ///< The hostname lookup timeout for add_peer hostname verification (set to a longish value for Tor support)
                            kProcessSoonInterval = 1.0, ///< "processSoon" means in 1 second
                            kFailureRetryTime = 10. * 60., ///< the amount of time to wait before retrying failed servers (10 mins)
                            kBadPeerRetryTime = 60. * 60., ///< the amount of time to wait before retrying bad peers (60 mins)
                            kConnectedPeerRefreshInterval = 3. * 60.; ///< we keep "pinging" connected peers at this interval (3 mins) to make sure they are still alive

    /// Used by PeerClient instances to compare the remote server's genesis hash to our own.
    QByteArray genesisHash() const { return _genesisHash; }
    QString publicHostNameForConnection(PeerClient *) const;
    /// returns a suitable features map for a given client connection
    QVariantMap makeFeaturesDict(PeerClient *) const;

    /// Thread-safe. Returns the current known-good PeerInfoList
    PeerInfoList peers() const;

public slots:
    /// The various Server instances are connected to this slot (via their gotRpcAddPeer signals), connections made by SrvMgr.
    /// Also: PeerClient instances are connected to this via their gotPeersSubscribeReply signal
    void on_rpcAddPeer(const PeerInfoList &, const QHostAddress & source);
    /// Called by SrvMgr to tell this instance all our services are up, so it may begin searching for peers and publishing our information.
    void allServersStarted();

signals:
    /// Emitted to notify Server instances of a new peers list.  Connected to the onPeersUpdated slot in all extant Server instances.
    void updated(const PeerInfoList &);

protected:
    void on_started() override;
    void process() override;
    Stats stats() const override;

protected slots:
    void on_bad(PeerClient *);
    void on_connectFailed(PeerClient *);
private:
    const std::shared_ptr<const Storage> storage; ///< from SrvMgr, read-only, for getChain() and genesisHash()
    const std::shared_ptr<const Options> options; ///< from SrvMgr that creates us.

    QByteArray _genesisHash;

    bool hasip4 = false, hasip6 = false;

    using PeerInfoMap = QHash<QString, PeerInfo>; // hostname -> PeerInfo

    PeerInfoMap seedPeers; ///< parsed PeerInfos from server.json or servers_testnet.json

    void parseServersDotJson(const QString &) noexcept(false); ///< may throw

    void addPeerVerifiedSource(const PeerInfo &, const QHostAddress &resolvedAddress);

    void processSoon();
    void updateSoon();
    void retryFailedPeers(bool useBadMapInstead = false);
    void detectProtocol(const QHostAddress &);
    PeerClient *newClient(const PeerInfo &);

    PeerInfoMap queued, bad, failed;

    QHash<QString, PeerClient *> clients;

    PeerInfoList sharedPeers; ///< gets returned from the public thread-safe function `peers`
    mutable std::shared_mutex mut; ///< mutex for above
    using ExclusiveLock = std::lock_guard<std::shared_mutex>;
    using SharedLock = std::shared_lock<std::shared_mutex>;
};


/// Thrown by PeerInfo::fromFeaturesMap
struct BadFeaturesMap : public Exception { using Exception::Exception; };
/// Thrown by PeerInfo::fromPeersSubscribeList
struct BadPeerList : public Exception { using Exception::Exception; };

struct PeerInfo
{
    QString hostName;
    QHostAddress addr; ///< may originally come from json or be empty -- is populated/reverified later after hostname lookup.
    quint16 ssl = 0; ///< ssl port - 0 means undefined (no port)
    quint16 tcp = 0; ///< tcp port - 0 means undefined (no port)
    Version protocolVersion; ///< may originally come from json or be empty -- is populated/reverified later after connection to peer

    QString subversion; ///< if we actually managed to connect to the server, its subversion string e.g. "Fulcrum 1.0", or may come initially from features dict
    /// These get populated if we managed to connect to the server, or if the server's info came from  a features dictionary
    QByteArray genesisHash; ///< if known, may be empty, may come from features map
    Version protocolMin,
            protocolMax;
    QString hashFunction = ServerMisc::HashFunction; /// may also come from features map

    QString failureReason; ///< the 'failed' and 'bad' PeerInfos may have this set

    void clear() { *this = PeerInfo(); }
    bool isTor() const { return hostName.toLower().endsWith(".onion"); }
    /// minimal checking that hostname is not empty and that at least an ssl or a tcp port are defined.
    bool isMinimallyValid() const { return !hostName.isEmpty() && (ssl || tcp) && hashFunction == ServerMisc::HashFunction; }

    /// Pass it the "features" map as returned by server.features. Normally only one PeerInfo will be returned, but
    /// there may be multiple in the case of .onion in the 'hosts' sub-map.  All of the hosts returned have identical
    /// members with the exception of .hostName, .ssl, and .tcp which may differ. Will never return an empty list,
    /// instead, it will throw if no servers are contained in the map. Will also throw if other minimal checks fail.
    static PeerInfoList fromFeaturesMap(const QVariantMap &m) noexcept(false); ///< NOTE: May throw BadFeaturesMap
    /// Pass it the list as you would get from a server.peers.subscribe response.  It should spit back out a
    /// list of infos, partially-filled-in, and ready to be send down the PeerMgr pipeline for connecting-to.
    static PeerInfoList fromPeersSubscribeList(const QVariantList &l) noexcept(false);
};

class PeerClient : public RPC::LinefeedConnection
{
    Q_OBJECT
protected:
    /// Only PeerMgr can construct us.
    friend class ::PeerMgr;
    explicit PeerClient(bool announceSelf, const PeerInfo &info, IdMixin::Id id, PeerMgr *mgr, int maxBuffer);
public:
    ~PeerClient() override;

    void connectToPeer();

    bool sentVersion = false;

    const bool announceSelf;
    PeerInfo info;

signals:
    /// connected to PeerMgr::on_bad
    void bad(PeerClient *me);
    /// connected to PeerMgr::on_connectFailed
    void connectFailed(PeerClient *me);
    /// connected to PeerMgr::on_rpcAddPeer
    void gotPeersSubscribeReply(const PeerInfoList &, const QHostAddress &);

protected slots:
    void handleReply(IdMixin::Id myid, const RPC::Message & reply);
protected:
    void do_ping() override;
    void on_connected() override;
    void do_disconnect(bool graceful = false) override; ///< calls base, also does this->deleteLater

    Stats stats() const override; /// adds more stats to base class's stats map

    PeerMgr *mgr;
private:
    void refresh();
    /// Updates the updateable fields in this->info from the remote "features" response
    void updateInfoFromRemoteFeaturesMap(const PeerInfo &);
};

Q_DECLARE_METATYPE(PeerInfo);
Q_DECLARE_METATYPE(PeerInfoList);
