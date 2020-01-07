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
#include "ServerMisc.h"
#include "Version.h"

#include <QHash>
#include <QHostAddress>
#include <QList>

struct Options;
class Storage;
struct PeerInfo;

using PeerInfoList = QList<PeerInfo>;

class PeerMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
public:
    PeerMgr(const std::shared_ptr<Storage> & , const std::shared_ptr<const Options> &);
    ~PeerMgr() override;

    void startup() noexcept(false) override; ///< may throw
    void cleanup() override;

    /// The hostname lookup timeout for add_peer hostname verification
    static constexpr int DNSTimeoutMS = 3000;

public slots:
    /// The various Server instances are connected to this slot (via their gotRpcAddPeer signals), connections made by SrvMgr.
    void on_rpcAddPeer(const PeerInfoList &, const QHostAddress & source);
    void allServersStarted(); ///< tells this instance all our services are up, so it may begin searching for peers and publishing our information

protected:
    void on_started() override;
private:
    const std::shared_ptr<const Storage> storage; ///< from SrvMgr, read-only, for getChain() and genesisHash()
    const std::shared_ptr<const Options> options; ///< from SrvMgr that creates us.

    using PeerInfoMap = QHash<QString, PeerInfo>; // hostname -> PeerInfo

    PeerInfoMap seedPeers; ///< parsed PeerInfos from server.json or servers_testnet.json
    void parseServersDotJson(const QString &) noexcept(false); ///< may throw

    void addPeerVerifiedSource(const PeerInfo &, const QHostAddress &resolvedAddress);

    PeerInfoMap queued, bad, stale;
};

/// Thrown by PeerInfo::fromFeaturesMap
struct BadFeaturesMap : public Exception { using Exception::Exception; };

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

    double ts = 0.; ///< ts from Util::getTimeSecs() -- when it went stale or bad,  (if stale or bad), or when it was added

    void clear() { *this = PeerInfo(); }
    bool isTor() const { return hostName.toLower().endsWith(".onion"); }
    /// minimal checking that hostname is not empty and that at least an ssl or a tcp port are defined.
    bool isMinimallyValid() const { return !hostName.isEmpty() && (ssl || tcp) && hashFunction == ServerMisc::HashFunction; }

    /// Pass it the "features" map as returned by server.features. Normally only one PeerInfo will be returned, but
    /// there may be multiple in the case of .onion in the 'hosts' sub-map.  All of the hosts returned have identical
    /// members with the exception of .hostName, .ssl, and .tcp which may differ. Will never return an empty list,
    /// instead, it will throw if no servers are contained in the map. Will also throw if other minimal checks fail.
    static PeerInfoList fromFeaturesMap(const QVariantMap &m) noexcept(false); ///< NOTE: May throw BadFeaturesMap
};

Q_DECLARE_METATYPE(PeerInfo);
Q_DECLARE_METATYPE(PeerInfoList);
