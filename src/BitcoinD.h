//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "BitcoinD_RPCInfo.h"
#include "BlockProcTypes.h"
#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"
#include "Version.h"

#include <QHash>
#include <QHostAddress>
#include <QMultiHash>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <memory>
#include <set>
#include <shared_mutex>
#include <vector>

class BitcoinD;
namespace BitcoinDMgrHelper { class ReqCtxObj; }

using BitcoinDZmqNotifications = QMultiHash<QString, QString>; ///< "topic"-> "endpoint" e.g. "hashblock" -> "tcp://192.168.0.2:8333"

/// This basically all comes from bitcoind RPC `getnetworkinfo`
struct BitcoinDInfo {
    Version version {0,0,0}; ///> major, minor, revision e.g. {0, 20, 6} for v0.20.6
    QString subversion; ///< subversion string from daemon e.g.: /Bitcoin Cash Node bla bla;EB32 ..../
    double relayFee = 0.0; ///< from 'relayfee' in the getnetworkinfo response; minimum fee/kb to relay a tx, usually: 0.00001000
    QString warnings = ""; ///< from 'warnings' in the getnetworkinfo response (usually is empty string, but may not always be)
    bool isBchd = false; ///< true if remote bitcoind subversion is: /bchd:...
    bool isZeroArgEstimateFee = false; ///< true if remote bitcoind expects 0 argument "estimatefee" RPC.
    bool isCore = false; ///< true if we are actually connected to /Satoshi.. node (Bitcoin Core)
    bool isLTC = false; ///< true if we are actually connected to /LitecoinCore.. node (Litecoin)
    bool isBU = false; ///< true if subversion string starts with "/BCH Unlimited:"
    bool isFlowee = false; ///< true if subversion string starts with "/Flowee"
    bool lacksGetZmqNotifications = false; ///< true if bchd or BU < 1.9.1.0, or if we got an RPC error the last time we queried
    bool hasDSProofRPC = false; ///< true if the RPC query to `getdsprooflist` didn't return an error.

    /// The below field is populated from bitcoind RPC `getzmqnotifications` (if supported and if we are compiled to
    /// use libzmq).  Note that entires in here are auto-transformed by BitcoinDMgr such that:
    ///     {"pubhashblock" : "tcp://0.0.0.0:8433"} -> { "hashblock" : "tcp://192.68.10.4:8433" }
    /// In other words, the topic has the "pub" prefix chopped off, and the 0.0.0.0 IP that bitcoind reports
    /// gets automatically transformed to the IP or hostname that we know we can use to connect to bitcoind.
    BitcoinDZmqNotifications zmqNotifications;

    /// Return all the information in this obejct as a QVariantMap suitable for placing into JSON results, etc (used by /stats and `getinfo`)
    QVariantMap toVariantMap() const;
};

class BitcoinDMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
public:
    BitcoinDMgr(unsigned nClients, const BitcoinD_RPCInfo &rpcInfo);
    ~BitcoinDMgr() override;

    void startup() override; ///< from Mgr
    void cleanup() override; ///< from Mgr

    const unsigned nClients; ///< The number of simultaneous BitcoinD clients we spawn. Always >=1. Comes ultimately from Options::bdNClients.

    using ResultsF = std::function<void(const RPC::Message &response)>;
    using ErrorF = ResultsF; // identical to ResultsF above except the message passed in is an error="" message.
    using FailF = std::function<void(const RPC::Message::Id &origId, const QString & failureReason)>;

    /// The default time in milliseconds after which we consider an extant request has "timed out". Can be set
    /// per-request in submitRequest. This default is used for remote clients (Electrum Protocol clients).
    /// For timeouts for requests originating from the Controller class, see Options::bdTimeout.
    static constexpr int kDefaultTimeoutMS = 15'000;

    /// This is safe to call from any thread.
    /// Internally it dispatches messages to `this` object's thread. Results/Error/Fail functions are called in the
    /// context of the `sender` object's thread, but only as long as `sender` is still alive. Returns immediately
    /// regardless of which thread context it's called in, with one of the 3 following being called later, in the thread
    /// context of `sender`, when results/errors/failure is determined:
    /// - ResultsF will be called exactly once on success with the reults encapsulated in an RPC::Message
    /// - If BitcoinD generated an error response, ErrorF will be called exactly once with the error wrapped in an
    ///   RPC::Message
    /// - If some other error occurred (such as timeout, or BitcoinD not connected, or connection lost, etc), FailF
    ///   will be called exactly once with a string message.
    ///
    /// If at any time before results are ready the `sender` object is deleted, nothing will be called and everything
    /// related to this request will be cleaned up automatically.
    /// NOTE:  the `id` for the request *must* be unique with respect to all other extant requests to bitcoind;
    ///        use newId() to guarantee this.
    /// NOTE2: calling this method while this BitcoinDManager is stopped or about to be stopped is not supported.
    void submitRequest(QObject *sender, const RPC::Message::Id &id, const QString & method, const QVariantList & params,
                       const ResultsF & = ResultsF(), const ErrorF & = ErrorF(), const FailF & = FailF(),
                       int timeout = kDefaultTimeoutMS);

    /// Thread-safe.  Returns a copy of the BitcoinDInfo object.  This object is refreshed each time we
    /// reconnect to BitcoinD.  This is called by ServerBase in various places.
    BitcoinDInfo getBitcoinDInfo() const;

    /// Thread-safe.  Returns a copy of the bitcoinDGenesisHash.  This hash is refreshed each time we
    /// reconnect to BitcoinD.  If empty, we haven't yet had a valid and successful bitcoind connection.
    /// This is called by the Controller task to check sanity and bail if it doesn't match the hash stored
    /// in the db. See also: Storage::genesisHash().
    BlockHash getBitcoinDGenesisHash() const;

    /// Thread-safe.  Convenient method to avoid an extra copy. Returns getBitcoinDInfo().isZeroArgEstimateFee
    bool isZeroArgEstimateFee() const;

    /// Thread-safe.  Convenient method to avoid an extra copy. Returns true iff getBitcoinDInfo().isCore || getBitcoinDInfo().isLTC.
    bool isCoreLike() const;

    /// Thread-safe.  Convenient method to avoid an extra copy. Returns getBitcoinDInfo().version
    Version getBitcoinDVersion() const;

    /// Thread-safe.  Convenient method to avoid an extra copy. Returns getBitcoinDInfo().zmqNotifications
    BitcoinDZmqNotifications getZmqNotifications() const;

    /// Thread-safe.  Convenient method to avoid an extra copy. Returns getBitcoinDInfo().hasDSProofRPC
    bool hasDSProofRPC() const;

signals:
    void gotFirstGoodConnection(quint64 bitcoindId); // emitted whenever the first bitcoind after a "down" state (or after startup) gets its first good status (after successful authentication)
    void allConnectionsLost(); // emitted whenever all bitcoind rpc connections are down.
    /// emitted if bitcoind is telling us it's still warming up (RPC error code -28). The actual warmup message is
    /// the argument.
    void inWarmUp(const QString &);

    /// Emitted as soon as we read the bitcoind subversion. If it starts with /Satoshi:.., we emit this
    /// with Coin::BTC, if subversion is /LitecoinCore... we emit Coin::LTC, otherwise, we emit it with
    /// Coin::BCH.
    void coinDetected(BTC::Coin);

    /// Emitted whenever the BitcoinDZmqNotifications change (this is also emitted the first time we retrieve them
    /// via getzmqnotifications). Note: this is never emitted if we are compiled without zmq support.
    void zmqNotificationsChanged(BitcoinDZmqNotifications);

    /// Emitted whenever we detected the optimal ping method to use: "uptime" (fast)  or "help help" (slower, more compatible)
    void detectedFastPingMethod(bool fast);

    /// Emitted by Controller whenever a block download starts and ends. This ends up controlling whether BitcoinD's
    /// disconnect the socket if they go "stale". Sometimes we get spurious "staleness" in BitcoinD when it's busy
    /// servicing a getblock request.  So during block download, we never disconnect if "stale".
    void inBlockDownload(bool b);

protected:
    Stats stats() const override; // from Mgr

    void on_started() override; // from ThreadObjectMixin
    void on_finished() override; // from ThreadObjectMixin

protected slots:
    // connected to BitcoinD gotMessage signal
    void on_Message(quint64 bitcoindId, const RPC::BatchId batchId, const RPC::Message &msg);
    // connected to BitcoinD gotErrorMessage signal
    void on_ErrorMessage(quint64 bitcoindId, const RPC::Message &msg);

private:
    const BitcoinD_RPCInfo rpcInfo;

    static constexpr int miniTimeout = 333, tinyTimeout = 167, medTimeout = 500, longTimeout = 1000;

    std::set<quint64> goodSet; ///< set of bitcoind's (by id) that are `isGood` (connected, authed). This set is updated as we get signaled from BitcoinD objects. May be empty. Has at most N_CLIENTS elements.

    std::vector<std::unique_ptr<BitcoinD>> clients;
    unsigned roundRobinCursor = 0; ///< this is incremented each time. use this % N_CLIENTS to dole out bitcoind's in a round-robin fashion

    BitcoinD *getBitcoinD(); ///< may return nullptr if none are up. Otherwise does a round-robin of the ones present to grab one. to be called only in this thread.

    mutable std::shared_mutex bitcoinDInfoLock;
    BitcoinDInfo bitcoinDInfo;     ///< guarded by bitcoinDInfoLock

    void refreshBitcoinDNetworkInfo(); ///< whenever bitcoind comes back alive, this is invoked to update the bitcoinDInfo struct

    mutable std::shared_mutex bitcoinDGenesisHashLock;
    /// When we first (re)connect to bitcoind, we query this info to make sure it's still sane.
    BlockHash bitcoinDGenesisHash; ///< guarded by bitcoinDGenesisHashLock

    /// called whenever bitcoind comes back alive, updates bitcoinDGenesisHash
    void refreshBitcoinDGenesisHash();

    /// called whenever bitcoind comes back alive, updates bitcoinDInfo.zmqNotifications (only called if we are compiled with zmq support)
    void refreshBitcoinDZmqNotifications();

    /// called whenever bitcoind comes back alive, updates bitcoinDInfo.hasDSProofRPC
    void probeBitcoinDHasDSProofRPC();

    /// called whenever bitcoind comes back alive, detects whether bitcoind has the 'uptime' RPC call. And if so,
    /// emits detectedFastPingMethod(true), otherwise emits detectedFastPingMethod(false) if it lacks the RPC.
    void probeBitcoinDHasUptimeRPC();

    /// Calls resetPingTimer on each BitcionD -- used by quirk fixup code since bchd vs bitcoind require different
    /// pingtimes
    void resetPingTimers(int timeout_ms);

    // -- Request context table and request handler function --
    QHash<RPC::Message::Id, std::weak_ptr<BitcoinDMgrHelper::ReqCtxObj>> reqContextTable; // this should only be accessed from this thread
    // called in on_Message and on_ErrorMessage -- dispatches message by emitting proper signal
    template <typename ReqCtxObjT> // <-- we must template this here because ReqCtxObj is not defined yet. :/
    void handleMessageCommon(const RPC::Message &, void (ReqCtxObjT::*resultsOrErrorFunc)(const RPC::Message &));

    unsigned requestZombieCtr = 0; ///< keep track of how many req responses came in after the sender was deleted
    static constexpr auto kRequestTimeoutTimer = "+RequestTimeoutChecker";
    static constexpr auto kRequestTimerPolltimeMS = kDefaultTimeoutMS / 2;
    unsigned requestTimeoutCtr = 0; ///< keep track of how many requests timed out after kRequestTimeoutMS msecs of no reply from bitcoind

    /// Periodically checks the reqContextTable and expires extant requests that have timed out.
    void requestTimeoutChecker();
    /// Called from lostConnection() and destroyed() on a BitcoinD in order to notify all extant requests of the failure
    /// Note that `bd` pointer is never dereferenced, and it can be any QObject, but it should be a `BitcoinD`.
    /// (it's ok to pass a `BitcoinD` that is destructing and is now a `QObject`)
    void notifyFailForRequestsMatchingBitcoinD(const QObject *bd, const QString &errorMessage);

    /// Thread-safe. Called internally when a new map retrieved from bitcoind. If the map changed, zmqNotificationsChanged will be emitted.
    void setZmqNotifications(const BitcoinDZmqNotifications &);
    /// Latched to false after the first time setZmqNotifications() is called.
    /// Used to unconditionally emit the signal the first time through, even if we got an empty map.
    bool setZmqNotificationsWasNeverCalled = true;

    /// dsproof rpc setter -- called internally by probeBitcoinDHasDSProofRPC
    void setHasDSProofRPC(bool);
};

class BitcoinD : public RPC::HttpConnection, public ThreadObjectMixin /* NB: also inherits TimersByNameMixin via AbstractConnection base */
{
    Q_OBJECT

public:
    explicit BitcoinD(const BitcoinD_RPCInfo &rpcInfo);
    ~BitcoinD() override;

    using ThreadObjectMixin::start;
    using ThreadObjectMixin::stop;

    bool isGood() const override; ///< from AbstractConnection -- returns true iff Status==Connected AND auth confirmed ok.

    /// Resets the pingTimer to the specified interval in ms. Specify an interval <= 0 to disable the ping timer for
    /// this instance. (Thread-safe).
    ///
    /// Unlike the other methods in this class, this one is thread-safe.  If the calling thread is this->thread(), it
    /// takes effect immediately, otherwise an event is send to this object in its thread to restart the ping timer with
    /// the specified interval.
    void resetPingTimer(int time_ms);

public slots:
    /// Connected to BitcoinDMgr::detectedFastPingMethod (via AutoConnection -> QueuedConnection)
    void on_detectedFastPingMethod(bool b) { fastPing = b; }
    void on_inBlockDownload(bool b);

signals:
    /// This is emitted immediately after successful socket connect but before auth. After this signal, client code
    /// can expect either one of the two following signals to be emitted: either the authenticated() signal below,
    /// or the base class's authFailure() signal.
    void connected(BitcoinD *me);
    void authenticated(BitcoinD *me); ///< This is emitted after we have successfully connected and auth'd.

protected:
    void on_started() override;
    void on_connected() override;

    void do_ping() override;

    void reconnect();

    /// Not thread safe. Be sure to call this in this object's thread. Override from StatsMixin
    Stats stats() const override;

private:
    void connectMiscSignals(); ///< some signals/slots to self to do bookkeeping

    const BitcoinD_RPCInfo rpcInfo;
    std::atomic_bool badAuth = false, needAuth = true;
    bool fastPing = false;
    bool inBlockDownload = false;
};


namespace BitcoinDMgrHelper {
    /// Internal class used by the BitcoinDMgr submitRequest method. Not for use outside BitcoinD.cpp.
    /// (We can't make this a nested class because QObjects with metaobjects/signals cannot be nested classes).
    class ReqCtxObj : public QObject {
        Q_OBJECT

        friend class ::BitcoinDMgr;
        ReqCtxObj(int timeout);
        ~ReqCtxObj() override;

        // used internally by submitRequest
        std::atomic_bool replied = false;
        bool timedOut = false;
        const int timeout; //< request timeout in milliseconds. Must be >= 0.
        qint64 ts; ///<--- intentionally uninitialized to save cycles
        /// The BitcoinD instance that is handling our request. This pointer should *not* be dereferenced but only be
        /// used for == compare (since it's running in another thread). The reason why it's a QObject * and not a
        /// BitcoinD * is because we connect to the `destroyed` signal and check for equality on the (now) QObject
        /// (which was once a BitcoinD).
        const QObject *bd = nullptr;

        /// Mainly used for debugging the lifecycle of this class's instances.
        static std::atomic_int extant;

    signals:
        /// emitted by bitcoindmgr submitRequest internally when results are ready
        void results(const RPC::Message &response);
        /// emitted by bitcoindmgr submitRequest internally when there is an error response
        void error(const RPC::Message &response);
        /// emitted by bitcoindmgr submitRequest internally when there is a failure to talk to bitcoind
        void fail(const RPC::Message::Id &origId, const QString & failureReason);
    };
}
