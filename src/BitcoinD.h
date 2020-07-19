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

#include "BlockProcTypes.h"
#include "Mixins.h"
#include "Mgr.h"
#include "RPC.h"
#include "Version.h"

#include <QHash>
#include <QHostAddress>
#include <QVariantMap>

#include <atomic>
#include <memory>
#include <set>
#include <shared_mutex>

class BitcoinD;
namespace BitcoinDMgrHelper { class ReqCtxObj; }

/// This basically all comes from bitcoind RPC `getnetworkinfo`
struct BitcoinDInfo {
    Version version {0,0,0}; ///> major, minor, revision e.g. {0, 20, 6} for v0.20.6
    QString subversion; ///< subversion string from daemon e.g.: /Bitcoin Cash Node bla bla;EB32 ..../
    double relayFee = 0.0; ///< from 'relayfee' in the getnetworkinfo response; minimum fee/kb to relay a tx, usually: 0.00001000
    QString warnings = ""; ///< from 'warnings' in the getnetworkinfo response (usually is empty string, but may not always be)

    /// Return all the information in this obejct as a QVariantMap suitable for placing into JSON results, etc (used by /stats and `getinfo`)
    QVariantMap toVariandMap() const;
};

class BitcoinDMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
public:
    BitcoinDMgr(const QString &hostnameOrIP, quint16 port, const QString &user, const QString &pass);
    ~BitcoinDMgr() override;

    void startup() override; ///< from Mgr
    void cleanup() override; ///< from Mgr

    static constexpr int N_CLIENTS = 3; ///< the number of simultaneous BitcoinD clients we spawn. TODO: make this configurable.

    using ResultsF = std::function<void(const RPC::Message &response)>;
    using ErrorF = ResultsF; // identical to ResultsF above except the message passed in is an error="" message.
    using FailF = std::function<void(const RPC::Message::Id &origId, const QString & failureReason)>;

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
    /// NOTE: the `id` for the request *must* be unique with respect to all other extant requests to bitcoind;
    ///       use newId() to guarantee this.
    void submitRequest(QObject *sender, const RPC::Message::Id &id, const QString & method, const QVariantList & params,
                       const ResultsF & = ResultsF(), const ErrorF & = ErrorF(), const FailF & = FailF());

    /// Thread-safe.  Returns a copy of the BitcoinDInfo object.  This object is refreshed each time we
    /// reconnect to BitcoinD.  This is called by ServerBase in various places.
    BitcoinDInfo getBitcoinDInfo() const;

    /// Thread-safe.  Returns a copy of the bitcoinDGenesisHash.  This hash is refreshed each time we
    /// reconnect to BitcoinD.  If empty, we haven't yet had a valid and successful bitcoind connection.
    /// This is called by the Controller task to check sanity and bail if it doesn't match the hash stored
    /// in the db. See also: Storage::genesisHash().
    BlockHash getBitcoinDGenesisHash() const;

signals:
    void gotFirstGoodConnection(quint64 bitcoindId); // emitted whenever the first bitcoind after a "down" state (or after startup) gets its first good status (after successful authentication)
    void allConnectionsLost(); // emitted whenever all bitcoind rpc connections are down.
    /// emitted if bitcoind is telling us it's still warming up (RPC error code -28). The actual warmup message is
    /// the argument.
    void inWarmUp(const QString &);
protected:
    Stats stats() const override; // from Mgr

    void on_started() override; // from ThreadObjectMixin
    void on_finished() override; // from ThreadObjectMixin

protected slots:
    // connected to BitcoinD gotMessage signal
    void on_Message(quint64 bitcoindId, const RPC::Message &msg);
    // connected to BitcoinD gotErrorMessage signal
    void on_ErrorMessage(quint64 bitcoindId, const RPC::Message &msg);

private:
    const QString hostName;
    const quint16 port;
    const QString user, pass;

    static constexpr int miniTimeout = 333, tinyTimeout = 167, medTimeout = 500, longTimeout = 1000;

    std::set<quint64> goodSet; ///< set of bitcoind's (by id) that are `isGood` (connected, authed). This set is updated as we get signaled from BitcoinD objects. May be empty. Has at most N_CLIENTS elements.

    std::unique_ptr<BitcoinD> clients[N_CLIENTS];

    BitcoinD *getBitcoinD(); ///< may return nullptr if none are up. Otherwise does a round-robin of the ones present to grab one. to be called only in this thread.

    /// Various quirk flags of the bitcoind we are connected to
    struct Quirks {
        /// If true, remote bitcoind is bchd. Gets set in refreshBitcoinDNetworkInfo() when we (re)connect to bitcoind.
        std::atomic_bool isBchd = false;
        /// (bchd only) If this is true, then `getrawtransaction` expects an integer not a bool for its second
        /// arg; start off true, but this flag may get latched to false if we detect that bchd fixed the bug.
        /// see: applyBitcoinDQuirksToParams()
        std::atomic_bool bchdGetRawTransaction = true;

        /// (ABC and BCHN only version >= 0.20.2) If true, `estimatefee` expects 0 args.
        std::atomic_bool zeroArgEstimateFee = false;
    };
    Quirks quirks;

    /// Called from `submitRequest` -- returns a params object which may be a shallow copy of `params`, or a
    /// transformed params object after applying bitcoind workarounds (consults the `quirks` struct above).
    QVariantList applyBitcoinDQuirksToParams(const BitcoinDMgrHelper::ReqCtxObj *context, const QString &method, const QVariantList &params);

    mutable std::shared_mutex bitcoinDInfoLock;
    BitcoinDInfo bitcoinDInfo;     ///< guarded by bitcoinDInfoLock

    void refreshBitcoinDNetworkInfo(); ///< whenever bitcoind comes back alive, this is invoked to update the bitcoinDInfo struct

    mutable std::shared_mutex bitcoinDGenesisHashLock;
    /// When we first (re)connect to bitcoind, we query this info to make sure it's still sane.
    BlockHash bitcoinDGenesisHash; ///< guarded by bitcoinDGenesisHashLock

    /// called whenever bitcoind comes back alive, updates bitcoinDGenesisHash
    void refreshBitcoinDGenesisHash();

    /// Calls resetPingTimer on each BitcionD -- used by quirk fixup code since bchd vs bitcoind require different
    /// pingtimes
    void resetPingTimers(int timeout_ms);

    // -- Request context table and request handler function --
    QHash<RPC::Message::Id, std::weak_ptr<BitcoinDMgrHelper::ReqCtxObj>> reqContextTable; // this should only be accessed from this thread
    // called in on_Message and on_ErrorMessage -- dispatches message by emitting proper signal
    template <typename ReqCtxObjT> // <-- we must template this here because ReqCtxObj is not defined yet. :/
    void handleMessageCommon(const RPC::Message &, void (ReqCtxObjT::*resultsOrErrorFunc)(const RPC::Message &));

    unsigned requestZombieCtr = 0; ///< keep track of how many req responses came in after the sender was deleted
    static constexpr qint64 kRequestTimeoutMS = 15'000; ///< the time in milliseconds after which we consider an extant request has "timed out"
    static constexpr auto kRequestTimeoutTimer = "+RequestTimeoutChecker";
    unsigned requestTimeoutCtr = 0; ///< keep track of how many requests timed out after kRequestTimeoutMS msecs of no reply from bitcoind

    /// Periodically checks the reqContextTable and expires extant requests that have timed out.
    void requestTimeoutChecker();
};

class BitcoinD : public RPC::HttpConnection, public ThreadObjectMixin /* NB: also inherits TimersByNameMixin via AbstractConnection base */
{
    Q_OBJECT

public:
    /// TODO: Have this come from config. For now: support up to ~50MiB blocks (hex encoded) from bitcoind.
    /// This should work for now since we are on 32MiB max block size on BCH anyway right now.
    static constexpr qint64 BTCD_DEFAULT_MAX_BUFFER = 100'000'000;

    explicit BitcoinD(const QString &host, quint16 port, const QString & user, const QString &pass, qint64 maxBuffer = BTCD_DEFAULT_MAX_BUFFER);
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

signals:
    /// This is emitted immediately after successful socket connect but before auth. After this signal, client code
    /// can expect either one of the two following signals to be emitted: either the authenticated() signal below,
    /// or the base class's authFailure() signal.
    void connected(BitcoinD *me);
    void authenticated(BitcoinD *me); ///< This is emitted after we have successfully connected and auth'd.

protected:
    void on_started() override;
    void on_connected() override;

    void do_ping() override; // testing

    void reconnect();

    /// Not thread safe. Be sure to call this in this object's thread. Override from StatsMixin
    Stats stats() const override;

private:
    void connectMiscSignals(); ///< some signals/slots to self to do bookkeeping

    const QString host;
    const quint16 port;
    std::atomic_bool badAuth = false, needAuth = true;
};


namespace BitcoinDMgrHelper {
    /// Internal class used by the BitcoinDMgr submitRequest method. Not for use outside BitcoinD.cpp.
    /// (We can't make this a nested class because QObjects with metaobjects/signals cannot be nested classes).
    class ReqCtxObj : public QObject {
        Q_OBJECT

        friend class ::BitcoinDMgr;
        ReqCtxObj();
        ~ReqCtxObj() override;

        // used internally by submitRequest
        qint64 ts; ///< intentionally uninitialized to save cycles
        QList<QMetaObject::Connection> conns;
        std::atomic_bool replied = false;
        bool timedOut = false;

        /// Mainly used for debugging the lifecycle of this class's instances.
        static std::atomic_int extant;

        /// Called to clear the conns list (conns only hold weak_ptr refs in their lambda captures)
        void killConns(); // only call this from this object's thread!
    signals:
        /// emitted by bitcoindmgr submitRequest internally when results are ready
        void results(const RPC::Message &response);
        /// emitted by bitcoindmgr submitRequest internally when there is an error response
        void error(const RPC::Message &response);
        /// emitted by bitcoindmgr submitRequest internally when there is a failure to talk to bitcoind
        void fail(const RPC::Message::Id &origId, const QString & failureReason);
    };
}
