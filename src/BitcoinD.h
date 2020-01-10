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

#include <QHostAddress>

#include <atomic>
#include <memory>
#include <set>

class BitcoinD;

class BitcoinDMgr : public Mgr, public IdMixin, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
public:
    BitcoinDMgr(const QString &hostnameOrIP, quint16 port, const QString &user, const QString &pass, bool preferIPv6);
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
    /// - ResultsF will be called exactly once on success returning the reults encapsulated in an RPC::Message
    /// - If BitcoinD generated an error response, ErrorF will be called exactly once with the error wrapped in an
    ///   RPC::Message
    /// - If some other error occurred (such as timeout, or BitcoinD not connected, or connection lost, etc), FailF
    ///   will be called exactly once with a string message.
    ///
    /// If at any time before results are ready the `sender` object is deleted, nothing will be called and everything
    /// related to this request will be cleaned up automatically.
    void submitRequest(QObject *sender, const RPC::Message::Id &id, const QString & method, const QVariantList & params,
                       const ResultsF & = ResultsF(), const ErrorF & = ErrorF(), const FailF & = FailF());

signals:
    void gotFirstGoodConnection(quint64 bitcoindId); // emitted whenever the first bitcoind after a "down" state (or after startup) gets its first good status (after successful authentication)
    void allConnectionsLost(); // emitted whenever all bitcoind rpc connections are down.
    /// emitted if bitcoind is telling us it's still warming up (RPC error code -28). The actual warmup message is
    /// the argument.
    void inWarmUp(const QString &);

    /// internal signal, emitted when resolved a new IP address for bitcoind
    void bitcoinDIPChanged(const QHostAddress &);

protected:
    Stats stats() const override; // from Mgr

    void on_started() override; // from ThreadObjectMixin

protected slots:
    // connected to BitcoinD gotMessage signal
    void on_Message(quint64 bitcoindId, const RPC::Message &msg);
    // connected to BitcoinD gotErrorMessage signal
    void on_ErrorMessage(quint64 bitcoindId, const RPC::Message &msg);

private:
    const QString hostName;
    QHostAddress resolvedAddress;
    const quint16 port;
    const QString user, pass;
    const bool preferIPv6;
    const bool needsResolver;

    static constexpr int miniTimeout = 333, tinyTimeout = 167, medTimeout = 500, longTimeout = 1000, resolverTimeout = 10000;

    std::set<quint64> goodSet; ///< set of bitcoind's (by id) that are `isGood` (connected, authed). This set is updated as we get signaled from BitcoinD objects. May be empty. Has at most N_CLIENTS elements.

    std::unique_ptr<BitcoinD> clients[N_CLIENTS];

    BitcoinD *getBitcoinD(); ///< may return nullptr if none are up. Otherwise does a round-robin of the ones present to grab one. to be called only in this thread.
    void resolveBitcoinDHostname();
};

class BitcoinD : public RPC::HttpConnection, public ThreadObjectMixin /* NB: also inherits TimersByNameMixin via AbstractConnection base */
{
    Q_OBJECT

public:
    /// TODO: have this come from config. For now: support up to ~50MiB blocks (hex encoded) from bitcoind.
    /// Note that Qt has a limitation for JSON document parsing at around 100MB anyway so .. it is what it is.
    /// This should work for now since we are on 32MiB max block size on BCH anyway right now.
    static constexpr qint64 BTCD_DEFAULT_MAX_BUFFER = 100*1000*1000;

    explicit BitcoinD(const QHostAddress &host, quint16 port, const QString & user, const QString &pass, qint64 maxBuffer = BTCD_DEFAULT_MAX_BUFFER);
    ~BitcoinD() override;

    using ThreadObjectMixin::start;
    using ThreadObjectMixin::stop;

    bool isGood() const override; ///< from AbstractConnection -- returns true iff Status==Connected AND auth confirmed ok.

signals:
    /// This is emitted immediately after successful socket connect but before auth. After this signal, client code
    /// can expect either one of the two following signals to be emitted: either the authenticated() signal below,
    /// or the base class's authFailure() signal.
    void connected(BitcoinD *me);
    void authenticated(BitcoinD *me); ///< This is emitted after we have successfully connected and auth'd.

public slots:
    void on_BitcoinDIPChanged(const QHostAddress &);

protected:
    void on_started() override;
    void on_connected() override;

    void do_ping() override; // testing

    void reconnect();

    /// Not thread safe. Be sure to call this in this object's thread. Override from StatsMixin
    Stats stats() const override;

private:
    void connectMiscSignals(); ///< some signals/slots to self to do bookkeeping

    QHostAddress host;
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
        std::atomic_bool replied = false;
        QList<QMetaObject::Connection> conns;

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
