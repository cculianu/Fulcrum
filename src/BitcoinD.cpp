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

#include "BitcoinD.h"
#include "bitcoin/rpc/protocol.h"

#include <QHostInfo>
#include <QMetaType>
#include <QPointer>

#include <mutex>

namespace {
    enum class PingTimes : int {
        Normal = 10'000,  /**< Normal bitcoind -- we send a ping every 10 seconds */
        BCHD   =  3'333,  /**< bchd has a short idle timeout of 10 secs. 3.333 sec pingtime ensures no dropped conns. */
    };
}

BitcoinDMgr::BitcoinDMgr(const QString &hostName, quint16 port,
                         const QString &user, const QString &pass)
    : Mgr(nullptr), IdMixin(newId()), hostName(hostName), port(port), user(user), pass(pass)
{
    setObjectName("BitcoinDMgr");
    _thread.setObjectName(objectName());
}

BitcoinDMgr::~BitcoinDMgr() {  cleanup(); }

void BitcoinDMgr::startup() {
    Log() << objectName() << ": starting " << N_CLIENTS << " " << Util::Pluralize("bitcoin rpc client", N_CLIENTS) << " ...";

    // As soon as a good BitcoinD is up, try and grab the network info (version, subversion, etc).  This must
    // happen early because the values in this info object determine which workarounds we may or may not apply to
    // RPC args.
    conns += connect(this, &BitcoinDMgr::gotFirstGoodConnection, this, &BitcoinDMgr::refreshBitcoinDNetworkInfo);

    for (auto & client : clients) {
        // initial resolvedAddress may be invalid if user specified a hostname, in which case we will resolve it and
        // tell bitcoind's to update themselves and reconnect
        client = std::make_unique<BitcoinD>(hostName, port, user, pass);

        // connect client to us -- TODO: figure out workflow: how requests for work and results will get dispatched
        connect(client.get(), &BitcoinD::gotMessage, this, &BitcoinDMgr::on_Message);
        connect(client.get(), &BitcoinD::gotErrorMessage, this, &BitcoinDMgr::on_ErrorMessage);
        connect(client.get(), &BitcoinD::authenticated, this, [this](BitcoinD *b){
            // guard against stale/old signal
            if (!b->isGood()) {
                DebugM("got authenticated for id:", b->id, " but isGood() is false!");
                return; // false/stale signal
            }
            const bool wasEmpty = goodSet.empty();
            goodSet.insert(b->id);
            if (wasEmpty)
                emit gotFirstGoodConnection(b->id);
        });
        connect(client.get(), &BitcoinD::lostConnection, this, [this](AbstractConnection *c){
            // guard against stale/old signal
            if (c->isGood()) {
                DebugM("got lostConnection for id:", c->id, " but isGood() is true!");
                return; // false/stale signal
            }
            goodSet.erase(c->id);
            auto constexpr chkTimer = "checkNoMoreBitcoinDs";
            // we throttle the spamming of the allConnectionsLost signal via this mechanism
            callOnTimerSoonNoRepeat(miniTimeout, chkTimer, [this]{
                if (goodSet.empty())
                    emit allConnectionsLost();
            }, true);
        });

        client->start();
    }

    start();

    Log() << objectName() << ": started ok";
}

void BitcoinDMgr::on_started()
{
    ThreadObjectMixin::on_started();
}

void BitcoinDMgr::cleanup() {
    stop();

    for (auto & client : clients) {
        client.reset(); /// implicitly calls client->stop()
    }
    goodSet.clear();

    Debug() << "BitcoinDMgr cleaned up";
}

auto BitcoinDMgr::stats() const -> Stats
{
    QVariantList l;
    constexpr int timeout = kDefaultTimeout/qMax(N_CLIENTS,1);
    for (const auto & client : clients) {
        if (!client) continue;
        auto map = client->statsSafe(timeout).toMap();
        auto name = map.take("name").toString();
        l += QVariantMap({{ name, map }});
    }
    QVariantMap m;
    m["rpc clients"] = l;
    m["extant request contexts"] = BitcoinDMgrHelper::ReqCtxObj::extant.load();
    m["request context table size"] = reqContextTable.size();
    m["zombie response count"] = zombieResponseCtr;
    m["activeTimers"] = activeTimerMapForStats();

    // "quirks"
    QVariantMap quirks;
    quirks["bchd"] = this->quirks.isBchd.load();
    quirks["bchdGetRawTransaction"] = this->quirks.isBchd && this->quirks.bchdGetRawTransaction;
    quirks["zeroArgEstimateFee"] = this->quirks.zeroArgEstimateFee.load();
    m["quirks"] = quirks;

    // "bitcoind info"
    m["bitcoind info"] = getBitcoinDInfo().toVariandMap(); // takes lock, makes a copy, releases lock;

    return m;
}


BitcoinD *BitcoinDMgr::getBitcoinD()
{
    BitcoinD *ret = nullptr;
    unsigned which = 0;
    if (unsigned n = quint32(goodSet.size()); n > 1)
        which = QRandomGenerator::system()->bounded(n); // pick a random client in the set (which is an index of the "good clients")
    if (!goodSet.empty()) {
        // linear search for a bitcoind that is not lastBitcoinDUsed
        unsigned i = 0;
        for (auto & client : clients) {
            if (goodSet.count(client->id) && i++ == which && client->isGood()) {
                ret = client.get();
                break;
            }
        }
    }
    return ret;
}

namespace {
    struct BitcoinDVersionParseResult {
        bool isBchd;
        Version version;
    };

    BitcoinDVersionParseResult parseBitcoindDVersion(unsigned val, const QString &subversion) {
        // e.g. 0.20.6 comes in like this from bitcoind (as an unsigned int): 200600 (millions, 10-thousands, hundreds).
        // Note: some bchd versions have a weird version int with a different format than above, so we handle bchd
        // differently.
        if (subversion.startsWith("/bchd")) {
            // bchd is quirky. We can't rely on its "version" integer since the algorithm for its packing
            // is bizarre in older versions. (In newer versons Josh says he changed it to match bitcoind).
            // Instead, we parse the subversion string: "/bchd:maj.min.rev.../"
            Version version;
            if (const int colon = subversion.indexOf(':'), trailSlash = subversion.lastIndexOf('/'); colon == 5 && trailSlash > colon) {
                const int len = trailSlash - (colon + 1);
                if (len > 0)
                    // try and parse everything after /bchd:
                    version = Version(subversion.mid(colon + 1, len));
            }
            if (!version.isValid())
                // hmm.. subversion isn't "/bchd:x.y.z.../" -> fall back to unpacking the integer value (only works on newer bchd)
                version = Version(val, Version::BitcoinD);
            return {true, version};
        } else {
            // regular bitcoind, "version" is reliable
            return {false, Version(val, Version::BitcoinD)};
        }
    }
}

void BitcoinDMgr::refreshBitcoinDNetworkInfo()
{
    submitRequest(this, newId(), "getnetworkinfo", QVariantList{},
        // success
        [this](const RPC::Message & reply) {
            {
                const QVariantMap networkInfo = reply.result().toMap();
                // --- EXCLUSIVE-LOCKED SCOPE below this line ---
                std::unique_lock g(bitcoinDInfoLock);
                bitcoinDInfo.subversion = networkInfo.value("subversion", "").toString();
                // try and determine version major/minor/revision
                quirks.isBchd = [&networkInfo, this] {
                    bool ok = false;
                    const auto val = networkInfo.value("version", 0).toUInt(&ok);

                    if (ok) {
                        const auto res = parseBitcoindDVersion(val, bitcoinDInfo.subversion);
                        bitcoinDInfo.version = res.version;
                        DebugM("Refreshed version info from bitcoind, version: ", bitcoinDInfo.version.toString(true),
                               ", subversion: ", bitcoinDInfo.subversion);
                        return res.isBchd;
                    } else {
                        bitcoinDInfo.version = Version();
                        Warning() << "Failed to parse version info from bitcoind";
                    }
                    return false;
                }();
                bitcoinDInfo.relayFee = networkInfo.value("relayfee", 0.0).toDouble();
                bitcoinDInfo.warnings = networkInfo.value("warnings", "").toString();
                // set quirk flags: requires 0 arg `estimatefee`?
                static const auto isZeroArgEstimateFee = [](const Version &version, const QString &subversion) -> bool {
                    static const QString zeroArgSubversionPrefixes[] = { "/Bitcoin ABC", "/Bitcoin Cash Node", };
                    static const Version minVersion{0, 20, 2};
                    if (version < minVersion)
                        return false;
                    for (const auto & prefix : zeroArgSubversionPrefixes)
                        if (subversion.startsWith(prefix))
                            return true;
                    return false;
                };
                quirks.zeroArgEstimateFee = isZeroArgEstimateFee(bitcoinDInfo.version, bitcoinDInfo.subversion);
            } // end lock scope
            // next, be sure to set up the ping time appropriately for bchd vs bitcoind
            resetPingTimers(int(quirks.isBchd ? PingTimes::BCHD : PingTimes::Normal));
            // next up, do this query
            refreshBitcoinDGenesisHash();
        },
        // error
        [](const RPC::Message &msg) {
            Error() << "getnetworkinfo error, code: " << msg.errorCode() << ", error: " << msg.errorMessage();
        },
        // failure
        [](const RPC::Message::Id &, const QString &reason){ Error() << "getnetworkinfo failed: " << reason; }
    );
}

void BitcoinDMgr::resetPingTimers(int timeout_ms)
{
    for (auto & bd : clients)
        if (bd) bd->resetPingTimer(timeout_ms); // thread-safe
}

void BitcoinDMgr::refreshBitcoinDGenesisHash()
{
    submitRequest(this, newId(), "getblockhash", {0},
        // success
        [this](const RPC::Message & reply) {
            bool ok, changed = false;
            BlockHash oldHash, newHash;
            if (const auto hex = reply.result().toString().toUtf8(); (ok = hex.length() == HashLen*2)) {
                newHash = Util::ParseHexFast(hex);
                if ((ok = newHash.length() == HashLen)) {
                    {   // Lock scope
                        std::unique_lock g(bitcoinDGenesisHashLock);
                        oldHash = bitcoinDGenesisHash;
                        bitcoinDGenesisHash = newHash;
                    }
                    changed = !oldHash.isEmpty() && oldHash != newHash;
                    ok = !changed;
                }
            }
            if (!ok) {
                // Both of these error modes are pretty fatal. It might be a good idea to just
                // quit the app here. But in the spirit of never giving up and never surrendering,
                // we will just power through this situation with some error messages.
                if (changed)
                    Error() << "Error: bitcoind reports that the genesis hash has changed! Old hash: " << oldHash.toHex()
                            << ", new hash: " << newHash.toHex();
                else
                    Error() << "Error: Failed to parse genesis hash from bitcoind: " << reply.result().toString();
            } else {
                DebugM("Refreshed genesis hash from bitcoind: ", newHash.toHex());
            }
        },
        // error
        [](const RPC::Message &msg){
            Error() << "getblockhash error when attempting to get genesis hash, code: " << msg.errorCode()
                    << ", error: " << msg.errorMessage();
        },
        // failure
        [](const RPC::Message::Id &, const QString &reason){
            Error() << "getblockhash failed when attempting to get genesis hash: " << reason;
        }
    );
}

BitcoinDInfo BitcoinDMgr::getBitcoinDInfo() const
{
    std::shared_lock g(bitcoinDInfoLock);
    return bitcoinDInfo;
}

BlockHash BitcoinDMgr::getBitcoinDGenesisHash() const
{
    std::shared_lock g(bitcoinDGenesisHashLock);
    return bitcoinDGenesisHash;
}

QVariantList BitcoinDMgr::applyBitcoinDQuirksToParams(const BitcoinDMgrHelper::ReqCtxObj *context, const QString &method, const QVariantList &paramsIn)
{
    QVariantList params = paramsIn; // quick shallow copy
    // bchd quirk workaround detection (may add custom error handler connected to `this`, and mutate params iff `getrawtransaction`)
    if (quirks.isBchd.load(std::memory_order::memory_order_relaxed)) {
        if (method == QStringLiteral("getrawtransaction")) {
            // first, unconditionally attach this error handler (runs via DIRECT CONNECTION in `context`'s thread)
            connect(context, &BitcoinDMgrHelper::ReqCtxObj::error, this, [quirks=&quirks](const RPC::Message &response) {
                // Note: for performance, this runs in the `context` object's thread as a direct conenction
                // and as such it only captures a pointer to the thread-safe object "quirks".
                // For now context->thread() == this->thread(), but we are being defensive here
                // in restricting things in case we decide to change where context lives in the
                // future.
                DebugM("BitcoinDMgr: bchd-quirk error handler fired for `", response.method, "`");
                if (response.errorCode() == -8) {
                    const bool flagVal = quirks->bchdGetRawTransaction;
                    if (!flagVal && response.errorMessage().contains("must be type int")) {
                        // bug present -- enable flag
                        quirks->bchdGetRawTransaction = true;
                        DebugM("BitcoinDMgr: latched quirk flag `bchdGetRawTransaction` to true");
                    } else if (flagVal && response.errorMessage().contains("must be type bool")) {
                        // bug was fixed in a future version -- disable flag
                        quirks->bchdGetRawTransaction = false;
                        DebugM("BitcoinDMgr: latched quirk flag `bchdGetRawTransaction` to false");
                    }
                }
            }, Qt::DirectConnection);
            // next, possibly do the `getrawtransaction` parameter transform if flag is set
            if (quirks.bchdGetRawTransaction && params.size() >= 2) {
                // transform the second arg to int from bool to handle bchd quirks
                if (auto var = params[1]; QMetaType::Type(var.type()) == QMetaType::Type::Bool) {
                    var = int(var.toBool());
                    params[1] = var;
                }
            }
        }
    }
    // BCHN or ABC >= v.0.20.2 require no arguments to "estimatefee"
    if (quirks.zeroArgEstimateFee.load(std::memory_order::memory_order_relaxed) && method == QStringLiteral("estimatefee")) {
        params.clear();
    }
    return params;
}

/// This is safe to call from any thread. Internally it dispatches messages to this obejct's thread.
/// Does not throw. Results/Error/Fail functions are called in the context of the `sender` thread.
void BitcoinDMgr::submitRequest(QObject *sender, const RPC::Message::Id &rid, const QString & method, const QVariantList & paramsIn,
                                const ResultsF & resf, const ErrorF & errf, const FailF & failf)
{
    using namespace BitcoinDMgrHelper;
    constexpr bool debugDeletes = false; // set this to true to print debug messages tracking all the below object deletions (tested: no leaks!)
    // A note about ownership: this context object is "owned" by the connections below to ->sender *only*.
    // It will be auto-deleted when the shared_ptr refct held by the lambdas drops to 0.  This is guaranteed
    // to happen either as a result of a successful request reply, or due to bitcoind failure, or if the sender
    // is deleted.
    auto context = std::shared_ptr<ReqCtxObj>(new ReqCtxObj, [](ReqCtxObj *context){
        // Note: this may run in any thread -- so all we can do here to context is context->deleteLater()
        if constexpr (debugDeletes) {
            DebugM(context->objectName(), " shptr deleter");
            connect(context, &QObject::destroyed, qApp, [n=context->objectName()]{ DebugM(n, " destroyed"); }, Qt::DirectConnection);
        }
        context->deleteLater(); // thread-safe
    });
    context->setObjectName(QStringLiteral("context for '%1' request id: %2").arg(sender ? sender->objectName() : QString()).arg(rid.toString()));

    // first, apply any bitcoind quirks (transforms 'params', may attach additional error handlers, etc)
    const QVariantList params = applyBitcoinDQuirksToParams(context.get(), method, paramsIn);

    // result handler (runs in sender thread), captures context and keeps it alive as long as signal/slot connection is alive
    connect(context.get(), &ReqCtxObj::results, sender, [context, resf, sender](const RPC::Message &response) {
        if (!context->replied.exchange(true) && resf)
            resf(response);
        // kill lambdas and shared_ptr captures, should cause deleter to execute
        context->disconnect(nullptr, sender); // thread-safe
    });
    // error handler (runs in sender thread), captures context and keeps it alive as long as signal/slot connection is alive
    connect(context.get(), &ReqCtxObj::error, sender, [context, errf, sender](const RPC::Message &response) {
        if (!context->replied.exchange(true) && errf)
            errf(response);
        // kill lambdas and shared_ptr captures, should cause deleter to execute
        context->disconnect(nullptr, sender); // thread-safe
    });
    // failure handler (runs in sender thread), captures context and keeps it alive as long as signal/slot connection is alive
    connect(context.get(), &ReqCtxObj::fail, sender, [context, failf, sender](const RPC::Message::Id &origId, const QString & failureReason) {
        if (!context->replied.exchange(true) && failf)
            failf(origId, failureReason);
        // kill lambdas and shared_ptr captures, should cause deleter to execute
        context->disconnect(nullptr, sender); // thread-safe
    });

    // send the context to our thread
    context->moveToThread(this->thread());

    // schedule this ASAP
    Util::AsyncOnObject(this, [this, context, rid, method, params] {
        auto bd = getBitcoinD();
        if (UNLIKELY(!bd)) {
            emit context->fail(rid, "Unable to find a good BitcoinD connection");
            return;
        }

        // put context in table -- this table is consulted in handleMessageCommon to dispatch
        // the reply directly to this context object
        if (auto it = reqContextTable.find(rid); LIKELY(it == reqContextTable.end() || it.value().expired())) {
            // does not exist in table, put in table
            reqContextTable[rid] = context; // weak ref inserted into table
            // Install cleanup handler to remove object from table on `destroyed`.
            // NOTE: it's not clear to me if the destroyed signal is guaranteed to be delivered if
            // context->thread() != this->thread().  Currently the two live in the same thread but
            // if that changes -- update this code and/or test that the signal is in fact delivered
            // reliably.
            connect(context.get(), &QObject::destroyed, this, [this, rid](QObject *context) {
                // remove context from table and also check it's what we expect
                if (const auto ref = reqContextTable.take(rid).lock(); ref && ref.get() != context) {
                    // this should never happen
                    Error() << "Context in table with rid " << rid << " differs from what we expected! FIXME!";
                }
                if constexpr (debugDeletes)
                    DebugM(__func__, " - req context table size now: ", reqContextTable.size());
            });
        } else {
            // this indicates a bug in this code
            emit context->fail(rid, QString("Request id %1 already exists in table! FIXME!").arg(rid.toString()));
            return;
        }

        /* Note the "Results" and "Error" responses are handled in on_Message and on_ErrorMessage
           by looking up the proper context object in the hash table directly. */

        // Connect some signals to trap the situation where things may go wrong.
        // The capture of `context` is a weak ptr to not keep it alive longer than it needs to stay alive.
        using WeakPtr = std::weak_ptr<BitcoinDMgrHelper::ReqCtxObj>;
        context->conns +=
        connect(bd, &BitcoinD::lostConnection, context.get(), [weakContext = WeakPtr(context), rid](AbstractConnection *){
            if (auto context = weakContext.lock()) {
                emit context->fail(rid, "connection lost");
                context->killConns(); // remove these two connections right away to prevent duplicate fail() delivery
            }
        });
        context->conns +=
        connect(bd, &QObject::destroyed, context.get(), [weakContext = WeakPtr(context), rid](QObject *){
            if (auto context = weakContext.lock()) {
                emit context->fail(rid, "bitcoind client deleted");
                context->killConns(); // remove these two connections right away to prevent duplicate fail() delivery
            }
        });

        bd->sendRequest(rid, method, params);
    });

    // .. aand.. return right away
}

namespace {
    using ReqCtxResultsOrErrorFunc = decltype(&BitcoinDMgrHelper::ReqCtxObj::results);
}

template <>
void BitcoinDMgr::handleMessageCommon(const RPC::Message &msg, ReqCtxResultsOrErrorFunc resultsOrErrorFunc)
{
    // find message context in map
    auto context = reqContextTable.take(msg.id).lock();
    if (!context) {
        if (msg.method != "ping") { // <--- pings don't go through our req layer so they always come through without a table entry here
            // this can happen in rare cases if the sender object was deleted before bitcoind responded.
            // log the situation but don't warn or anything like that
            DebugM(__func__, " - request id ", msg.id, " method `", msg.method, "` not found in request context table "
                   "(sender object may have already been deleted)");
            ++zombieResponseCtr; // increment this counter for /stats
        }
        return;
    }
    // call member function pointer
    emit (context.get()->*resultsOrErrorFunc)(msg);
    // kill lambdas, weak_ptr captures
    context->killConns();
}

void BitcoinDMgr::on_Message(quint64 bid, const RPC::Message &msg)
{
    TraceM("Msg from: ", bid, " (reqId: ", msg.id, " method: ", msg.method, ")");

    // handle the messsage by looking up the context in the table and emitting the proper signal
    handleMessageCommon(msg, &BitcoinDMgrHelper::ReqCtxObj::results);
}

void BitcoinDMgr::on_ErrorMessage(quint64 bid, const RPC::Message &msg)
{
    DebugM("ErrMsg from: ", bid, " (reqId: ", msg.id, ", method: ", msg.method, ") code=", msg.errorCode(),
           " error=", msg.errorMessage());
    if (msg.errorCode() == bitcoin::RPCErrorCode::RPC_IN_WARMUP) {
        emit inWarmUp(msg.errorMessage());
    }

    // handle the messsage by looking up the context in the table and emitting the proper signal
    handleMessageCommon(msg, &BitcoinDMgrHelper::ReqCtxObj::error);
}


namespace BitcoinDMgrHelper {
    /* static */ std::atomic_int ReqCtxObj::extant{0};
    ReqCtxObj::ReqCtxObj() : QObject(nullptr) { ++extant; }
    ReqCtxObj::~ReqCtxObj() { --extant; }
    void ReqCtxObj::killConns() {
        for (const auto & conn : conns)
            QObject::disconnect(conn);
        conns.clear();
    }
}


/* --- BitcoinD --- */
auto BitcoinD::stats() const -> Stats
{
    auto m = RPC::HttpConnection::stats().toMap();
    m["lastPeerError"] = badAuth ? "Auth Failure" : lastPeerError;
    m.remove("nErrorsSent"); // should always be 0
    m.remove("nNotificationsSent"); // again, 0
    m.remove("nResultsSent"); // again, 0
    return m;
}

BitcoinD::BitcoinD(const QString &host, quint16 port, const QString & user, const QString &pass, qint64 maxBuffer_)
    : RPC::HttpConnection(RPC::MethodMap{}, newId(), nullptr, maxBuffer_), host(host), port(port)
{
    static int N = 1;
    setObjectName(QString("BitcoinD.%1").arg(N++));
    _thread.setObjectName(objectName());

    setAuth(user, pass);
    setHeaderHost(QString("%1:%2").arg(host).arg(port)); // for HTTP RFC 2616 Host: field
    setV1(true); // bitcoind uses jsonrpc v1
    resetPingTimer(int(PingTimes::Normal)); // just sets pingtime_ms and stale_threshold = pingtime_ms * 2

    connectMiscSignals();
}


BitcoinD::~BitcoinD()
{
    stop();
}

void BitcoinD::connectMiscSignals()
{
    connect(this, &BitcoinD::gotMessage, this, [this]{
        // this hook emits "authenticated" as soon as we get a good result message via 'do_ping' initiated from 'on_connected' below
        if (needAuth || badAuth) {
            needAuth = badAuth = false;
            emit authenticated(this);
        }
    });
}

bool BitcoinD::isGood() const
{
    return !badAuth && !needAuth && RPC::HttpConnection::isGood();
}

void BitcoinD::on_started()
{
    ThreadObjectMixin::on_started();

    { // setup the "reconnect timer"
        constexpr auto reconnectTimer = "reconnectTimer";
        const auto SetTimer = [this] {
            callOnTimerSoon(5000, reconnectTimer, [this]{
                if (!isGood()) {
                    DebugM(prettyName(), " reconnecting...");
                    reconnect();
                    return true; // keep the timer alive
                }
                return false; // kill timer
            });
        };
        conns += connect(this, &BitcoinD::lostConnection, this, [SetTimer]{
            Log() << "Lost connection to bitcoind, will retry every 5 seconds ...";
            SetTimer();
        });
        conns += connect(this, &BitcoinD::authFailure, this, [SetTimer, this] {
            Error() << "Authentication to bitcoind rpc failed. Please check the rpcuser and rpcpass are correct and restart!";
            badAuth = true;
            SetTimer();
        });
        conns += connect(this, &BitcoinD::authenticated, this, [this] { stopTimer(reconnectTimer); });

        SetTimer();
    }

    reconnect();
}

void BitcoinD::reconnect()
{
    if (socket) delete socket;
    socket = new QTcpSocket(this);
    socketConnectSignals();
    socket->connectToHost(host, port);
}

void BitcoinD::on_connected()
{
    RPC::HttpConnection::on_connected();
    lastGood = Util::getTime();
    nSent = nReceived = 0;
    lastPeerError.clear();
    lastSocketError.clear();
    badAuth = false;
    needAuth = true;
    emit connected(this);
    // note that the 'authenticated' signal is only emitted after good auth is confirmed via the reply from the do_ping below
    do_ping();
}

void BitcoinD::do_ping()
{
    if (isStale()) {
        DebugM("Stale connection, reconnecting.");
        reconnect();
    } else
        emit sendRequest(newId(), "ping");
}

void BitcoinD::resetPingTimer(int time_ms)
{
    auto setter = [time_ms, this] {
        if (pingtime_ms != time_ms)
            DebugM("Changed pingtime_ms: ", time_ms);
        pingtime_ms = time_ms;
        stale_threshold = pingtime_ms * 2;
        if (pingtime_ms > 0) {
            resetTimerInterval(pingTimer, pingtime_ms); // no-op if pingTimer not active
        } else {
            stopTimer(pingTimer); // no-op if pingTimer not active
        }
    };
    // thread guard -- can only do the above in "this" object's thread
    if (this->thread() == QThread::currentThread())
        setter();
    else
        Util::AsyncOnObject(this, setter, 0);
}


QVariantMap BitcoinDInfo::toVariandMap() const
{
    QVariantMap ret;
    ret["version"] = version.toString(true);
    ret["subversion"] = subversion;
    ret["warnings"] = warnings;
    ret["relayfee"] = relayFee;
    return ret;
}
