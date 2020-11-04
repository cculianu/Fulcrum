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
#include <QSslConfiguration>
#include <QSslSocket>

#include <mutex>
#include <tuple>

namespace {
    enum class PingTimes : int {
        Normal = 10'000,  /**< Normal bitcoind -- we send a ping every 10 seconds */
        BCHD   =  3'333,  /**< bchd has a short idle timeout of 10 secs. 3.333 sec pingtime ensures no dropped conns. */
    };
}

BitcoinDMgr::BitcoinDMgr(const QString &hostName, quint16 port, const QString &user, const QString &pass, bool useSsl)
    : Mgr(nullptr), IdMixin(newId()), hostName(hostName), port(port), user(user), pass(pass), useSsl(useSsl)
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
        client = std::make_unique<BitcoinD>(hostName, port, user, pass, useSsl);

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
            // tell all extant requests being serviced by this BitcoinD about this failure
            notifyFailForRequestsMatchingBitcoinD(static_cast<BitcoinD *>(c) /* guaranteed to be a BitcoinD * */,
                                                  "bitcoind connection lost");
        });
        connect(client.get(), &QObject::destroyed, this, [this](QObject *o){
            // just in case there are any extant requests up when this has been deleted (unlikely)
            notifyFailForRequestsMatchingBitcoinD(static_cast<BitcoinD *>(o) /* guaranteed to be a BitcoinD * */,
                                                  "bitcoind client deleted");
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
    callOnTimerSoon(kRequestTimeoutMS / 2, kRequestTimeoutTimer, [this]{ requestTimeoutChecker(); return true; });
}

void BitcoinDMgr::on_finished()
{
    // Note: There normally aren't any requests in this table when we get here since Controller and Servers are the only
    // objects that issue requests to us, and they are all stopped and deleted before we are stopped.  However, in the
    // interests of correctness, we must make an attempt to clean the req table.  We would ideally emit "fail" here for
    // all active contexts in this table, but that's ill-defined since our thread is about to end, and not supported.
    // Instead we just disconnect all signals for each `context` which should cause their deleters to fire immediately
    // and thus call `context->deleteLater()`, which will get each `context` deleted as soon as our thread ends (which
    // is right after this function returns).
    for (auto it = reqContextTable.begin(); it != reqContextTable.end(); ++it)
        if (auto context = it.value().lock())
            context->disconnect();
    reqContextTable.clear();

    // We need to stop the timer before we call ThreadObjectMixin::on_finished (since that moves us to a different
    // thread), and we need to delete the timer while still in our current calling thread.
    stopTimer(kRequestTimeoutTimer);

    ThreadObjectMixin::on_finished();
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
    m["request zombie count"] = requestZombieCtr;
    m["request timeout count"] = requestTimeoutCtr;
    m["activeTimers"] = activeTimerMapForStats();

    // "bitcoind info"
    m["bitcoind info"] = getBitcoinDInfo().toVariandMap(); // takes lock, makes a copy, releases lock;

    return m;
}


BitcoinD *BitcoinDMgr::getBitcoinD()
{
    if (goodSet.empty())
        return nullptr;
    // Scan round-robin through clients for a client that is both in the goodSet (authenticated) and still has
    // immediate "isGood" status. Note this loop is optimized for the common case where all clients are in the goodSet
    // and so most of the time it will only iterate once.
    for (int i = 0; i < N_CLIENTS; ++i) {
        auto client = clients[ roundRobinCursor++ % N_CLIENTS ].get();
        if (goodSet.count(client->id) && client->isGood())
            return client;
    }
    // nothing found
    return nullptr;
}

namespace {
    struct BitcoinDVersionParseResult {
        bool isBchd, isCore;
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
            return {true, false, version};
        } else {
            const bool isCore = subversion.startsWith("/Satoshi:");
            // regular bitcoind, "version" is reliable
            return {false, isCore, Version(val, Version::BitcoinD)};
        }
    }
}

void BitcoinDMgr::refreshBitcoinDNetworkInfo()
{
    submitRequest(this, newId(), "getnetworkinfo", QVariantList{},
        // success
        [this](const RPC::Message & reply) {
            bool isBchd{}, isCore{};
            {
                const QVariantMap networkInfo = reply.result().toMap();
                // --- EXCLUSIVE-LOCKED SCOPE below this line ---
                std::unique_lock g(bitcoinDInfoLock);
                bitcoinDInfo.subversion = networkInfo.value("subversion", "").toString();
                // try and determine version major/minor/revision
                std::tie(bitcoinDInfo.isBchd, bitcoinDInfo.isCore) = [&networkInfo, this] {
                    bool ok = false;
                    const auto val = networkInfo.value("version", 0).toUInt(&ok);

                    if (ok) {
                        const auto res = parseBitcoindDVersion(val, bitcoinDInfo.subversion);
                        bitcoinDInfo.version = res.version;
                        DebugM("Refreshed version info from bitcoind, version: ", bitcoinDInfo.version.toString(true),
                               ", subversion: ", bitcoinDInfo.subversion);
                        return std::pair{res.isBchd, res.isCore};
                    } else {
                        bitcoinDInfo.version = Version();
                        Warning() << "Failed to parse version info from bitcoind";
                    }
                    return std::pair{false, false};
                }();
                isBchd = bitcoinDInfo.isBchd;
                isCore = bitcoinDInfo.isCore;
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
                bitcoinDInfo.isZeroArgEstimateFee = !isCore && isZeroArgEstimateFee(bitcoinDInfo.version, bitcoinDInfo.subversion);
            } // end lock scope
            // be sure to announce whether remote bitcoind is bitcoin core (this determines whether we use segwit or not)
            emit bitcoinCoreDetection(isCore);
            // next, be sure to set up the ping time appropriately for bchd vs bitcoind
            resetPingTimers(int(isBchd ? PingTimes::BCHD : PingTimes::Normal));
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

bool BitcoinDMgr::isZeroArgEstimateFee() const
{
    std::shared_lock g(bitcoinDInfoLock);
    return bitcoinDInfo.isZeroArgEstimateFee;
}

bool BitcoinDMgr::isBitcoinCore() const
{
    std::shared_lock g(bitcoinDInfoLock);
    return bitcoinDInfo.isCore;
}

Version BitcoinDMgr::getBitcoinDVersion() const
{
    std::shared_lock g(bitcoinDInfoLock);
    return bitcoinDInfo.version;
}

BlockHash BitcoinDMgr::getBitcoinDGenesisHash() const
{
    std::shared_lock g(bitcoinDGenesisHashLock);
    return bitcoinDGenesisHash;
}

/// This is safe to call from any thread. Internally it dispatches messages to this obejct's thread.
/// Does not throw. Results/Error/Fail functions are called in the context of the `sender` thread.
void BitcoinDMgr::submitRequest(QObject *sender, const RPC::Message::Id &rid, const QString & method, const QVariantList & params,
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
            // the below is not technically thread-safe, because it calls objectName(); only enable this branch when testing
            DebugM(context->objectName(), " shptr deleter");
            connect(context, &QObject::destroyed, qApp, [n=context->objectName()]{ DebugM(n, " destroyed"); }, Qt::DirectConnection);
        }
        context->deleteLater(); // thread-safe
    });
    context->setObjectName(QStringLiteral("context for '%1' request id: %2").arg(sender ? sender->objectName() : QString()).arg(rid.toString()));

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
        context->bd = bd; // record which bitcoind is servicing this request for notifyFailForRequestsMatchingBitcoinD()

        // Note: there is a small chance of a race condition here because the `bd` that getBitcoinD() returns runs in
        // its own thread, and it may have "gone bad" from underneath our feet as this code executes by losing its
        // connection; we must defensively handle that situation just in case the "lostConnection" signal is emitted
        // when we are here.  In that very unlikely case, if a request has not completed in 15 seconds, eventually
        // requestTimeoutChecker() will tell the sender that the request timed out.  Also, it is theoretically possible
        // for BitcoinD to just never respond, so we need to be able to handle that situation as well with a guaranteed
        // `fail` signal delivery "some time later".

        // put context in table -- this table is consulted in handleMessageCommon to dispatch
        // the reply directly to this context object
        if (auto it = reqContextTable.find(rid); LIKELY(it == reqContextTable.end() || it.value().expired())) {
            // does not exist in table, put in table
            context->ts = Util::getTime(); // set timestamp; used by requestTimeoutChecker()
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
            // this indicates a bug the calling code; it is sending dupe id's which we do not support
            emit context->fail(rid, QString("Request id %1 already exists in table! FIXME!").arg(rid.toString()));
            return;
        }

        /*
           Notes:
             - The "Results" and "Error" responses are handled in on_Message and on_ErrorMessage by looking up the
               proper context object in the hash table directly.
             - BitcoinD losing connection (lostConnection signal) is handled by notifyFailForRequestsMatchingBitcoinD().
             - BitcoinD being deleted (destroyed signal) is handled by notifyFailForRequestsMatchingBitcoinD().
             - If BitcoinD goes out to lunch for >15 seconds the periodic requestTimeoutChecker() will eventually
               notify the sender of a timeout.
        */

        bd->sendRequest(rid, method, params);
    });

    // .. aand.. return right away
}

void BitcoinDMgr::requestTimeoutChecker()
{
    const auto cutoffTime = Util::getTime() - kRequestTimeoutMS /* 15 seconds */;
    for (auto it = reqContextTable.begin(); it != reqContextTable.end(); ++it) {
        if (auto context = it.value().lock(); context && context->ts < cutoffTime && !context->timedOut) {
            // This context timed out. A rare event but we need to notify the `sender` object
            // so that the sender gets a (belated) "failed" reply to its request, and so that
            // the context may be deleted. Note that this can only occur in circumstances where
            // the bitcoind connection went away while we were preparing the request to bitcoind
            // (see the note above in submitRequest() about the race that may occur there).
            context->timedOut = true; // flag it as having already been handled
            ++requestTimeoutCtr; // increment counter for /stats
            emit context->fail(it.key(), "bitcoind request timed out");
            DebugM(__func__, " - request id ", it.key(), " timed out after ", (Util::getTime()-context->ts)/1e3,
                   " secs without a response from bitcoind (possibly because the connection was lost while we were"
                   " preparing the request, or bitcoind may have hung)");
        }
    }
}

void BitcoinDMgr::notifyFailForRequestsMatchingBitcoinD(const BitcoinD *bd, const QString &errorMessage)
{
    for (auto it = reqContextTable.begin(); it != reqContextTable.end(); ++it)
        if (auto context = it.value().lock(); context && context->bd == bd)
            emit context->fail(it.key(), errorMessage);
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
        if (msg.method != QStringLiteral("ping")) { // <--- pings don't go through our req layer so they always come through without a table entry here
            // this can happen in rare cases if the sender object was deleted before bitcoind responded.
            // log the situation but don't warn or anything like that
            DebugM(__func__, " - request id ", msg.id, " method `", msg.method, "` not found in request context table "
                   "(sender object may have already been deleted)");
            ++requestZombieCtr; // increment this counter for /stats
        }
        return;
    }
    // call member function pointer
    emit (context.get()->*resultsOrErrorFunc)(msg);
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

BitcoinD::BitcoinD(const QString &host, quint16 port, const QString & user, const QString &pass, bool useSsl_, qint64 maxBuffer_)
    : RPC::HttpConnection(RPC::MethodMap{}, newId(), nullptr, maxBuffer_), host(host), port(port), useSsl(useSsl_)
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
    if (useSsl) {
        // remote bitcoind expects https (--bitcoind-tls CLI option); usually this is only for bchd
        QSslSocket *ssl;
        socket = ssl = new QSslSocket(this);

        auto conf = ssl->sslConfiguration();
        conf.setPeerVerifyMode(QSslSocket::PeerVerifyMode::VerifyNone);
        conf.setProtocol(QSsl::SslProtocol::AnyProtocol);
        ssl->setSslConfiguration(conf);

        socketConnectSignals();
        connect(ssl, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), ssl, [ssl](auto errs) {
            for (const auto & err : errs)
                DebugM("Ignoring SSL error for ", ssl->peerName(), ": ", err.errorString());
            ssl->ignoreSslErrors();
        });

        ssl->connectToHostEncrypted(host, port);
    } else {
        // regular http bitcoind (default)
        socket = new QTcpSocket(this);
        socketConnectSignals();
        socket->connectToHost(host, port);
    }
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
    ret["isZeroArgEstimateFee"] = isZeroArgEstimateFee;
    ret["isBchd"] = isBchd;
    ret["isCore"] = isCore;
    return ret;
}
