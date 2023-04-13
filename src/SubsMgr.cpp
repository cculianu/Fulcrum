//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "SubsMgr.h"
#include "Util.h"

#include "bitcoin/hash.h"

#include <QThread>

#include <algorithm>
#include <cmath>
#include <mutex>

/* static */ std::atomic_int64_t Subscription::nGlobalInstances = 0;

Subscription::Subscription(const HashX &k)
    : QObject(nullptr), key(k)
{
    ++nGlobalInstances;
}

Subscription::~Subscription()
{
    if (const auto n = --nGlobalInstances; UNLIKELY(n < 0))
        // should never happen
        Error() << "BUG! Subscription::nGlobalInstances (" << n << ") is negative! FIXME!";
}

namespace {
    using LockGuard = std::lock_guard<std::mutex>;
    constexpr int kNotifTimerIntervalMS = 500; ///< we notify in batches at most once every 500ms .. this delay is ok because anyway we only receive mempool updates at most once per second.
    constexpr const char *kNotifTimerName = "NotificationTimer";
    constexpr int kRemoveZombiesTimerIntervalMS = 60000; ///< we remove zombie subs entries every minute
    constexpr const char *kRemoveZombiesTimerName = "ZombieTimer";

    constexpr bool debugPrint = false; ///< some of the more performance critical code in this file has its trace/debug prints compiled in or out based on this flag.
}

struct SubsMgr::Pvt
{
    std::mutex mut;
    std::unordered_map<HashX, SubsMgr::SubRef, HashHasher> subs;
    std::unordered_set<HashX, HashHasher> pendingNotificatons;

    static std::atomic_int64_t nGlobalClientSubsActive;
    std::atomic_int64_t nClientSubsActive{0};
    std::atomic_uint64_t cacheHits{0}, cacheMisses{0};

    static constexpr size_t kSubsReserveSize = 16384;
    Pvt() {
        subs.reserve(kSubsReserveSize);
        pendingNotificatons.reserve(kRecommendedPendingNotificationsReserveSize);
    }
    /// call this with the lock held
    inline void clearPending_nolock() {
        decltype(pendingNotificatons) emptySet;
        pendingNotificatons.swap(emptySet);
        pendingNotificatons.reserve(kRecommendedPendingNotificationsReserveSize);
    }
};

/*static*/ std::atomic_int64_t SubsMgr::Pvt::nGlobalClientSubsActive{0};

SubsMgr::LimitReached::~LimitReached() {} // vtable

SubsMgr::SubsMgr(const std::shared_ptr<const Options> & o, Storage *s, const QString &n)
    : Mgr(nullptr), options(o), storage(s), p(std::make_unique<SubsMgr::Pvt>())
{
    setObjectName(n);
    _thread.setObjectName(n);
}
SubsMgr::~SubsMgr() { Debug() << __func__; cleanup(); }
void SubsMgr::startup() {
    if (UNLIKELY(!storage || !options))
        // paranoia
        throw BadArgs("SubsMgr constructed with nullptr for either options or storage! FIXME!");
    start();
}
void SubsMgr::cleanup() {
    if (_thread.isRunning())
         Debug() << "Stopping " << objectName() << " ...";
    stop();
}

ScriptHashSubsMgr::~ScriptHashSubsMgr() {} // for vtable


void SubsMgr::on_started()
{
    ThreadObjectMixin::on_started();
    conns += connect(this, &SubsMgr::queueNoLongerEmpty, this, [this]{
        callOnTimerSoonNoRepeat(kNotifTimerIntervalMS, kNotifTimerName, [this]{ doNotifyAllPending(); }, false, Qt::TimerType::PreciseTimer);
    }, Qt::QueuedConnection);
    conns += connect(this, &SubsMgr::requestRemoveZombiesSoon, this, [this](int when_ms) {
        // remove zombies in when_ms, outside normal rate-limiting timer
        QTimer::singleShot(std::max(when_ms, 0), this, [this]{ removeZombies(true /* forced */); });
    }, Qt::QueuedConnection);
    callOnTimerSoon(kRemoveZombiesTimerIntervalMS, kRemoveZombiesTimerName, [this]{ removeZombies(false); return true;}, true);
}

void SubsMgr::on_finished()
{
    stopTimer(kNotifTimerName);
    stopTimer(kRemoveZombiesTimerName);
    ThreadObjectMixin::on_finished();
}
// this runs in our thread
void SubsMgr::doNotifyAllPending()
{
    const Tic t0;
    size_t ctr = 0, ctrSH = 0;
    bool emitQueueEmpty = false;
    const bool useCache = useStatusCache();
    std::vector<SubRef> pending; // this ends up being the intersection of the sh's in p->pendingNotifications and p->subs
    {
        LockGuard g(p->mut);
        const bool pendingWasEmpty = p->pendingNotificatons.empty();
        if (!pendingWasEmpty && !p->subs.empty()) {
            const size_t pnsize = p->pendingNotificatons.size(), subsize = p->subs.size();
            pending.reserve(std::min(pnsize, subsize));
            // The loop should always loop through the smaller structure, as a performance optimization, hence
            // this `if` here.
            if (pnsize < subsize) {
                // p->pendingNotifications is smaller, loop over that, doing constant-time checks against the larger
                // p->subs for each scripthash.
                // Under current BCH typical network usage, this is usually the more likely branch, unless blocks are
                // full or the network is very busy, in which case the other branch is more likely.
                for (const auto & sh : p->pendingNotificatons) {
                    if (const auto it = p->subs.find(sh); it != p->subs.end()) {
                        pending.push_back( it->second );
                    }
                }
            } else {
                // p->subs is smaller (or equal), loop over that, doing constant-time checks against the larger
                // p->pendingNotification for each scripthash.
                for (const auto & [sh, subref] : p->subs) {
                    if (p->pendingNotificatons.count(sh)) {
                        pending.push_back( subref );
                    }
                }
            }
        }
        p->clearPending_nolock();
        emitQueueEmpty = !pendingWasEmpty; // emit queueEmpty below only if it wasn't empty before
    }
    if (emitQueueEmpty) {
        // defensive programming nit, let's emit the signal with no locks held in case somebody someday connects this
        // signal via a direct connection to a slot in this thread that then tries to take the same lock.
        emit queueEmpty();
    }
    // at this point we got all the subrefs for the scripthashes that changed.. and the lock is released .. now run through them all and notify each
    for (const auto & sub : pending) {
        HashX sh; // we take a copy of this from sub in the block below with the lock held for paranoia purposes (technically we could take it now, though)
        ++ctrSH;
        {
            LockGuard g(sub->mut);
            if (sub->subscribedClientIds.empty()) {
                // We need to clear the "last status notified" because we have no clients now and we are skipping a
                // notification. The "last status notified"'s primary purpose is to prevent sending existing clients
                // dupe notifications (if status didn't change). Since we are skipping a notification, we must clear
                // it to invalidate it.
                sub->lastStatusNotified.reset();
                sub->cachedStatus.reset(); // forget the cached status as it is now very definitely wrong.
                continue;
            } // else..
            sh = sub->key;
        }
        // ^^^ We must release the above lock here temporarily because we do not want to hold it while also implicitly
        // grabbing the Storage 'blocksLock' below for getFullStatus* (storage->getHistory acquires that lock in
        // read-only mode).
        try {
            const auto status = getFullStatus(sh);
            // Now, re-acquire sub lock. Temporarily having released it above should be fine for our purposes, since the
            // above empty() check was only a performance optimization and the predicate not holding for the duration of
            // this code block is fine. In the unlikely event that a sub lost its clients while the lock was released, the
            // below emit sub->statusChanged(...) will just be a no-op.
            LockGuard g(sub->mut);
            const bool doemit = !sub->lastStatusNotified.has_value() || sub->lastStatusNotified != status;
            // we basically cache 2 statuses -- one for what we return immediately to new subs and one to
            // keep track of not notifying twice on the same sub.
            sub->lastStatusNotified = status;
            if (useCache)
                sub->cachedStatus = status;
            if (doemit) {
                const auto nClients = sub->subscribedClientIds.size();
                ctr += nClients;
                DebugM("Notifying ", nClients, Util::Pluralize(" client", nClients), " of status for ", Util::ToHexFast(sh));
                sub->updateTS();
                emit sub->statusChanged(sh, status);
            }
        } catch (const std::exception & e) {
            // Defensive programming here in case getFullStatus() or other functions throw (extremely unlikely)
            Error() << "ERROR: Caught exception attempting to calculate status for subscribable: " << sh.toHex();
        }
    }
    if (ctr || ctrSH) {
        DebugM(__func__, ": ", ctr, Util::Pluralize(" client", ctr), ", ", ctrSH, Util::Pluralize(" subscribable", ctrSH),
               " in ", t0.msecStr(4), " msec");
    }
}

void SubsMgr::enqueueNotifications(std::unordered_set<HashX, HashHasher> &&s)
{
    if (s.empty()) return;
    LockGuard g(p->mut);
    const bool wasEmpty = p->pendingNotificatons.empty();
    p->pendingNotificatons.merge(std::move(s));
    if (wasEmpty)
        emit queueNoLongerEmpty();
}

void SubsMgr::unsubscribeClientsForKeys(const std::unordered_set<HashX, HashHasher> & keys)
{
    if (UNLIKELY(!dynamic_cast<DSProofSubsMgr *>(this))) {
        // this only is set up to work only for the DSProofsSubMgr currently. Print error to log and return.
        Error() << "INTERNAL ERROR: " << " currently " << __func__ << " is only supported for the DSProofSubsMgr. FIXME!";
        return;
    }
    if (keys.empty()) return;
    const Tic t0;
    std::vector<SubRef> matchedSubs;
    matchedSubs.reserve(std::min(keys.size(), kRecommendedPendingNotificationsReserveSize));
    size_t subsSize;
    {
        LockGuard g(p->mut);
        subsSize = p->subs.size();
        if (keys.size() < subsSize) {
            // iterate over keys
            for (const auto &key : keys)
                if (auto it = p->subs.find(key); it != p->subs.end())
                    matchedSubs.push_back(it->second);
        } else {
            // iterate over subs
            for (const auto &[key, sub] : p->subs)
                if (keys.count(key))
                    matchedSubs.push_back(sub);
        }
    }
    // now, emit the signal with locks not held
    for (const auto &sub : matchedSubs) {
        {
            LockGuard g(sub->mut);
            // clear cached status since this sub is going away very sooon because the associated txid is gone;
            // as such, if a new sub comes in right after this runs, we want to return a fresh status not a cached one.
            sub->cachedStatus.reset();
        }
        emit sub->unsubscribeRequested(); // will run in client thread(s) for subscribed client(s)
    }
    if (!matchedSubs.empty())
        DebugM(__func__, ": enqueued unsubscribe for ", matchedSubs.size(), "/", subsSize, " txids in ", t0.msecStr(), " msec");
}


auto SubsMgr::makeSubRef(const HashX &key) -> SubRef
{
    static const auto Deleter = [](Subscription *s){ s->deleteLater(); };
    SubRef ret(new Subscription(key), Deleter);
    if (QThread::currentThread() != this->thread()) {
        ret->moveToThread(this->thread());
    }
    return ret;
}

bool SubsMgr::isSubsLimitExceeded(int64_t & limit) const {
    limit = options->maxSubsGlobally;
    return numGlobalSubscriptions() >= limit;
}

// may throw LimitReached
auto SubsMgr::getOrMakeSubRef(const HashX &key) -> std::pair<SubRef, bool>
{
    if (int64_t limit; UNLIKELY(isSubsLimitExceeded(limit)))
        // Note we check the limit against all subs (including zombies) to prevent a DoS attack that circumvents
        // the limit by repeatedly creating subs, disconnecting, reconnecting, creating a different set of subs, etc.
        throw LimitReached(QString("Subs limit of %1 has been reached").arg(limit));

    std::pair<SubRef, bool> ret;
    LockGuard g(p->mut);

    if (auto it = p->subs.find(key); it != p->subs.end()) {
        ret.first = it->second;
        ret.second = false; // was not new
    } else {
        ret.first = makeSubRef(key);
        p->subs[key] = ret.first;
        ret.second = true; // was new
    }
    return ret;
}

auto SubsMgr::findExistingSubRef(const HashX &key) const -> SubRef
{
    SubRef ret;
    LockGuard g(p->mut);
    if (auto it = p->subs.find(key); it != p->subs.end())
        ret = it->second;
    return ret;
}

auto SubsMgr::subscribe(RPC::ConnectionBase *c, const HashX &key, const StatusCallback &notifyCB) -> SubscribeResult
{
    const auto t0 = debugPrint ? Util::getTimeNS() : 0LL;
    const bool useCache = useStatusCache();
    if (UNLIKELY(!notifyCB))
        throw BadArgs("SubsMgr::subscribe must be called with a valid notifyCB. FIXME!");

    SubscribeResult ret = { false, {} };
    auto [sub, wasnew] = getOrMakeSubRef(key); // may throw LimitReached
    {
        LockGuard g(sub->mut);
        if (!wasnew && sub->subscribedClientIds.count(c->id)) {
            // already had a sub for this client, disconnect it because we will re-add the new functor below
            bool res = QObject::disconnect(sub.get(), &Subscription::statusChanged, c, nullptr);
            if constexpr (debugPrint) Debug() << "Existing sub disconnected signal: " << (res ? "ok" : "not ok!");
        } else {
            // did not have a sub for this client, add its id and also add the destroyed signal to clean up the id
            // upon client object destruction
            ret.first = true;
            sub->subscribedClientIds.insert(c->id);
            auto conn = QObject::connect(c, &QObject::destroyed, sub.get(), [sub=sub.get(), id=c->id, this](QObject *){
                --p->nClientSubsActive;
                --Pvt::nGlobalClientSubsActive;
                LockGuard g(sub->mut);
                sub->subscribedClientIds.erase(id);
                sub->updateTS();
                //Debug() << "client id " << id << " destroyed, implicitly unsubbed from " << sub->key.toHex()
                //        << ", " << sub->subscribedClientIds.size() << " sub(s) remain";
            });
            if (UNLIKELY(!conn))
                throw InternalError("SubsMgr::subscribe: Failed to make the 'destroyed' connection for the client object! FIXME!");
            ++p->nClientSubsActive;
            ++Pvt::nGlobalClientSubsActive;
        }
        if (useCache) {
            // Copy the last known StatusHash to caller. This is guaranteed to either be a recent status since the
            // last notification sent (if known), or !has_value if not known.
            ret.second = sub->cachedStatus;
        }
        sub->updateTS(); // our basic 'mtime'
        auto conn = QObject::connect(sub.get(), &Subscription::statusChanged, c, notifyCB, Qt::QueuedConnection); // QueuedConnection paranoia in case client 'c' "lives" in our thread
        if (UNLIKELY(!conn))
            throw InternalError("SubsMgr::subscribe: Failed to make the 'statusChanged' connection to the notifyCB functor! FIXME!");
    }

    if (useCache) {
        if (ret.second.has_value())
            ++p->cacheHits;
        else
            ++p->cacheMisses;
    }

    if constexpr (debugPrint) {
        const auto elapsed = Util::getTimeNS() - t0;
        Debug() << "subscribed " << Util::ToHexFast(key) << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    }
    return ret;
}

auto DSProofSubsMgr::subscribe(RPC::ConnectionBase *c, const HashX &key, const StatusCallback &notifyCB) -> SubscribeResult
{
    auto ret = SubsMgr::subscribe(c, key, notifyCB);
    if (ret.first) { // this sub <-> client association is new, attach signal for unsubscribeAllClients() to work
        if (SubRef sub = findExistingSubRef(key)) {
            auto conn = QObject::connect(sub.get(), &Subscription::unsubscribeRequested, c, [this, c, key, notifyCB] {
                if (notifyCB) {
                    // tell client the sub is gone -- send them an empty status immediately
                    notifyCB(key, {});
                }
                DebugM("unsubscribeRequested signal invoked lambda, proceeding to unsubscribe client ", c->id,
                       " for key ", key.toHex(), " ...");
                // just call unsubscribe. this will zombify this sub and it will be deleted
                unsubscribe(c, key, false /* don't update ts */);
            });
            if (UNLIKELY(!conn)) {
                // this should never happen
                Error() << "INTERNAL ERROR: failed to make the connecttion to the 'unsubscribeRequested' signal for client " << c->id << ". FIXME!";
            }
        } else {
            // should never happen
            Error() << "INTERNAL ERROR: sub immediately lost its subref for " << key.toHex() << ". FIXME!";
        }
    }
    return ret;
}

void SubsMgr::maybeCacheStatusResult(const HashX &sh, const SubStatus &status)
{
    if (!status.has_value() || !useStatusCache())
        return;
    if (auto *ba = status.byteArray(); ba && ba->length() != HashLen && !ba->isEmpty())
        // we only allow empty (null) or 32 bytes.. otherwise reject
        return;
    else if (auto *dsp = status.dsproof(); dsp && !dsp->isComplete() && !dsp->isEmpty())
        // we only allow empty (default constructred) DSProofs or ones that are isComplete(), otherwise reject
        return;
    // else .. we always cache status.blockHeight() ..
    SubRef sub = findExistingSubRef(sh);
    if (sub) {
        LockGuard g(sub->mut);
        if (!sub->lastStatusNotified.has_value() && !sub->cachedStatus.has_value())
            sub->cachedStatus = status;
    }
}

bool SubsMgr::unsubscribe(RPC::ConnectionBase *c, const HashX &key, bool updateTS)
{
    bool ret = false;
    const auto t0 = debugPrint ? Util::getTimeNS() : 0LL;
    SubRef sub = findExistingSubRef(key);
    if (sub) {
        // found
        LockGuard g(sub->mut);
        if (auto it = sub->subscribedClientIds.find(c->id); it != sub->subscribedClientIds.end()) {
            sub->subscribedClientIds.erase(it);
            if (updateTS) sub->updateTS();
            QObject::disconnect(sub.get(), &Subscription::statusChanged, c, nullptr);
            QObject::disconnect(c, &QObject::destroyed, sub.get(), nullptr);
            QObject::disconnect(sub.get(), &Subscription::unsubscribeRequested, c, nullptr);
            ret = true;
            --p->nClientSubsActive;
            --Pvt::nGlobalClientSubsActive;
        }
    }
    if constexpr (debugPrint) {
        const auto elapsed = Util::getTimeNS() - t0;
        Debug() << int(ret) << " unsubscribed " << Util::ToHexFast(key) << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    }
    return ret;
}

int64_t SubsMgr::numActiveClientSubscriptions() const { return p->nClientSubsActive; }
int64_t SubsMgr::numScripthashesSubscribed() const {
    LockGuard g(p->mut);
    return int64_t(p->subs.size());
}

/*static*/
int64_t SubsMgr::numGlobalActiveClientSubscriptions() { return Pvt::nGlobalClientSubsActive.load(); }

std::pair<bool, bool> SubsMgr::globalSubsLimitFlags() const
{
    constexpr double factor = .8;
    const auto thresh = int64_t(std::round(options->maxSubsGlobally * factor));
    return { numGlobalActiveClientSubscriptions() > thresh, numGlobalSubscriptions() > thresh };
}

namespace {
// assumption: `hist` is not empty!
inline QByteArray optimizedStatusHashCalc(const Storage::History &hist) {
    /*
    // This is the original implementation: it is 2x slower than the optimized version
    QString historyString;
    {
        QTextStream ts(&historyString, QIODevice::WriteOnly);
        for (const auto & item : hist) {
            ts << Util::ToHexFast(item.hash) << ":" << item.height << ":";
        }
    }
    */
    // optimized version:
    static_assert (sizeof(decltype(hist.front().height)) <= 4, "Assumption below is for at most 32-bit heights");
    constexpr size_t WorstCaseElementSize = HashLen*2 + 11 + 2; // worse case: 11 bytes max for sign & int, 2 colons, plus 64 bytes for hashHex
    bitcoin::CHash256 hasher(true /* hash once */);
    for (const auto & item : hist) {
        constexpr size_t BufSize = WorstCaseElementSize + 10; // leave a little room (this happens to align sbuf to cache on 64-bit)
        Util::AsyncSignalSafe::SBuf<BufSize> sbuf; // fast stack-based buffer
        if (const auto hexLen = item.hash.length() * 2; LIKELY(hexLen <= HashLen * 2)) {
            Util::ToHexFastInPlace(item.hash, sbuf.strBuf.data(), hexLen);
            sbuf.len += hexLen;
        }
        sbuf.append(':').append(item.height).append(':');
        hasher.Write(reinterpret_cast<const uint8_t *>(std::as_const(sbuf.strBuf).data()), sbuf.len);
    }

    static_assert (hasher.OUTPUT_SIZE == HashLen, "Assumption is that HashLen is the sha256 output size (32 bytes)");
    QByteArray ret{HashLen, Qt::Uninitialized};
    hasher.Finalize(reinterpret_cast<uint8_t *>(ret.data()));

    // status is non-reversed, single sha256 (32 bytes)
    return ret;
}
} // namespace

auto ScriptHashSubsMgr::getFullStatus(const HashX &sh) const -> SubStatus
{
    const Tic t0;
    QByteArray ret;
    const auto hist = storage->getHistory(sh, true, true);
    if (hist.empty())
        // no history, return an empty QByteArray
        return ret;
    ret = optimizedStatusHashCalc(hist);
    constexpr qint64 kTookKindaLongNS = 7'500'000LL; // 7.5mec -- if it takes longer than this, log it to debug log, otherwise don't as this can get spammy.
    if (t0.nsec() > kTookKindaLongNS) {
        DebugM("full status for ",  Util::ToHexFast(sh), " ", hist.size(), " items in ", t0.msecStr(4), " msec");
    }
    return ret;
}

void SubsMgr::removeZombies(bool forced)
{
    const Tic t0;
    int ctr = 0;
    const auto now = Util::getTime();
    LockGuard g(p->mut);
    const auto total = p->subs.size();
    for (auto it = p->subs.begin(); it != p->subs.end(); /* */) {
        SubRef sub = it->second; // take a copy to increment refct so it doesn't get deleted before we unlock it (erase() below)...
        if (UNLIKELY(!sub)) { // paranoia
            Fatal() << "A SubRef was null in " << __func__ << ". FIXME!";
            return;
        }
        LockGuard g(sub->mut);
        if (sub->subscribedClientIds.empty() && (forced || now - sub->tsMsec > kRemoveZombiesTimerIntervalMS)) {
            ++ctr;
            it = p->subs.erase(it);
        } else
            ++it;
    }
    if (ctr) {
        if (p->subs.load_factor() <= 0.5)
            p->subs.rehash(p->kSubsReserveSize); // shrink_to_fit down toward kSubsReserveSize (reclaim memory)
        DebugM(objectName(), ": Removed ", ctr, " zombie ", Util::Pluralize("sub", ctr), " out of ", total,
               " in ", t0.msecStr(4), " msec");
    }
}

std::unordered_set<HashX, HashHasher> SubsMgr::nonZombieKeysOlderThan(const int64_t msec) const
{
    std::unordered_set<HashX, HashHasher> ret;
    const auto now = Util::getTime();
    LockGuard g(p->mut);
    for (const auto & [key, sub] : p->subs) {
        LockGuard g(sub->mut);
        if (!sub->subscribedClientIds.empty() && now - sub->tsMsec > msec)
            ret.insert(key); // it is not a zombie and it's older than msec, add to return set
    }
    return ret;
}


auto SubsMgr::debug(const StatsParams &params) const -> Stats
{
    QVariant ret;
    if (params.contains("subs") || params.contains("dspsubs") || params.contains("txsubs")) {
        QVariantMap subs;
        qulonglong collisions{}, largestBucket{}, medianBucket{}, medianNonzeroBucket{};
        {
            LockGuard g(p->mut);
            for (const auto & [sh, sub] : p->subs) {
                QVariantMap m2;
                {
                    LockGuard g2(sub->mut);
                    m2["count"] = qlonglong(sub->subscribedClientIds.size());
                    m2["lastStatusNotified"] = sub->lastStatusNotified.toVariant();
                    m2["cachedStatus"] = sub->cachedStatus.toVariant();
                    m2["idleSecs"] = (Util::getTime() - sub->tsMsec)/1e3;
                    const auto & clients = sub->subscribedClientIds;
#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
                    // Qt < 5.14 lacks the ranged constructors for containers so we must do this.
                    m2["clientIds"] = QVariantList::fromStdList(Util::toList<std::list<QVariant>>(clients));
#else
                    m2["clientIds"] = Util::toList<QVariantList>(clients);
#endif
                }
                subs[QString(Util::ToHexFast(sh))] = m2;
            }
            std::tie(collisions, largestBucket, medianBucket, medianNonzeroBucket) = Util::bucketStats(p->subs);
        }
        QVariantMap m;
        m["subs"] = std::move(subs);
        auto stats = this->stats().toMap();
        stats["subscriptions bucket collisions"] = collisions;
        stats["subscriptions largest bucket"] = largestBucket;
        stats["subscriptions median bucket"] = medianBucket;
        stats["subscriptions median non-zero bucket"] = medianNonzeroBucket;
        m["stats"] = std::move(stats);
        ret = std::move(m);
    }
    return ret;
}

auto SubsMgr::stats() const -> Stats
{
    QVariantMap ret;
    {
        LockGuard g(p->mut);
        ret["subscriptions load factor"] = p->subs.load_factor();
        ret["subscriptions bucket count"] = qulonglong(p->subs.bucket_count());
        QVariantList l;
        for (const auto & sh : p->pendingNotificatons) {
            l.push_back(Util::ToHexFast(sh));
        }
        ret["pendingNotifications"] = l;
    }
    ret["subscriptions cache hits"] = qlonglong(p->cacheHits.load()); // atomic, no lock needed
    ret["subscriptions cache misses"] = qlonglong(p->cacheMisses.load()); // atomic, no lock needed
    // these below 2 take the above lock again so we do them without the lock held
    ret["Num. active client subscriptions"] = qlonglong(numActiveClientSubscriptions());
    ret["Num. unique scripthashes subscribed (including zombies)"] = qlonglong(numScripthashesSubscribed());
    ret["Num. active client subscriptions (global)"] = qlonglong(numGlobalActiveClientSubscriptions());
    ret["Num. unique subscriptions (global; including zombies)"] = qlonglong(numGlobalSubscriptions());
    ret["activeTimers"] = activeTimerMapForStats();
    return ret;
}

DSProofSubsMgr::~DSProofSubsMgr() {} // for vtable

namespace {
    inline constexpr int64_t kExpireSubsNotInMempoolAgeMsec = 150'000; ///< we expire subs >2.5 minutes old that point to txids not in mempool
    inline constexpr auto kExpireSubsNotInMempoolTimerName = "ExireSubsNotInMempoolTimer";
}

void DSProofSubsMgr::on_started()
{
    SubsMgr::on_started();
    callOnTimerSoon(kExpireSubsNotInMempoolAgeMsec / 2, kExpireSubsNotInMempoolTimerName, [this]{ expireSubsNotInMempool(); return true;}, true);
}
void DSProofSubsMgr::on_finished()
{
    stopTimer(kExpireSubsNotInMempoolTimerName);
    SubsMgr::on_finished();
}

void DSProofSubsMgr::expireSubsNotInMempool()
{
    const Tic t0;
    auto candidates = nonZombieKeysOlderThan(kExpireSubsNotInMempoolAgeMsec);
    if (!candidates.empty()) {
        auto [mempool, lock] = storage->mempool(); // shared, read-only lock
        if (candidates.size() < mempool.txs.size()) {
            // loop over candidates
            for (auto it = candidates.begin(); it != candidates.end(); /* see below */) {
                if (mempool.txs.count(*it)) {
                    // candidate has a mempool tx -- erase
                    it = candidates.erase(it);
                } else {
                    // candidate has no mempool tx, keep!
                    ++it;
                }
            }
        } else {
            // loop over mempool
            for (const auto &[txid, tx] : mempool.txs)
                candidates.erase(txid); // if txid was in candidates, remove it (candidates must not be in mempool)
        }
    }
    if (!candidates.empty()) {
        DebugM(__func__, ": ", candidates.size(), " txid subscriptions do not correspond to any mempool tx and are >",
               QString::number(kExpireSubsNotInMempoolAgeMsec / 1e3, 'f', 1), " secs old, forcing unsubscribe now",
               " (elapsed: ", t0.msecStr(), " msec)");
        unsubscribeClientsForKeys(candidates);
    }
}

auto DSProofSubsMgr::getFullStatus(const HashX &txHash) const -> SubStatus
{
    auto [mempool, lock] = storage->mempool();
    if (auto *dsproof = mempool.dsps.bestProofForTx(txHash))
        return *dsproof;
    return DSProof{}; // a SubStatus with a .isEmpty() indicates no proof for this txhash
}

TransactionSubsMgr::~TransactionSubsMgr() {}

SubStatus TransactionSubsMgr::getFullStatus(const HashX &txHash) const
{
    return storage->getTxHeight(txHash);
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "BlockProcTypes.h"
#include <utility>
#include <vector>

namespace {
    void testStatusHash() {
        constexpr std::size_t N = Options::defaultMaxHistory * 2;
        Log() << "Generating " << N << " random history items ...";
        using History = Storage::History;
        using HistoryItem = Storage::HistoryItem;
        History hist;
        hist.reserve(N);
        // append a few special-cases to ensure correctness at corner cases
        hist.push_back(HistoryItem{BTC::Hash160("123132"), std::numeric_limits<decltype(HistoryItem().height)>::min(), {}});
        hist.push_back(HistoryItem{BTC::Hash160("Calin"), std::numeric_limits<decltype(HistoryItem().height)>::max(), {}});
        hist.push_back(HistoryItem{"", 0, {}});
        hist.push_back(HistoryItem{QByteArray{}, 11111, {}});
        hist.push_back(HistoryItem{QByteArray(HashLen, char(-1)), -1, {}});
        while (hist.size() < N) {
            QByteArray hash(HashLen, Qt::Uninitialized);
            int height;
            Util::getRandomBytes(hash.data(), HashLen);
            Util::getRandomBytes(reinterpret_cast<std::byte *>(&height), sizeof(height));
            hist.push_back(HistoryItem{std::move(hash), height, std::nullopt});
        }
        constexpr int iters = 5;
        Log() << "Iterating " << iters << " times ...";
        int64_t elapsedUsecOld{}, elapsedUsecNew{};
        for (int i = 0; i < iters; ++i) {
            if (i > 0) {
                Log() << "Shuffling history items ...";
                Util::shuffle(hist.begin(), hist.end());
            }
            QByteArray s1, s2;
            bool gotbadalloc = false;
            Log() << "Calculating status hash the old way ...";
            try {
                Tic t0;
                QString historyString;
                QTextStream ts(&historyString, QIODevice::WriteOnly);
                for (const auto & [hash, height, xx] : hist) {
                    ts << Util::ToHexFast(hash) << ":" << height << ":";
                }
                // status is non-reversed, single sha256 (32 bytes)
                s1 = BTC::HashOnce(historyString.toUtf8());
                t0.fin();
                elapsedUsecOld += t0.usec<int64_t>();
                Log() << "Elapsed: " << t0.msecStr(6) << " msec";
            } catch (const std::bad_alloc &e) {
                Error() << e.what();
                gotbadalloc = true;
            }

            Log() << "Calculating status hash the new way ...";
            {
                Tic t0;
                s2 = optimizedStatusHashCalc(hist);
                t0.fin();
                elapsedUsecNew += t0.usec<int64_t>();
                Log() << "Elapsed: " << t0.msecStr(6) << " msec";
            }
            if (gotbadalloc) throw Exception("old way threw bad_alloc, aborting");
            if (s1 != s2) throw Exception("results do not compare ok!");
        }
        Log() << "Elapsed totals: old way: " << QString::number(elapsedUsecOld/1e3, 'f', 3) << " msec"
              <<  ", new way: " << QString::number(elapsedUsecNew/1e3, 'f', 3) << " msec";
    }

    const auto t1 = App::registerTest("statushash", testStatusHash);
}
#endif
