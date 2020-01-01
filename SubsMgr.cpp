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
#include "SubsMgr.h"
#include "Util.h"

#include "robin_hood/robin_hood.h"

#include <QThread>

#include <mutex>

Subscription::Subscription(const HashX &sh)
    : QObject(nullptr), scriptHash(sh)
{
}

Subscription::~Subscription()
{
}

namespace {
    using LockGuard = std::lock_guard<std::mutex>;
    constexpr int kNotifTimerIntervalMS = 500; ///< we notify in batches at most once every 500ms .. this delay is ok because anyway we only receive mempool updates at most once per second.
    constexpr const char *kNotifTimerName = "NotificationTimer";
    constexpr int kRemoveZombiesTimerIntervalMS = 60000; ///< we remove zombie subs entries every minute
    constexpr const char *kRemoveZombiesTimerName = "ZombieTimer";
}

struct SubsMgr::Pvt
{
    std::mutex mut;
    robin_hood::unordered_flat_map<HashX, SubsMgr::SubRef, HashHasher> subs;
    std::unordered_set<HashX, HashHasher> pendingNotificatons;

    std::atomic_int nClientSubsActive{0};

    static constexpr size_t kSubsReserveSize = 16384;
    Pvt() {
        subs.reserve(kSubsReserveSize);
        pendingNotificatons.reserve(kRecommendedPendingNotificationsReserveSize);
    }
    /// call this with the lock held
    void clearPending_nolock() noexcept {
        decltype(pendingNotificatons) emptySet;
        pendingNotificatons.swap(emptySet);
        pendingNotificatons.reserve(kRecommendedPendingNotificationsReserveSize);
    }
};

SubsMgr::SubsMgr(const std::shared_ptr<Options> & o, Storage *s, const QString &n)
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

void SubsMgr::on_started()
{
    ThreadObjectMixin::on_started();
    conns += connect(this, &SubsMgr::queueNoLongerEmpty, this, [this]{
        callOnTimerSoonNoRepeat(kNotifTimerIntervalMS, kNotifTimerName, [this]{ doNotifyAllPending(); }, false, Qt::TimerType::PreciseTimer);
    }, Qt::QueuedConnection);
    callOnTimerSoon(kRemoveZombiesTimerIntervalMS, kRemoveZombiesTimerName, [this]{ removeZombies(); return true;}, true);
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
    const auto t0 = Util::getTimeNS();
    size_t ctr = 0, ctrSH = 0;
    decltype(p->subs) pending;
    {
        LockGuard g(p->mut);
        const bool pendingWasEmpty = p->pendingNotificatons.empty();
        if (!pendingWasEmpty && !p->subs.empty()) {
            pending.reserve(std::min(p->pendingNotificatons.size(), p->subs.size()));
            for (const auto & sh : p->pendingNotificatons) {
                if (auto it = p->subs.find(sh); it != p->subs.end()) {
                    pending[it->first] = it->second; // save memory by using it->first instead of 'sh' as the map key
                }
            }
        }
        p->clearPending_nolock();
        if (!pendingWasEmpty)
            emit queueEmpty();
    }
    // at this point we got all the subrefs for the scripthashes that changed.. and the lock is released .. now run through them all and notify each
    for (auto & [sh, sub] : pending) {
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
            }
        }
        // ^^^ We must release the above lock here temporarily because we do not want to hold it while also implicitly
        // grabbing the Storage 'blocksLock' below for getFullStatus* (storage->getHistory acquires that lock in
        // read-only mode).
        const auto status = getFullStatus(sh);
        // Now, re-acquire sub lock. Temporarily having released it above should be fine for our purposes, since the
        // above empty() check was only a performance optimization and the invariant not holding for the duration of
        // this code block is fine. In the unlikely event that a sub lost its clients while the lock was released, the
        // below emit sub->statusChanged(...) will just be a no-op.
        LockGuard g(sub->mut);
        const bool doemit = !sub->lastStatusNotified.has_value() || sub->lastStatusNotified.value() != status;
        // we basically cache 2 statuses but they are implicitly shared copies of the same memory so it's ok.
        sub->lastStatusNotified = status;
        sub->cachedStatus = status;
        if (doemit) {
            const auto nClients = sub->subscribedClientIds.size();
            ctr += nClients;
            Debug() << "Notifying " << nClients << Util::Pluralize(" client", nClients) << " of status for " << Util::ToHexFast(sh);
            sub->updateTS();
            emit sub->statusChanged(sh, status);
        }
    }
    if (ctr || ctrSH) {
        const auto elapsedMS = (Util::getTimeNS() - t0)/1e6;
        Debug() << __func__ << ": " << ctr << Util::Pluralize(" client", ctr) << ", " << ctrSH << Util::Pluralize(" scripthash", ctrSH) << " in " << QString::number(elapsedMS, 'f', 4) << " msec";
    }
}

void SubsMgr::enqueueNotifications(std::unordered_set<HashX, HashHasher> &s)
{
    if (s.empty()) return;
    LockGuard g(p->mut);
    const bool wasEmpty = p->pendingNotificatons.empty();
    p->pendingNotificatons.merge(s);
    if (wasEmpty)
        emit queueNoLongerEmpty();
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

auto SubsMgr::makeSubRef(const HashX &sh) -> SubRef
{
    static const auto Deleter = [](Subscription *s){ s->deleteLater(); };
    SubRef ret(new Subscription(sh), Deleter);
    if (QThread::currentThread() != this->thread()) {
        ret->moveToThread(this->thread());
    }
    return ret;
}

auto SubsMgr::getOrMakeSubRef(const HashX &sh) -> std::pair<SubRef, bool>
{
    std::pair<SubRef, bool> ret;
    LockGuard g(p->mut);
    if (auto it = p->subs.find(sh); it != p->subs.end()) {
        ret.first = it->second;
        ret.second = false; // was not new
    } else {
        ret.first = makeSubRef(sh);
        p->subs[sh] = ret.first;
        ret.second = true; // was new
    }
    return ret;
}

auto SubsMgr::findExistingSubRef(const HashX &sh) const -> SubRef
{
    SubRef ret;
    LockGuard g(p->mut);
    if (auto it = p->subs.find(sh); it != p->subs.end())
        ret = it->second;
    return ret;
}

auto SubsMgr::subscribe(RPC::ConnectionBase *c, const HashX &sh, const StatusCallback &notifyCB) -> SubscribeResult
{
    SubscribeResult ret = { false, {} };
    const auto t0 = Util::getTimeNS();
    if (UNLIKELY(!notifyCB))
        throw BadArgs("SubsMgr::subscribe must be called with a valid notifyCB. FIXME!");
    auto [sub, wasnew] = getOrMakeSubRef(sh);
    {
        LockGuard g(sub->mut);
        if (!wasnew && sub->subscribedClientIds.count(c->id)) {
            // already had a sub for this client, disconnect it because we will re-add the new functor below
            bool res = QObject::disconnect(sub.get(), &Subscription::statusChanged, c, nullptr);
            Trace() << "Existing sub disconnected signal: " << (res ? "ok" : "not ok!");
        } else {
            // did not have a sub for this client, add its id and also add the destroyed signal to clean up the id
            // upon client object destruction
            ret.first = true;
            sub->subscribedClientIds.insert(c->id);
            auto conn = QObject::connect(c, &QObject::destroyed, sub.get(), [sub=sub.get(), id=c->id, this](QObject *){
                --p->nClientSubsActive;
                LockGuard g(sub->mut);
                sub->subscribedClientIds.erase(id);
                sub->updateTS();
                //Debug() << "client id " << id << " destroyed, implicitly unsubbed from " << sub->scriptHash.toHex()
                //        << ", " << sub->subscribedClientIds.size() << " sub(s) remain";
            });
            if (UNLIKELY(!conn))
                throw InternalError("SubsMgr::subscribe: Failed to make the 'destroyed' connection for the client object! FIXME!");
            ++p->nClientSubsActive;
        }
        // Always copy the last known StatusHash to caller. This is guaranteed to either be a recent status since the
        // last notification sent (if known), or !has_value if not known.
        ret.second = sub->cachedStatus;
        sub->updateTS(); // our basic 'mtime'
        auto conn = QObject::connect(sub.get(), &Subscription::statusChanged, c, notifyCB, Qt::QueuedConnection); // QueuedConnection paranoia in case client 'c' "lives" in our thread
        if (UNLIKELY(!conn))
            throw InternalError("SubsMgr::subscribe: Failed to make the 'statusChanged' connection to the notifyCB functor! FIXME!");
    }

    const auto elapsed = Util::getTimeNS() - t0;
    Trace() << "subscribed " << Util::ToHexFast(sh) << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    return ret;
}

void SubsMgr::maybeCacheStatusResult(const HashX &sh, const StatusHash &status)
{
    if (status.length() != HashLen && !status.isEmpty())
        // we only allow empty (null) or 32 bytes.. otherwise reject
        return;
    SubRef sub = findExistingSubRef(sh);
    if (sub) {
        LockGuard g(sub->mut);
        if (!sub->lastStatusNotified.has_value() && !sub->cachedStatus.has_value())
            sub->cachedStatus = status;
    }
}

bool SubsMgr::unsubscribe(RPC::ConnectionBase *c, const HashX &sh)
{
    bool ret = false;
    const auto t0 = Util::getTimeNS();
    SubRef sub = findExistingSubRef(sh);
    if (sub) {
        // found
        LockGuard g(sub->mut);
        if (auto it = sub->subscribedClientIds.find(c->id); it != sub->subscribedClientIds.end()) {
            sub->subscribedClientIds.erase(it);
            sub->updateTS();
            bool res = QObject::disconnect(sub.get(), &Subscription::statusChanged, c, nullptr);
            //Trace() << "Unsub: disconnected signal1 " << (res ? "ok" : "not ok!");
            res = QObject::disconnect(c, &QObject::destroyed, sub.get(), nullptr);
            //Trace() << "Unsub: disconnected signal2 " << (res ? "ok" : "not ok!");
            ret = true;
            --p->nClientSubsActive;
        }
    }
    const auto elapsed = Util::getTimeNS() - t0;
    Trace() << int(ret) << " unsubscribed " << Util::ToHexFast(sh) << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    return ret;
}

int SubsMgr::numActiveClientSubscriptions() const { return p->nClientSubsActive; }
int SubsMgr::numScripthashesSubscribed() const {
    LockGuard g(p->mut);
    return int(p->subs.size());
}

auto SubsMgr::getFullStatus(const HashX &sh) const -> StatusHash
{
    const auto t0 = Util::getTimeNS();
    StatusHash ret;
    const auto hist = storage->getHistory(sh, true, true);
    if (hist.empty())
        // no history, return an empty QByteArray
        return ret;
    QString historyString;
    {
        QTextStream ts(&historyString, QIODevice::WriteOnly);
        for (const auto & item : hist) {
            ts << Util::ToHexFast(item.hash) << ":" << item.height << ":";
        }
    }
    // status is non-reversed, single sha256 (32 bytes)
    ret = BTC::HashOnce(historyString.toUtf8());
    const auto elapsed = Util::getTimeNS() - t0;
    Debug() << "full status for " << Util::ToHexFast(sh) << " " << hist.size() << " items in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    return ret;
}

void SubsMgr::removeZombies()
{
    const auto t0 = Util::getTimeNS();
    int ctr = 0;
    const auto now = Util::getTime();
    LockGuard g(p->mut);
    const auto total = p->subs.size();
    for (auto it = p->subs.begin(), next = it; it != p->subs.end(); it = next) {
        SubRef sub = it->second; // take a copy to increment refct so it doesn't disappear due to erase() below...
        if (UNLIKELY(!sub)) { // paranoia
            Fatal() << "A SubRef was null in " << __func__ << ". FIXME!";
            return;
        }
        LockGuard g(sub->mut);
        if (sub->subscribedClientIds.empty() && now - sub->tsMsec > kRemoveZombiesTimerIntervalMS) {
            ++ctr;
            next = it = p->subs.erase(it); // `it` is invalidated at this point, so we assign to it immediately to not keep an invalid iterator around...
        } else
            ++next;
    }
    if (ctr) {
        const auto elapsed = Util::getTimeNS() - t0;
        Debug() << "SubsMgr: Removed " << ctr << " zombie " << Util::Pluralize("sub", ctr) << " out of " << total
                << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    }
}

auto SubsMgr::stats() const -> Stats
{
    QVariantMap ret;
    {
        QVariantMap m;
        LockGuard g(p->mut);
        for (auto [sh, sub] : p->subs) { // value-copy intentional here (these are very cheap to perform on QByteArray and SubsRef anyway)
            QVariantMap m2;
            {
                LockGuard g2(sub->mut);
                m2["count"] = qlonglong(sub->subscribedClientIds.size());
                m2["lastStatusNotified"] = sub->lastStatusNotified.value_or(StatusHash()).toHex();
                m2["idleSecs"] = (Util::getTime() - sub->tsMsec)/1e3;
                const auto & clients = sub->subscribedClientIds;
                m2["clientIds"] = QVariantList::fromStdList(Util::toList<std::list<QVariant>>(clients));
            }
            m[QString(sh.toHex())] = m2;
        }
        ret["subscriptions"] = m;
        QVariantList l;
        for (auto sh : p->pendingNotificatons) {
            l.push_back(QString(sh.toHex()));
        }
        ret["pendingNotifications"] = l;
    }
    // these below 2 take the above lock again so we do them without the lock held
    ret["Num. active client subscriptions"] = numActiveClientSubscriptions();
    ret["Num. unique scripthashes subscribed (including zombies)"] = numScripthashesSubscribed();
    return ret;
}
