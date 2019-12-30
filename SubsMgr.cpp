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
    constexpr int kNotifTimerIntervalMS = 50; ///< we notify in batches at most once every 50ms
    constexpr const char *kNotifTimerName = "ScripthashStatusNotificationTimer";
    constexpr int kRemoveZombiesTimerIntervalMS = 60000; ///< we remove zombie subs entries every minute
    constexpr const char *kRemoveZombiesTimerName = "ScripthashStatusNotificationTimer";
}

struct SubsMgr::Pvt
{
    std::mutex mut;
    robin_hood::unordered_flat_map<HashX, SubsMgr::SubRef, HashHasher> subs;
    std::unordered_set<HashX, HashHasher> pendingNotificatons;

    std::atomic_int nClientSubsActive{0};
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
    });
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
    decltype(p->subs) pending;
    {
        LockGuard g(p->mut);
        for (const auto & sh : p->pendingNotificatons) {
            if (auto it = p->subs.find(sh); it != p->subs.end()) {
                pending[it->first] = it->second; // save memory by using it->first instead of 'sh' as the map key
            }
        }
        p->pendingNotificatons.clear();
        emit queueEmpty();
    }
    // at this point we got all the subrefs for the scripthashes that changed.. and the lock is released .. now run through them all and notify each
    for (auto & [sh, sub] : pending) {
        {
            LockGuard g(sub->mut);
            if (sub->subscribedClientIds.empty())
                continue;
        }
        // ^^^ We must release the above lock here temporarily because we do not want to hold it while also implicitly
        // grabbing the Storage 'blocksLock' below for getFullStatus* (storage->getHistory acquires that lock in
        // read-only mode).
        const auto status = getFullStatus_nolock_noupdate(sh);
        // Now, re-acquire sub lock. Temporarily having released it above should be fine for our purposes, since the
        // above empty() check was only a performance optimization and the invariant not holding for the duration of
        // this code block is fine. In the unlikely event that a sub lost its clients while the lock was released, the
        // below emit sub->statusChanged(...) will just be a no-op.
        LockGuard g(sub->mut);
        const bool doemit = sub->lastStatus != status;
        sub->lastStatus = status;
        if (doemit) {
            Debug() << "Notifying " << sub->subscribedClientIds.size() << " client(s) of status for " << Util::ToHexFast(sh);
            sub->updateTS();
            emit sub->statusChanged(sh, status);
        }
    }
}

void SubsMgr::enqueueNotification(const HashX &sh) {
    LockGuard g(p->mut);
    addNotif_nolock(sh);
}

std::unique_lock<std::mutex> SubsMgr::grabLock() { return std::unique_lock(p->mut); }
void SubsMgr::addNotif_nolock(const HashX & sh)
{
    if (UNLIKELY(sh.length() != HashLen)) {
        Warning() << __FUNCTION__ << ": called with a scripthash whose length is not " << HashLen << " (" << Util::ToHexFast(sh) << "), ignoring ... ";
        return;
    }
    const bool wasEmpty = p->pendingNotificatons.empty();
    p->pendingNotificatons.insert(sh);
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

bool SubsMgr::subscribe(RPC::ConnectionBase *c, const HashX &sh, const StatusCallback &notifyCB)
{
    bool ret = false;
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
            ret = true;
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
        sub->updateTS();
        auto conn = QObject::connect(sub.get(), &Subscription::statusChanged, c, notifyCB);
        if (UNLIKELY(!conn))
            throw InternalError("SubsMgr::subscribe: Failed to make the 'statusChanged' connection to the notifyCB functor! FIXME!");
    }

    const auto elapsed = Util::getTimeNS() - t0;
    Trace() << "subscribed " << Util::ToHexFast(sh) << " in " << QString::number(elapsed/1e6, 'f', 4) << " msec";
    return ret;
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
    // TODO here -- use cached status if the sh has existing subs ..?! It's tricky because race conditions.
    // For now we just recompute the full status unconditionally and don't cache it.
    return getFullStatus_nolock_noupdate(sh);
}

auto SubsMgr::getFullStatus_nolock_noupdate(const HashX &sh) const -> StatusHash
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
                m2["lastStatusNotified"] = sub->lastStatus.toHex();
                m2["idleSecs"] = (Util::getTime() - sub->tsMsec)/1e3;
                const auto & clients = sub->subscribedClientIds;
                m2["clientIds"] = QVariantList::fromStdList(Util::toList<decltype(clients), std::list<QVariant>>(clients));
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
