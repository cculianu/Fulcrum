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
#include "Options.h"
#include "RPC.h"
#include "Storage.h"
#include "Util.h"

#include <QObject>

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <unordered_set>
#include <utility> // for pair

using StatusHash = QByteArray;

class SubsMgr;

/// A class encapsulating a single subscription to a scripthash. It acts as a signal "fusebox" where many Clients
/// can sign up to the `statusChanged` signal.
class Subscription : public QObject
{
    Q_OBJECT
protected:
    friend class SubsMgr;
    Subscription(const HashX & scriptHash);
    ~Subscription() override;

    std::mutex mut; ///< this mutex guards the below data structures.

    const HashX scriptHash; ///< This is typically an implicitly shared copy of the same bytes as in the map key pointing to this instance (thus it's cheap to keep around here too)
    std::unordered_set<quint64> subscribedClientIds; ///< this is atomically updated as clients subscribe/unsubscribe or as they are deleted/disconnected
    /// The last status sent out as a notification. If it has_value, it's guaranteed to be the most recent one announced
    /// to clients, so it is suitable for use in the respone to e.g. blockchain.scripthash.subscribe (iff has_value).
    std::optional<StatusHash> lastStatusNotified;
    /// The last status that was computed as the result of a blockchain.scripthash.subscribe RPC call.
    /// This status is returned as the immediate result for subsequent .subscribe calls after the first client
    /// subscribes (as a performance optimization).  This value is correctly maintained by the notification mechanism
    /// in collaboration with Servers.cpp.  In rare cases it is not the most recent possible status since it is a
    /// slightly delayed value -- but that's ok as a future notification to a client will rectify the situation with
    /// the most up-to-date status in the near future anyway.
    std::optional<StatusHash> cachedStatus;
    /// The last time this sub was accessed in milliseconds (Util::getTime()). If the ts goes beyond 1 minute in the
    /// past, and it has no clients attached, its entry may be removed.
    int64_t tsMsec = Util::getTime();

    /// Call this with the lock held.
    inline void updateTS() { tsMsec = Util::getTime(); }

signals:
    /// sh is the scripthash (raw 32 bytes). The status is raw 32 bytes as well.
    void statusChanged(const HashX &sh, const StatusHash &status);
};

using StatusCallback = std::function<void(const HashX &, const StatusHash &)>;

/// The Subscriptions Manager. Thread-safe operations for managing subscriptions and doing notifications.
///
/// This class is "owned" by the Storage instance.  Internally it takes a class-level data lock for some operations,
/// and also a per-Subscription-level locks for others.
///
/// Note about deadlocking: This class's locks are *SUBSERVIENT* to the "Storage" instance that owns it! Currently
/// it takes no locks at the same time as holding a Storage lock.  However, if one must take multiple locks the order
/// should be:  1. Storage Locks (in their defined order),  2. p->mut (Pvt::mut),  3. sub->mut (Subscription::mut).
class SubsMgr : public Mgr, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
    friend class ::Storage;
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    SubsMgr(const std::shared_ptr<const Options> & opts, Storage * storage, const QString &name = "SubsMgr");
public:
    ~SubsMgr() override;

    void startup() override; ///< from Mgr, called only from Storage that owns us
    void cleanup() override; ///< from Mgr, called only from Storage that owns us

    static constexpr size_t kRecommendedPendingNotificationsReserveSize = 2048;

    using SubscribeResult = std::pair<bool, std::optional<StatusHash>>; ///< used by "subscribe" below as the return value.
    /// Thread-safe. Subscribes client to a scripthash. Call this from the client's thread (not doing so is undefined).
    ///
    /// `notifyCB` is called for update notifications asynchronously as the tx history for `sh` changes. It will always
    /// be called in the `client`'s thread.  If the client is deleted, all context for the client is cleaned-up
    /// automatically, and the subscription dereferenced.
    ///
    /// Multiple calls to this function for the same client + scripthash combination overwrite previous notifyCB
    /// callback registrations for the subscription. Thus each client + scripthash combo can only have at most 1 active
    /// notifyCB extant at any time.
    ///
    /// Returns .first = true if the subscription for this client is new, or false if it replaced a previous subscription.
    /// In either case the client is now subscribed to the scripthash in question.
    ///
    /// The .second of the pair is a cached StatusHash (if known).  Note the StatusHash may be defined but an empty
    /// QByteArray if there is no history.  If the optional !has_value, then we don't have a known StatusHash for the
    /// scripthash in question (but one still may exist!) -- client code should follow up with a getFullStatus() call to
    /// get the updated status.
    ///
    /// Doesn't normally throw but may throw BadArgs if notifyCB is invalid, or InternalError if it failed to
    /// make a QMetaObject::Connection for the subscription.
    SubscribeResult subscribe(RPC::ConnectionBase *client, const HashX &sh, const StatusCallback &notifyCB);
    /// Thread-safe. The inverse of subscribe. Returns true if the client was previously subscribed, false otherwise.
    /// Always call this from the client's thread otherwise undefined behavior may result.
    bool unsubscribe(RPC::ConnectionBase *client, const HashX &sh);

    /// Returns the total number of (sh, client) subscriptions that are active (non-zombie).
    int numActiveClientSubscriptions() const;
    /// Returns the total number of unique scripthashes subscribed-to.  A scripthash may be subscribe-to by more than 1
    /// client simultaneously, in which case it counts once towards this total.  This number may be <=
    /// numActiveClientSubscriptions. Additionally, this number also represents "zombie" subscriptions that we keep
    /// around for a time after clients disconnect (in case they reconnect in the future; this is to not lose caching
    /// information for an extant subscription).  Thus, this number may be larger than numActiveClientSubscriptions
    /// as well since it includes the aforementioned "zombies".
    int numScripthashesSubscribed() const;


    /// Thread-safe. Returns the status hash bytes (32 bytes single sha256 hash of the status text). Will return
    /// an empty byte vector if the scriptHash in question has no history.
    ///
    /// Note that this implicitly will take the Storage "blocksLock" as a shared lock -- so bear that in mind if calling
    /// this from `Storage` with that lock already held.
    StatusHash getFullStatus(const HashX &scriptHash) const;

    /// Thread-safe.  Client calls this to maybe save the status hash it just got from getFullStatus. We don't always
    /// take the value and cache it -- only under very specific conditions.
    void maybeCacheStatusResult(const HashX &, const StatusHash &);

    /// Thread-safe. We do it this way because it's the fastest approach (uses C++17 unordered_set:::merge). After this
    /// call, s is modified and contains only the elements that were already pending (thus were not enqueued as they
    /// were already in the queue).
    void enqueueNotifications(std::unordered_set<HashX, HashHasher> & s);
    /// Like the above but uses move.  After this call, s can be considered to be invalidated.
    void enqueueNotifications(std::unordered_set<HashX, HashHasher> && s);
signals:
    /// Private signal.  Used to indicate the notification queue is empty (and thus any associated timers should be stopped).
    void queueEmpty();
    /// Private signal.  Used to indicate the notification queue is no longer empty (and thus associated timers should be started).
    void queueNoLongerEmpty();
protected:
    void on_started() override; ///< from ThreadObjectMixin
    void on_finished() override; ///< from ThreadObjectMixin
    Stats stats() const override; ///< from StatsMixin -- show some subs stats

private:
    const std::shared_ptr<const Options> options;
    Storage * const storage; ///< pointer guaranteed to be valid since Storage "owns" us and if we are alive, it is alive.
    struct Pvt;
    std::unique_ptr<Pvt> p;

    using SubRef = std::shared_ptr<Subscription>;
    SubRef makeSubRef(const HashX &sh);
    std::pair<SubRef, bool> getOrMakeSubRef(const HashX &sh); // takes locks, returns a new subref or an existing subref
    SubRef findExistingSubRef(const HashX &) const; // takes locks, returns an existing subref or empty ref.

    void doNotifyAllPending();

    void removeZombies();
};
