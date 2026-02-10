//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "SubStatus.h"
#include "Storage.h"
#include "Util.h"

#include <QObject>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <utility> // for pair

class SubsMgr;

/// A class encapsulating a single subscription to a "HashX" key. Originally this was designed to work with
/// ElectrumX-style scripthashes but has been extended whereby a client can subscribe to any "key" that is a
/// 32-byte hash (such as scripthash, txid, etc).
///
/// This class acts as a signal "fusebox" where many Clients can sign up to the `statusChanged` signal given
/// a particular HashX key.
class Subscription : public QObject
{
    Q_OBJECT
protected:
    friend class SubsMgr;

    /// The number of global Subscription instances. This is the total across all SubsMgrs that exist (zombie + active subs)
    static std::atomic_int64_t nGlobalInstances;

    explicit Subscription(const HashX & key);
    ~Subscription() override;

    const HashX key; ///< This is typically an implicitly shared copy of the same bytes as in the map key pointing to this instance (thus it's cheap to keep around here too)

    std::mutex mut; ///< this mutex guards the below data structures.

    std::unordered_set<quint64> subscribedClientIds; ///< this is atomically updated as clients subscribe/unsubscribe or as they are deleted/disconnected
    /// The last status sent out as a notification. If it has_value, it's guaranteed to be the most recent one announced
    /// to clients, so it is suitable for use in the respone to e.g. blockchain.scripthash.subscribe (iff has_value).
    SubStatus lastStatusNotified;
    /// The last status that was computed as the result of a blockchain.[scripthash|dsproof].subscribe RPC call
    /// This status is returned as the immediate result for subsequent .subscribe calls after the first client
    /// subscribes (as a performance optimization).  This value is correctly maintained by the notification mechanism
    /// in collaboration with Servers.cpp.  In rare cases it is not the most recent possible status since it is a
    /// slightly delayed value -- but that's ok as a future notification to a client will rectify the situation with
    /// the most up-to-date status in the near future anyway.
    SubStatus cachedStatus;
    /// The last time this sub was accessed in milliseconds (Util::getTime()). If the ts goes beyond 1 minute in the
    /// past, and it has no clients attached, its entry may be removed.
    int64_t tsMsec = Util::getTime();

    /// Call this with the lock held.
    void updateTS() { tsMsec = Util::getTime(); }

signals:
    /// @param key is the subscription key (ScriptHash or TxHash) (raw 32 bytes).
    /// @param status is raw 32 bytes as well if the manager is ScriptHashSubsMgr, otherwise it is whatever is
    ///     specified for that SubsMgr  (e.g. if DSProofSubsMgr, then it's a DSProof object).
    void statusChanged(const HashX &key, const SubStatus &status);

    /// This is a private signal. Do not emit this in code outside SubsMgr.cpp internals.
    ///
    /// It is connected to a lambda that will execute in the thread for all the subscribed clients for this sub.
    /// It will automatically unsubscribe them. Used by the DSProofSubsMgr when txids get confirmed and are no longer
    /// in the mempool.
    void unsubscribeRequested();
};

using StatusCallback = std::function<void(const HashX &, const SubStatus &)>;

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
protected:
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    SubsMgr(const std::shared_ptr<const Options> & opts, Storage * storage, const QString &name = "SubsMgr");
public:
    ~SubsMgr() override;

    void startup() override; ///< from Mgr, called only from Storage that owns us
    void cleanup() override; ///< from Mgr, called only from Storage that owns us

    static constexpr size_t kRecommendedPendingNotificationsReserveSize = 2048;

    /// Thrown by subsribe() if the global Options::maxSubsGlobally limit is reached.
    struct LimitReached : public Exception { using Exception::Exception; ~LimitReached() override; /**< for vtable */ };

    using SubscribeResult = std::pair<bool, SubStatus>; ///< used by "subscribe" below as the return value.
    /// Thread-safe. Subscribes client to a key (such as a scripthash). Call this from the client's thread (not doing
    /// so is undefined behavior).
    ///
    /// The exact meaning of `key` depends on the concrete subclass, but the ScriptHashSubsMgr will subscribe to a
    /// ScriptHash, for instance, the below description is for ScriptHashSubsMgr's behavior:
    ///
    /// `notifyCB` is called for update notifications asynchronously as the tx history for `sh` changes. It will always
    /// be called in the `client`'s thread.  If the client is deleted, all context for the client is cleaned-up
    /// automatically, and the subscription dereferenced. Pass a null `notifyCB` if you wish to benefit from the "weak"
    /// subscription mechanism which is a hack of sorts to get blockchain.scripthash.get_status working and caching
    /// calculated results.
    ///
    /// Unless `notifyCB` is null, multiple calls to this function for the same client + scripthash combination will
    /// overwrite previous non-null `notifyCB` callback registrations for the subscription. Thus each
    /// client + scripthash combo can only have at most 1 active non-null `notifyCB` extant at any time. (If `notifyCB`
    /// is null, the current client + scripthash notification callbacks that existed, if any, are left unmolested.)
    ///
    /// Returns .first = true if the subscription for this client is new, or false if it replaced a previous subscription.
    /// Note that if called with a null `notifyCB`, .first will be false since this isn't a "real" new subscription.
    /// In the non-null `notifyCB` case, the client is now subscribed to the scripthash in question. In the null
    /// `notifyCB` case, the client is not subscribed at all, and we only query for any cached status hashes.
    ///
    /// The .second of the pair is a cached StatusHash (if known).  Note the StatusHash may be defined but an empty
    /// QByteArray if there is no history for the scripthash.  If the SubStatus !has_value, then we don't have a cached
    /// status for the scripthash in question (but one still may exist!) -- client code should follow up with a
    /// getFullStatus() call to get the updated (non-cached) status.
    ///
    /// Doesn't normally throw but may throw BadArgs if notifyCB is invalid, or InternalError if it failed to
    /// make a QMetaObject::Connection for the subscription (or some other invariant failed to be satisfied).
    ///
    /// Will throw LimitReached if the subs table is full.  Calling code should catch this exception.
    /// (May also throw BadArgs).
    virtual SubscribeResult subscribe(RPC::ConnectionBase *client, const HashX &key, const StatusCallback &notifyCB);
    /// Thread-safe. The inverse of subscribe. Returns true if the client was previously subscribed, false otherwise.
    /// Always call this from the client's thread otherwise undefined behavior may result.
    bool unsubscribe(RPC::ConnectionBase *client, const HashX &key, bool updateTS = true);

    /// Returns the total number of (sh, client) subscriptions that are active for this instance (non-zombie).
    int64_t numActiveClientSubscriptions() const;
    /// Returns the total number of unique scripthashes subscribed-to.  A scripthash may be subscribe-to by more than 1
    /// client simultaneously, in which case it counts once towards this total.  This number may be <=
    /// numActiveClientSubscriptions. Additionally, this number also represents "zombie" subscriptions that we keep
    /// around for a time after clients disconnect (in case they reconnect in the future; this is to not lose caching
    /// information for an extant subscription).  Thus, this number may be larger than numActiveClientSubscriptions
    /// as well since it includes the aforementioned "zombies".
    int64_t numScripthashesSubscribed() const;

    /// Returns the number of Subscription objects extant across all instances of SubsMgr (and its subclasses), app-wide.
    static int64_t numGlobalSubscriptions() { return Subscription::nGlobalInstances.load(); }
    static int64_t numGlobalActiveClientSubscriptions();

    /// Returns a pair of (limitActive, limitAll)
    /// `limitActive` - is true if the number of active client subscriptions is near the global subs limit (>80% of global limit).
    /// `limitAll` - is true if the subs table (including zombies) is near the global subs limit (>80% of global limit).
    /// The global limit comes from Options::maxSubsGlobally. This function is thread-safe.
    std::pair<bool, bool> globalSubsLimitFlags() const;


    /// Thread-safe. Returns the status. Will always return an object that .has_value().
    ///
    /// Note that for ScriptHashSubsMgr, this implicitly will take the Storage "blocksLock" as a shared lock -- so bear
    /// that in mind if calling this from `Storage` with that lock already held.
    virtual SubStatus getFullStatus(const HashX &key) const = 0;

    /// Thread-safe.  Client calls this to maybe save the status hash it just got from getFullStatus. We don't always
    /// take the value and cache it -- only under very specific conditions.
    void maybeCacheStatusResult(const HashX &, const SubStatus &);

    /// Thread-safe. We do it this way because it's the fastest approach (uses C++17 unordered_set:::merge). After this
    /// call, s is modified and contains only the elements that were already pending (thus were not enqueued as they
    /// were already in the queue).  However since this is a move-based operation, s should officially be considered
    /// moved-from and thus in a "valid but unspecified state".
    void enqueueNotifications(std::unordered_set<HashX, HashHasher> && s);

signals:
    /// Public signal.  Emitted by SrvMgr to tell us to run removeZombies() right now outside the normal timer rate limit.
    /// See SrvMgr::globalSubsLimitReached().
    void requestRemoveZombiesSoon(int when_ms);
signals:
    /// Private signal.  Used to indicate the notification queue is empty (and thus any associated timers should be stopped).
    void queueEmpty();
    /// Private signal.  Used to indicate the notification queue is no longer empty (and thus associated timers should be started).
    void queueNoLongerEmpty();

protected:
    /// Thread-safe. Takes exclusive locks. Unsubscribes all clients currently subscribed for keys in subKeys. This
    /// effectively iterates over all the subs matching subKeys and emits the unsubscribeRequested() private signal.
    /// The actual unsubscribe is effectuated in the thread for each subscribed client.
    ///
    /// Only for use with the DSProofSubsMgr.
    void unsubscribeClientsForKeys(const std::unordered_set<HashX, HashHasher> & subKeys);

    /// Reimplement in subclasses to disable caching. called by subscribe and doNotifications to decide if it should
    /// cache statuses or not, or used cached statuses.  Since the DSProofSubsMgr has a very cheap "getFullStatus()",
    /// it reimplements this to false.
    virtual bool useStatusCache() const { return true; }

    /// This is here in case we ever need to implement per-derived-class subs limit checks.
    ///
    /// If we ever need that, we can make this virtual and then reimplement this in subclasses to customize global
    /// limit checks. The default implementation checks the number of extant subs globally for all SubsMgr instances
    /// against the limit specified in options->maxSubsGlobally.
    bool isSubsLimitExceeded(int64_t & limit) const;

    void on_started() override; ///< from ThreadObjectMixin
    void on_finished() override; ///< from ThreadObjectMixin
    Stats stats() const override; ///< from StatsMixin -- show some subs stats
    Stats debug(const StatsParams &) const override; ///< from StatsMixin -- returns a QVariantMap of *all* subs iff param "subs" is present.

    const std::shared_ptr<const Options> options;
    Storage * const storage; ///< pointer guaranteed to be valid since Storage "owns" us and if we are alive, it is alive.

    using SubRef = std::shared_ptr<Subscription>;
    SubRef findExistingSubRef(const HashX &) const; // takes locks, returns an existing subref or empty ref.

    /// Used by the DSProofSubsMgr expireSubsNotInMempool() function to get a set of txids that maybe should be expired
    /// because they are subscribed but have no mempool tx.
    std::unordered_set<HashX, HashHasher> nonZombieKeysOlderThan(int64_t msec) const;

private:
    struct Pvt;
    std::unique_ptr<Pvt> p;

    SubRef makeSubRef(const HashX &key);
    std::pair<SubRef, bool> getOrMakeSubRef(const HashX &key); // takes locks, returns a new subref or an existing subref, may throw LimitReached

    void doNotifyAllPending();
    void removeZombies(bool forced);
};

class ScriptHashSubsMgr final : public SubsMgr {
protected:
    friend class ::Storage;
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    using SubsMgr::SubsMgr;

public:
    ~ScriptHashSubsMgr() override;

    /// Thread-safe. Returns the status hash bytes (32 bytes single sha256 hash of the status text). Will return
    /// a status containing a zero-length QByteArray if the scriptHash in question has no history. The returned object
    /// will always have non-nullptr .byteArray().
    ///
    /// Note that this implicitly will take the Storage "blocksLock" as a shared lock -- so bear that in mind if calling
    /// this from `Storage` with that lock already held.
    SubStatus getFullStatus(const HashX &scriptHash) const override;
};

class DSProofSubsMgr final : public SubsMgr {
protected:
    friend class ::Storage;
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    DSProofSubsMgr(const std::shared_ptr<const Options> & opts, Storage * storage, const QString &name = "SubsMgr (DSPs)")
        : SubsMgr(opts, storage, name) {}

public:
    ~DSProofSubsMgr() override;

    /// Thread-safe. Returns a SubStatus object which .has_value() and where .dsproof() is not nullptr.
    /// Will return an object with a dsproof which is not isComplete() (default constructed) if there are no dsproofs
    /// for the given txHash.
    ///
    /// Note that this implicitly will take the Storage "mempool lock" as a shared lock -- so bear that in mind if
    /// calling this from `Storage` with that lock already held.
    SubStatus getFullStatus(const HashX &txHash) const override;
    /// Identical to superclass implementation but it also attaches the unsubscribeRequested() signal to a lambda
    /// for client, so that SubsMgr::unsubscribeClientsForKeys() is not a no-op.
    ///
    /// Note that for the DSProofSubsMgr, we never return a cached value here -- SubscribeResult.second is always
    /// !has_value() (empty).  Calling code can just query getFullStatus() (this is because getFullStatus() is very
    /// cheap to call for this SubsMgr, and caching just wastes memory).
    SubscribeResult subscribe(RPC::ConnectionBase *client, const HashX &sh, const StatusCallback &notifyCB) override;

protected:
    void on_started() override;
    void on_finished() override;

    bool useStatusCache() const override { return false; }

private:
    void expireSubsNotInMempool(); // takes mempool lock in shared mode, called from a timer
};

class TransactionSubsMgr final : public SubsMgr {
protected:
    friend class ::Storage;
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    TransactionSubsMgr(const std::shared_ptr<const Options> & opts, Storage * storage, const QString &name = "SubsMgr (Txs)")
        : SubsMgr(opts, storage, name) {}
public:
    ~TransactionSubsMgr() override;

    /// Thread-safe. Returns a SubStatus object which .has_value().
    /// Will return an object with a blockHeight() which is itself nullopt (default constructed) if the tx in question
    /// is not known. Otherwise the *blockHeight() will be a height where 0=mempool and >0=confirmed_height.
    ///
    /// Note that this implicitly will take some of the Storage locks: blocksLock, blkInfoLock, and mempoolLock.
    SubStatus getFullStatus(const HashX &txHash) const override;
};
