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
#include <type_traits>
#include <unordered_set>

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

    const HashX scriptHash;
    std::unordered_set<quint64> subscribedClientIds;
    StatusHash lastStatus;
    /// The last time this sub was accessed in milliseconds (Util::getTime()). If the ts goes beyond 1 minute, and it
    /// has no clients attached, its entry may be removed.
    int64_t tsMsec = Util::getTime();

    inline void updateTS() { tsMsec = Util::getTime(); }

signals:
    /// sh is the scripthash (raw 32 bytes). The status is raw 32 bytes as well.
    void statusChanged(const HashX &sh, const StatusHash &status);
};

using StatusCallback = std::function<void(const HashX &, const StatusHash &)>;

class SubsMgr : public Mgr, public ThreadObjectMixin, public TimersByNameMixin
{
    Q_OBJECT
    friend class ::Storage;
    /// Only Storage can construct one of these -- Storage is guaranteed to remain alive at least as long as this instance.
    SubsMgr(const std::shared_ptr<Options> & opts, Storage * storage, const QString &name = "SubsMgr");
public:
    ~SubsMgr() override;

    void startup() override; ///< from Mgr, called only from Storage that owns us
    void cleanup() override; ///< from Mgr, called only from Storage that owns us

    /// Thread-safe. Subscribes client to a scripthash. Call this from the client's thread (not doing so is undefined).
    ///
    /// `notifyCB` is called for update notifications asynchronously as the tx history for `sh` changes. It will always
    /// be called in the `client`'s thread.  If the client is deleted, all context for the client is cleaned-up
    /// automatically.
    ///
    /// Multiple calls to this function for the same client+scripthash combination overwrite previous notifyCB
    /// callbacks registrations for the subscription. Thus each client+scripthash combo can only have at most 1 active
    /// notifyCB extant at any time.
    ///
    /// Doesn't normally throw but may throw BadArgs if resultCB is invalid, or InternalError if it failed to
    /// make a QMetaObject::Connection for the subscription.
    void subscribe(RPC::ConnectionBase *client, const HashX &sh, const StatusCallback &notifyCB);
    /// Thread-safe. The inverse of subscribe. Returns true if the client was previously subscribed, false otherwise.
    /// Always call this from the client's thread otherwise undefined behavior may result.
    bool unsubscribe(RPC::ConnectionBase *client, const HashX &sh);

    /// Thread-safe. Returns the status hash bytes (32 bytes single sha256 hash of the status text). Will return
    /// an empty byte vector if the scriptHash in question has no history.
    ///
    /// Note that this implicitly will take the Storage "blocksLock" as a shared lock -- so bear that in mind if calling
    /// this from `Storage` with that lock already held.
    StatusHash getFullStatus(const HashX &scriptHash) const;

    /// Thread-safe. Add a single HashX to the notification queue. If it has any subs, it will receive a notification
    /// with the updated status hash in the very near future.
    void enqueueNotification(const HashX &sh);
    /// Thread-safe, batched version of the above. Submit a list,set,vector,etc of HashX's for notification.
    template <typename Iterable>
    void enqueueNotifications(const Iterable & container1D)
    {
        auto guard = grabLock();
        for (const auto & sh : container1D) {
            static_assert(std::is_base_of_v<HashX, std::remove_cv_t<std::remove_reference_t<decltype(sh)>>>, "Container of HashX must be used with enqueueNotifications");
            addNotif_nolock(sh);
        }
    }
signals:
    /// Private signal.  Used to indicate the notification queue is empty (and thus any associated timers should be stopped).
    void queueEmpty();
    /// Private signal.  Used to indicate the notification queue is no longer empty (and thus associated timers should be started).
    void queueNoLongerEmpty();
protected:
    void on_started() override; ///< from ThreadObjectMixin
    void on_finished() override; ///< from ThreadObjectMixin
private:
    const std::shared_ptr<Options> options;
    Storage * const storage; ///< ponter guaranteed to be valid since Storage "owns" us and if we are alive, it is alive.
    struct Pvt;
    std::unique_ptr<Pvt> p;

    using SubRef = std::shared_ptr<Subscription>;
    SubRef makeSubRef(const HashX &sh);
    std::pair<SubRef, bool> getOrMakeSubRef(const HashX &sh); // takes locks, returns a new subref or an existing subref
    SubRef findExistingSubRef(const HashX &) const; // takes locks, returns an existing subref or empty ref.

    /// Note: Despite the name, this does implicitly acquire the Storage blocksLock as a shared lock.
    StatusHash getFullStatus_nolock_noupdate(const HashX &scriptHash) const;

    void doNotifyAllPending();

    std::unique_lock<std::mutex> grabLock();
    /// Only ever call this with the lock held.
    void addNotif_nolock(const HashX & sh);
    void removeZombies();
};
