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

#include "Common.h"
#include "Util.h"

#include <QHash>
#include <QPointer>
#include <QObject>

#include <atomic>
#include <cassert>
#include <memory>
#include <mutex>
#include <shared_mutex>

/// A thread-safe hash table with "WeakValueDictionary" semantics. That is, the getOrCreate function either creates a
/// new data item or returns a pre-existing one, wrapped in a std::shared_ptr.  The table will auto-delete any items
/// once theeir shared_ptr refct drops to 0.
///
/// Note: This object *must* live longer than all of its subordinate DataRefs because the deleters for the returned
/// objects access this object!
template <typename Key, typename Data, bool debugPrt = true || !isReleaseBuild(),
          auto KeyToStringMember = &Key::toString>
class ThreadSafeHashTable : public QObject
{
public:
    using DataRef = std::shared_ptr<Data>;
private:
    mutable std::shared_mutex mut;
    using DataWeakRef = std::weak_ptr<Data>;
    using SharedLockGuard = std::shared_lock<std::shared_mutex>;
    using ExclusiveLockGuard = std::unique_lock<std::shared_mutex>;
    using Table = QHash <Key, DataWeakRef>;
    const size_t squeezeThreshold;
    Table table;
    std::atomic_bool isDeleted{false};

    static inline QString ToString(const Key & key) { return (key.*KeyToStringMember)(); }

public:
    explicit ThreadSafeHashTable(QObject *parent=nullptr, size_t initialCapacity=0, size_t squeezeThreshold_=0)
        : QObject(parent), squeezeThreshold(squeezeThreshold_)
    {
        setObjectName(QString("ThreadSafeHashTable<%1, %2>").arg(typeid(Key).name()).arg(typeid(Data).name()));
        if (initialCapacity)
            table.reserve(initialCapacity);
    }
    ~ThreadSafeHashTable() override {
        isDeleted = true;
        if constexpr (debugPrt) {
            Debug() << objectName() << ": Checking table...";
            for (auto it = table.begin(); it != table.end(); ++it) {
                if (!it.value().expired())
                    Error() << objectName() << " d'tor: a weak ref was still alive for " << ToString(it.key()) << ". FIXME!";
            }
        }
    }

    // Use these to grab the table for iterating
    std::pair<const Table, SharedLockGuard> getTable() const { return {table, SharedLockGuard{mut}}; } // read-only access
    std::pair<Table, ExclusiveLockGuard> getMutableTable() const { return {table, ExclusiveLockGuard{mut}}; } // read/write access


    /// Thread-safe.  Gets an existing shared object, or atomically creates a new one if one does not
    /// already exist. (In the case of a new connection for this client).  The object's table entry will be
    /// removed automatically by its deleter when the last instance of the returned std::shared_ptr is dereferenced.
    DataRef getOrCreate(const Key &key, bool createIfMissing)
    {
        DataRef ret;
        constexpr auto MkDebugPrtFunc = [](const auto & key, const auto & ret, auto me) constexpr -> auto  {
            // ugh, we need to do it this way to avoid unused lambda capture warnings in the !debugPrt branch
            if constexpr (debugPrt)
                return [&key, &ret, me] {
                    Debug() << me->objectName() << ": " << ToString(key) << " found existing with refct: " << ret.use_count();
                };
            else return [] {};
        };
        const auto debugPrtFoundExisting = MkDebugPrtFunc(key, ret, this);

        // first, take the shared lock and see if we can find the per-ip data for addr, as a performance optimization.
        {
            SharedLockGuard g(mut);
            if (auto it = table.find(key); it != table.end())
                ret = it.value().lock();
            // fall thru to below code
        }

        if (!ret && createIfMissing) {
            // Note there's a potential race condition here -- even if !ret, another thread may come in and create that
            // object and insert it into the table since we released the shared_lock above.  So we will need to search
            // for the object again with the unique_lock held.
            ExclusiveLockGuard g(mut);
            if (auto it = table.find(key); UNLIKELY(it != table.end()))
                // Another thread may have inserted an object into the table in the meantime...
                // Note: this weakref may be invalid here, so we may have to create a new object anyway and
                // overwrite this table entry below if it is (bool(ret) will be false in that case).
                ret = it.value().lock();
            if (LIKELY(!ret)) {
                // definitely no entries in table for this key exist -- create a new Data object
                ret = DataRef(new Data, [weakThis = QPointer(this), key, myname = objectName()](Data *p){
                    // Deleter may be called from any thread. It's critical here that this instance live
                    // longer than the subordinate DataRefs it manages, else the behavior is undefined.
                    // (If this assumption is violated then there is a race condition here with the QPointer being valid
                    // one moment then invalid the next while this function executes).
                    constexpr auto MkDeleteFunc = [](Data *&p, const auto & myname, const auto & key) constexpr -> auto
                    {
                        // ugh, we need to do it this way to avoid unused lambda capture warnings in the !debugPrt branch
                        if constexpr (debugPrt)
                            return [&p, &myname, &key] {
                                Debug() << myname << ": entry for " << ToString(key) << " DELETED!";
                                delete p; p = nullptr;
                            };
                        else
                            return [&p] { delete p; p = nullptr; };
                    };
                    const Defer deleteP = MkDeleteFunc(p, myname, key); // <--- guarantee deletion at scope end

                    auto me = weakThis.data();
                    if (UNLIKELY(!me)) {
                        Error() << myname << " CRITICAL: While deleting entry for " << ToString(key)
                                << ", manager object no longer exists! FIXME!";
                        return;
                    }
                    if (UNLIKELY(me->isDeleted)) {
                        if constexpr (debugPrt)
                            Debug() << myname << ": is cleaing up, skipping remove-from-table for " << ToString(key);
                        return;
                    }
                    // Common-case -- above checks pass, remove from table. Note that if the predicate that we live
                    // longer than the subordinate objects is violated, then the code here will fail.
                    ExclusiveLockGuard g(me->mut);
                    auto it = me->table.find(key);
                    if (LIKELY(it != me->table.end())) {
                        if (UNLIKELY(!it.value().expired() && it.value().lock().get() != p)) {
                            Warning() << myname << ": Deleter for " << ToString(key)
                                      << " found entry, but the weak_ref in the table refers to a different object! FIXME!";
                        } else {
                            // Eithr a valid entry was found in the table or a defunct weak_ref was found.. in either
                            // case, remove the entry from the table. This is the most likely branch.
                            it = me->table.erase(it);
                            if (me->squeezeThreshold) {
                                if (const auto size = size_t(me->table.size());
                                        size >= me->squeezeThreshold && size * 2U <= size_t(me->table.capacity())) {
                                    // save space if we are over 2x capacity vs size
                                    me->table.squeeze();
                                }
                            }
                            if constexpr (debugPrt) Debug() << myname << ": Removed entry from table for " << ToString(key);
                        }
                    } else {
                        // this should never happen
                        Error() << myname << ": Deleter for " << ToString(key) << " could not find an entry in the table for this item! FIXME!";
                    }
                });
                table.insert(key, DataWeakRef{ret}); // Note: QHash::insert overwrites existing, unlike std::unordered_map::insert!
                if constexpr (debugPrt)
                    Debug() << objectName() << ": entry for " << ToString(key) << " CREATED!";
            } else
                // was inserted by somebody else in the meantime..
                debugPrtFoundExisting();
        } else if (ret)
            // was found in fast-path with shared_lock above.
            debugPrtFoundExisting();
        assert(!createIfMissing || ret);
        return ret;
    }
};
