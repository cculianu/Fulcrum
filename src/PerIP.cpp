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
#include "PerIP.h"
#include "SrvMgr.h"
#include "Util.h"

#include <cassert>

namespace PerIP
{
    namespace {
        constexpr bool debugPrt = true;
    }
    Mgr::Mgr(SrvMgr *parent)
        : QObject(parent)
    {
        assert(parent);
        setObjectName("PerIP Manager");
    }

    Mgr::~Mgr() { isDeleting = true; }

    DataRef Mgr::getOrCreate(const QHostAddress &addr) {
        DataRef ret;
        const auto debugPrtFoundExisting = [&addr, &ret]{
            if constexpr (debugPrt)
                Debug() << "PerIP::Data for " << addr.toString() << " found existing with refct: " << ret.use_count();
        };
        {
            // first, take the shared lock and see if we can find the per-ip data for addr, as a performance optimization.
            std::shared_lock g(mut);
            if (auto it = ipDataTable.find(addr); it != ipDataTable.end())
                ret = it.value().lock();
            // fall thru to below code
        }
        if (!ret) {
            // Note there's a potential race condition here -- even if !ret, another thread may come in and create that
            // object and insert it into the table since we released the shared_lock.  So we will need to search for
            // the object again with the unique lock held.
            std::unique_lock g(mut);
            if (auto it = ipDataTable.find(addr); it != ipDataTable.end())
                // Another thread may have inserted an object into the table in the meantime...
                // Note: this weakref may be invalid here, so we may have to create a new object anyway and
                // overwrite this table entry below if it is (bool(ret) will be false in that case).
                ret = it.value().lock();
            if (!ret) {
                // definitely no entries in table for this IP exist -- new connection from this IP; create PerIP::Data
                ret = DataRef(new Data{addr}, [weakThis = QPointer<Mgr>(this)](Data *p){
                    // Deleter may be called from any thread. It's critical here that this PerIP::Mgr instance live
                    // longer than the subordinate PerIPDataRefs it manages, else the behavior is undefined.
                    // (If this assumption is violated then there is a race condition in that case where the QPointer
                    // may not become invalidated in time across threads).
                    auto me = weakThis.data();
                    if (LIKELY(me && !me->isDeleting)) {
                        std::unique_lock g(me->mut);
                        auto it = me->ipDataTable.find(p->addr);
                        if (LIKELY(it != me->ipDataTable.end())) {
                            if (UNLIKELY(!it.value().expired() && it.value().lock().get() != p)) {
                                Warning() << "Deleter for PerIP::Data for " << p->addr.toString()
                                          << " found entry, but the weak_ref in the table refers to a different object! FIXME!";
                            } else {
                                // Valid entry found in table -- this is the most likely branch -- remove the weak_ref entry now.
                                it = me->ipDataTable.erase(it);
                                if constexpr (debugPrt) Debug() << "Removed PerIP::Data entry from table for " << p->addr.toString();
                            }
                        } else
                            Error() << "CRITICAL: ipDataTable had no entries for " << p->addr.toString() << " in PerIP::DataRef deleter! FIXME!";
                    } else
                        Error() << "CRITICAL: While deleting PerIP::Data for address " << p->addr.toString() << ", Mgr object no longer exists! FIXME!";
                    if constexpr (debugPrt) Debug() << "PerIP::Data for " << p->addr.toString() << " DELETED!";
                    delete p; // lastly, don't forget to delete!
                });
                ipDataTable.insert(addr, DataWeakRef{ret}); // Note: QHash::insert overwrites existing, unlike std::unordered_map::insert!
                if constexpr (debugPrt) Debug() << "PerIP::Data for " << addr.toString() << " CREATED!";
            } else
                // was inserted by somebody else in the meantime..
                debugPrtFoundExisting();
        } else
            // was found in fast-path with shared_lock above.
            debugPrtFoundExisting();
        assert(ret);
        return ret;
    }

} // end namespace PerIP
