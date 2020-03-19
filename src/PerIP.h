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
#include "Mixins.h"

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QPointer>

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>

class SrvMgr;

namespace PerIP
{
    /// Each Client * instance (see Servers.h) holds a strong reference to one of these.
    struct Data
    {
        const QHostAddress addr;

        std::atomic<int64_t> foo{}; ///< dummy for testing
    };

    using DataRef = std::shared_ptr<Data>;
    using DataWeakRef = std::weak_ptr<Data>;


    /// Note: This object *must* live longer than all of its subordinate PerIPDataRefs because the deleter for those
    /// objects accesses this object!  To ensure that fact, only SrvMgr can manipulate this class directly.
    class Mgr : public QObject
    {
        friend class ::SrvMgr;
        mutable std::shared_mutex mut;
        QHash <QHostAddress, DataWeakRef> ipDataTable;
        std::atomic_bool isDeleting{false};

    protected:
        // The below methods are for access by SrvMgr...

        /// Only SrvMgr can construct us. This ensures we live longer than the Client instances that reference us.
        explicit Mgr(SrvMgr *parent);
        ~Mgr() override;

        /// Thread-safe.  Gets an existing shared PerIPDataRed object, or atomically creates a new one if one does not
        /// already exist. (In the case of a new connection for this client).
        DataRef getOrCreate(const QHostAddress &addr);
    };
}
