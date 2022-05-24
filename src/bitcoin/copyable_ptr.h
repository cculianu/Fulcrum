//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2022 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <memory>
#include <utility>

namespace bitcoin {

    /// std::unique_ptr work-alike that is copy-constructible and copy-assignable (does a deep copy)
    /// Also can be copy/move-constructed or copy/move-assigned from a T.
    template <typename T>
    class CopyablePtr {
        std::unique_ptr<T> p{};
    public:
        using element_type = T;

        constexpr CopyablePtr() noexcept = default;
        explicit CopyablePtr(const T & t) { *this = t; }
        explicit CopyablePtr(T && t) { *this = t; }

        CopyablePtr(const CopyablePtr & o) { *this = o; }
        CopyablePtr(CopyablePtr && o) = default;

        CopyablePtr(std::unique_ptr<T> && u) : p{std::move(u)} {}

        template <typename ...Args>
        static CopyablePtr Make(Args && ...args) { return CopyablePtr(std::make_unique<T>(std::forward<Args>(args)...)); }

        CopyablePtr & operator=(const CopyablePtr & o) {
            if (o.p) p = std::make_unique<T>(*o.p);
            else p.reset();
            return *this;
        }
        CopyablePtr & operator=(CopyablePtr && o) = default;

        CopyablePtr & operator=(const T & t) { p = std::make_unique<T>(t); return *this; }
        CopyablePtr & operator=(T && t) { p = std::make_unique<T>(std::move(t)); return *this; }

        operator bool() const { return static_cast<bool>(p); }
        T & operator*() { return *p; }
        const T & operator*() const { return *p; }
        T * get() { return p.get(); }
        const T * get() const { return p.get(); }
        T * operator->() { return p.operator->(); }
        const T * operator->() const { return p.operator->(); }

        void reset(T * t = nullptr) { p.reset(t); }
        T * release() { return p.release(); }
    };

} // namespace bitcoin
