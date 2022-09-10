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

#include <algorithm>
#include <memory>
#include <type_traits>
#include <utility>

namespace bitcoin {

    /// std::unique_ptr work-alike that is copy-constructible and copy-assignable (does a deep copy)
    /// Also can be copy/move-constructed or copy/move-assigned from a T.
    ///
    /// Intended to be used for "heavy" optional data members that are null in the common case, but
    /// take non-trivial amounts of memory when they are not null.
    template <typename T>
    class CopyablePtr {
        std::unique_ptr<T> p{};
    public:
        using element_type = T;

        constexpr CopyablePtr() noexcept = default;
        explicit CopyablePtr(const T & t) { *this = t; }
        explicit CopyablePtr(T && t) noexcept { *this = t; }

        /// Construct the CopyablePtr in-place using argument forwarding
        template <typename ...Args>
        explicit CopyablePtr(Args && ...args) { emplace(std::forward<Args>(args)...); }

        CopyablePtr(const CopyablePtr & o) { *this = o; }
        CopyablePtr(CopyablePtr && o) = default;

        /// Create the new object in-place. Deletes previous object (if any) first.
        template <typename ...Args>
        void emplace(Args && ...args) { p = std::make_unique<T>(std::forward<Args>(args)...); }

        CopyablePtr & operator=(const CopyablePtr & o) {
            if (o.p) p = std::make_unique<T>(*o.p);
            else p.reset();
            return *this;
        }
        CopyablePtr & operator=(CopyablePtr && o) noexcept = default;

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


        //--- Comparison operators: ==, !=, <, does deep compare of pointed-to T values
        //    (only SFINAE-enabled if underlying type T supports these ops)

        auto operator==(const CopyablePtr & o) const -> decltype(std::declval<std::equal_to<T>>()(std::declval<T>(),
                                                                                                  std::declval<T>())) {
            if (p && o.p) return std::equal_to{}(*p, *o.p); // compare by pointed-to value if both are not null
            return std::equal_to{}(p, o.p); // compare the unique_ptr's if either are null
        }
        // compare to a value directly
        auto operator==(const T & t) const -> decltype(std::declval<std::equal_to<T>>()(std::declval<T>(),
                                                                                        std::declval<T>())) {
            if (!p) return false; // we never compare equal to a real value if we are null
            return std::equal_to{}(*p, t); // compare by pointed-to value if we not null
        }

        auto operator!=(const CopyablePtr & o) const -> decltype(std::declval<std::not_equal_to<T>>()(std::declval<T>(),
                                                                                                      std::declval<T>())) {
            if (p && o.p) return std::not_equal_to{}(*p, *o.p); // compare by pointed-to value if both are not null
            return std::not_equal_to{}(p, o.p); // compare the unique_ptr's if either are null
        }
        // compare to a value directly
        auto operator!=(const T & t) const -> decltype(std::declval<std::not_equal_to<T>>()(std::declval<T>(),
                                                                                            std::declval<T>())) {
            if (!p) return true; // we are not equal to t if we are nullptr
            return std::not_equal_to{}(*p, t); // compare by pointed-to value
        }

        auto operator<(const CopyablePtr & o) const -> decltype(std::declval<std::less<T>>()(std::declval<T>(),
                                                                                             std::declval<T>())) {
            if (p && o.p) return std::less{}(*p, *o.p); // compare by pointed-to value if both are not null
            return std::less{}(p, o.p); // compare the unique_ptr's if either are null
        }
        // compare to a value directly
        auto operator<(const T & t) const -> decltype(std::declval<std::less<T>>()(std::declval<T>(), std::declval<T>())) {
            if (!p) return true; // if we are null we are always less
            return std::less{}(*p, t); // compare to the pointed-to value
        }
    };

} // namespace bitcoin
