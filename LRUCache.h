//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
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

/*
 * This is based on the following, with heavy modifications by me, Calin Culianu <calin.culianu@gmail.com>:
 *
 * Original copyright & license below:
 *
 * LRUCache11 - a templated C++11 based LRU cache class that allows
 * specification of
 * key, value and optionally the map container type (defaults to
 * std::unordered_map)
 * By using the std::unordered_map and a linked list of keys it allows O(1) insert, delete
 * and
 * refresh operations.
 *
 * This is a header-only library and all you need is the LRUCache11.hpp file
 *
 * Github: https://github.com/mohaps/lrucache11
 *
 * This is a follow-up to the LRUCache project -
 * https://github.com/mohaps/lrucache
 *
 * Copyright (c) 2012-22 SAURAV MOHAPATRA <mohaps@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#pragma once

#include "robin_hood/robin_hood.h"

#include <algorithm>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <type_traits>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wweak-vtables"  // for LRU::KeyNotFound below
#endif


namespace LRU {

    /// Exception thrown when a requested key is not in cache. Thrown by Cache::get().
    struct KeyNotFound : public std::invalid_argument {
        KeyNotFound() : std::invalid_argument("Cache key not found") {}
    };

    template <typename Key, typename Value>
    struct KeyValuePair {
        Key key;
        Value value;

        KeyValuePair(const Key & k, const Value & v) : key(k), value(v) {}
    };

    /***
     *	The LRU Cache class templated by
     *      threadSafe - a compile-time boolean that decides whether a real mutex will be used to guarantee thread
     *                   safety if set to true, otherwise no locking is done in get/insert/remove, etc.
     *      Key        - key type (keys will be stored twice for each item in the cache so use a lightweight type or an
     *                   implicitly-shared, reference-counted type here)
     *      Value      - value type (values must be copy-constructible)
     *      Hasher     - the hasher to use for Key. Defaults to robin_hood::hash<Key>.
     *
     * According to STL, order of templates has effect on throughput. That's why I've moved the boolean to the front.
     * https://www.reddit.com/r/cpp/comments/ahp6iu/compile_time_binary_size_reductions_and_cs_future/eeguck4/
     */
    template <bool threadSafe, typename Key, typename Value, typename Hasher = robin_hood::hash<Key>>
    class Cache {
        struct NullLock {};
        struct NullGuard { NullGuard(NullLock &) {} };
    public:
        // std-like member types
        using node_type = KeyValuePair<Key, Value>;
        using list_type = std::list<node_type>;
        using map_type = robin_hood::unordered_flat_map<Key, typename list_type::iterator, Hasher>;
        using lock_type = typename std::conditional<threadSafe, std::mutex, NullLock>::type;
        using Guard = typename std::conditional<threadSafe, std::lock_guard<lock_type>, NullGuard>::type;

        /// The maxSize is the soft limit of keys and (maxSize + elasticity) is the
        /// hard limit. The cache is allowed to grow until (maxSize + elasticity) and is pruned back
        /// to maxSize keys.  Setting maxSize=0 is undefined.
        Cache(size_t maxSize, size_t elasticity)
            : maxSize_(std::max(maxSize, size_t(1))), elasticity_(elasticity) {
        }

        size_t size() const {
            Guard g(lock);
            return k_nodeit_map.size();
        }
        bool empty() const {
            Guard g(lock);
            return k_nodeit_map.empty();
        }
        size_t maxSize() const { return maxSize_; }
        size_t elasticity() const { return elasticity_; }
        size_t maxAllowedSize() const { return maxSize_ + elasticity_; }

        void clear() {
            Guard g(lock);
            k_nodeit_map.clear();
            nodes.clear();
        }
        /// Inserts a new item into the cache. If the specified key `k` was already in the cache, its associated value
        /// will be overwritten with `v` via operator=.  Returns true if a new item was inserted, or false if an
        /// existing item was overwritten.  In either case the new value `v` will be in the cache upon function return.
        bool insert(const Key & k, const Value & v) {
            Guard g(lock);
            const auto iter = k_nodeit_map.find(k);
            if (iter != k_nodeit_map.end()) {
                iter->second->value = v; // overwrite existing value
                nodes.splice(nodes.begin(), nodes, iter->second);
                return false;
            }

            nodes.emplace_front(k, v);
            k_nodeit_map[k] = nodes.begin();
            prune();
            return true;
        }
        /// Like get() below, but does not throw but instead uses an optional to communicate whether the key was found
        /// or not.  Note that this function will only work correctly if exceptions are enabled at compile-time.
        std::optional<Value> tryGet(const Key & key) noexcept {
            std::optional<Value> ret;
            Guard g(lock);
            const auto ptr = get_nolock_nothrow(key);
            if (ptr) ret.emplace(*ptr); // copy construct in place
            return ret;
        }
        /// Gets a copy-constructed version of the internally stored value.
        /// May throw KeyNotFound if the key is not in the cache.
        Value get(const Key & key) {
            Guard g(lock);
            return get_nolock(key);
        }
        /// Returns a const reference to the internally stored value. Does not use any locks. Use this version only in
        /// code where threadSafe=false. Otherwise it will not be offered because SFINAE will exlcude it
        /// from being emitted.  May throw KeyNotFound if `key` is not found in the cache.
        /// Simplified function signature:
        ///     auto getRef(const Key &) -> const Value &;
        template <typename Ret = const Value &>
        auto getRef(const Key &key) -> std::enable_if_t<std::is_same_v<Guard, NullGuard> && std::is_same_v<Ret, const Value &>, Ret>
        { return get_nolock(key); }

        /// Removes an item from the cache. Returns true if an item was removed or false otherwise.
        bool remove(const Key & k) {
            Guard g(lock);
            auto iter = k_nodeit_map.find(k);
            if (iter == k_nodeit_map.end()) {
                return false;
            }
            nodes.erase(iter->second);
            k_nodeit_map.erase(iter);
            return true;
        }

        bool contains(const Key & k) const {
            Guard g(lock);
            return k_nodeit_map.find(k) != k_nodeit_map.end();
        }

        /// Walk over every item in the cache. Pass a functor that will be called as: func(const KeyValuePair &) for
        /// every item in the cache. The lock will be held while this walk is doen if threadSafe=true
        template <typename F>
        void cwalk(const F & f) const {
            Guard g(lock);
            std::for_each(nodes.begin(), nodes.end(), f);
        }

        /// Shrink the down cache to maxSize() (eliminating the extra elasticity elements). Returns the number
        /// of cache items deleted.
        size_t shrink() {
            Guard g(lock);
            return prune(true);
        }

    private:
        /// Caller must the lock. Returns the number of elements removed.
        size_t prune(bool shrink = false) {
            const size_t maxAllowed = maxSize_ + (shrink ? 0 : elasticity_);
            if (k_nodeit_map.size() < maxAllowed) {
                return 0;
            }
            size_t count = 0;
            while (k_nodeit_map.size() > maxSize_) {
                k_nodeit_map.erase(nodes.back().key);
                nodes.pop_back();
                ++count;
            }
            return count;
        }
        /// Caller must hold the lock. Throws if not found.
        const Value & get_nolock(const Key & k) {
            const auto retPtr = get_nolock_nothrow(k);
            if (!retPtr)
                throw KeyNotFound();
            return *retPtr;
        }

        /// Caller must hold the lock. Throws if not found.
        const Value *get_nolock_nothrow(const Key & k) noexcept {
            const auto iter = k_nodeit_map.find(k);
            if (iter == k_nodeit_map.end())
                return nullptr;
            nodes.splice(nodes.begin(), nodes, iter->second);
            return &(iter->second->value);
        }

        // Disallow copying.
        Cache(const Cache &) = delete;
        Cache & operator=(const Cache &) = delete;

        mutable lock_type lock;
        map_type k_nodeit_map;
        list_type nodes;
        const size_t maxSize_;
        const size_t elasticity_;
    };

}  // namespace LRUCache

#ifdef __clang__
#pragma clang diagnostic pop
#endif
