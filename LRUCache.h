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
     *      threadSafe - a compile-time boolean that decides a real mutex will be used to guarantee thread
     *                   safety if set to true, otherwise no locking is done in get/insert/remove, etc.
     *      Key        - key type (keys will be stored twice for each item in the cache so use a lightweight type or an
     *                   implicitly-shared, reference-counted type here)
     *      Value      - value type (values must be copy-constructible)
     *
     * According to STL, order of templates has effect on throughput. That's why I've moved the boolean to the front.
     * https://www.reddit.com/r/cpp/comments/ahp6iu/compile_time_binary_size_reductions_and_cs_future/eeguck4/
     */
    template <bool threadSafe, typename Key, typename Value, typename Hasher = robin_hood::hash<Key>>
    class Cache {
        struct NullLock {};
        struct NullGuard { NullGuard(const NullLock &) {} };
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
            Guard g(lock_);
            return cache_.size();
        }
        bool empty() const {
            Guard g(lock_);
            return cache_.empty();
        }
        size_t maxSize() const { return maxSize_; }
        size_t elasticity() const { return elasticity_; }
        size_t maxAllowedSize() const { return maxSize_ + elasticity_; }

        void clear() {
            Guard g(lock_);
            cache_.clear();
            keys_.clear();
        }
        /// Inserts a new item into the cache. If the specified key `k` was already in the cache, its associated value
        /// will be overwritten with `v` via operator=.  Returns true if a new item was inserted, or false if an
        /// existing item was overwritten.  In either case the new value `v` will be in the cache upon function return.
        bool insert(const Key & k, const Value & v) {
            Guard g(lock_);
            const auto iter = cache_.find(k);
            if (iter != cache_.end()) {
                iter->second->value = v; // overwrite existing value
                keys_.splice(keys_.begin(), keys_, iter->second);
                return false;
            }

            keys_.emplace_front(k, v);
            cache_[k] = keys_.begin();
            prune();
            return true;
        }
        /// Like get() below, but does not throw but instead uses an optional to communicate whether the key was found
        /// or not.  Note that this function will only work correctly if exceptions are enabled at compile-time.
        std::optional<Value> tryGet(const Key & key) noexcept {
            std::optional<Value> ret;
            try {
                Guard g(lock_);
                ret.emplace(get_nolock(key));
            } catch (const KeyNotFound &) {}
            return ret;
        }
        /// Gets a copy-constructed version of the internally stored value.
        /// May throw KeyNotFound if the key is not in the cache.
        Value get(const Key & key) {
            Guard g(lock_);
            return get_nolock(key);
        }
        /// Returns a reference to the internally stored value. Does not use any locks. Use this version only in
        /// code where threadSafe=false. Otherwise it will not be offered because SFINAE will exlcude it
        /// from being emitted.  May throw KeyNotFound if `key` is not found in the cache.
        template <std::enable_if_t<std::is_same_v<Guard, NullGuard>, int> = 0>
        const Value & getRef(const Key &key) { return get_nolock(key); }

        /// Removes an item from the cache. Returns true if an item was removed or false otherwise.
        bool remove(const Key & k) {
            Guard g(lock_);
            auto iter = cache_.find(k);
            if (iter == cache_.end()) {
                return false;
            }
            keys_.erase(iter->second);
            cache_.erase(iter);
            return true;
        }

        bool contains(const Key & k) const {
            Guard g(lock_);
            return cache_.find(k) != cache_.end();
        }

        /// Walk over every item in the cache. Pass a functor that will be called as: func(const KeyValuePair &) for
        /// every item in the cache. The lock will be held while this walk is doen if threadSafe=true
        template <typename F>
        void cwalk(const F & f) const {
            Guard g(lock_);
            std::for_each(keys_.begin(), keys_.end(), f);
        }

    private:
        /// Caller must the lock. Returns the number of elements removed.
        size_t prune() {
            const size_t maxAllowed = maxSize_ + elasticity_;
            if (cache_.size() < maxAllowed) {
                return 0;
            }
            size_t count = 0;
            while (cache_.size() > maxSize_) {
                cache_.erase(keys_.back().key);
                keys_.pop_back();
                ++count;
            }
            return count;
        }
        /// Caller must hold the lock. Throws if not found.
        const Value & get_nolock(const Key & k) {
            const auto iter = cache_.find(k);
            if (iter == cache_.end())
                throw KeyNotFound();
            keys_.splice(keys_.begin(), keys_, iter->second);
            return iter->second->value;
        }

        // Disallow copying.
        Cache(const Cache &) = delete;
        Cache & operator=(const Cache &) = delete;

        mutable lock_type lock_;
        map_type cache_;
        list_type keys_;
        const size_t maxSize_;
        const size_t elasticity_;
    };

}  // namespace LRUCache

#ifdef __clang__
#pragma clang diagnostic pop
#endif
