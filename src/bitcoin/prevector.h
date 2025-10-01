// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

static_assert(__cplusplus >= 202000L, "C++20 is required to compile this file");
#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <new> // for std::bad_alloc
#include <type_traits>

namespace bitcoin {
/**
 * Implements a drop-in replacement for std::vector<T> which stores up to N
 * elements directly (without heap allocation). The types Size and Diff are used
 * to store element counts, and can be any unsigned + signed type.
 *
 * Storage layout is either:
 * - Direct allocation:
 *   - Size _size: the number of used elements (between 0 and N)
 *   - T direct[N]: an array of N elements of type T
 *     (only the first _size are initialized).
 * - Indirect allocation:
 *   - Size _size: the number of used elements plus N + 1
 *   - Size capacity: the number of allocated elements
 *   - T* indirect: a pointer to an array of capacity elements of type T
 *     (only the first _size are initialized).
 *
 * The data type T must be movable by memmove/realloc(). Once we switch to C++,
 * move constructors can be used instead.
 */
template <unsigned int N, typename T, typename Size = uint32_t, typename Diff = int32_t>
class prevector {
    static_assert (std::is_standard_layout_v<T> && std::is_trivially_destructible_v<T> && std::is_trivial_v<T>
                   && sizeof(Size) == sizeof(Diff) && std::is_integral_v<Size>
                   && std::is_integral_v<Diff> && std::is_unsigned_v<Size> && std::is_signed_v<Diff>
                   && sizeof(Size) >= 4);
    using byte = std::byte;
public:
    using size_type = Size;
    using difference_type = Diff;
    using value_type = T;
    using reference = value_type &;
    using const_reference = const value_type &;
    using pointer = value_type *;
    using const_pointer = const value_type *;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

private:
#pragma pack(push,1) // push alignment 1 onto alignment stack /* Calin asks: Is this always safe on every arch?! */
    union direct_or_indirect {
        byte direct[sizeof(T) * N];
        struct S {
            byte *indirect;
            size_type capacity;
        } s;
    };
#pragma pack(pop)
    alignas(byte *) direct_or_indirect m_union = {};
    size_type m_size = 0;
    static_assert (alignof(byte *) % alignof(size_type) == 0 && sizeof(byte *) % alignof(size_type) == 0,
                   "size_type cannot have more restrictive alignment requirement than pointer");
    static_assert (alignof(byte *) % alignof(T) == 0,
                   "value_type T cannot have more restrictive alignment requirement than pointer");

    T *direct_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(m_union.direct) + pos;
    }
    const T *direct_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(m_union.direct) + pos;
    }
    T *indirect_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(m_union.s.indirect) + pos;
    }
    const T *indirect_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(m_union.s.indirect) + pos;
    }
    constexpr bool is_direct() const noexcept { return m_size <= N; }

    static byte *reallocate(byte *ptr, std::size_t nbytes) {
        // Modified by Calin: the original code asserted to check malloc.
        // Instead, we follow the C++ spec and call new_handler until
        // the allocation succeeds if there is a new_handler. If not, we
        // throw bad_alloc().
        for (;;) {
            if (byte *ret = static_cast<byte *>(std::realloc(ptr, nbytes)); ret)
                return ret;
            if (auto *new_handler = std::get_new_handler(); new_handler)
                new_handler();
            else
                throw std::bad_alloc();
        }
    }

    void change_capacity(size_type new_capacity) {
        if (new_capacity <= N) {
            if (!is_direct()) {
                T *indirect = indirect_ptr(0);
                T *src = indirect;
                T *dst = direct_ptr(0);
                std::memcpy(dst, src, size() * sizeof(T));
                std::free(indirect);
                m_size -= N + 1;
            }
        } else {
            if (!is_direct()) {
                m_union.s.indirect = reallocate(m_union.s.indirect, sizeof(T) * new_capacity);
                m_union.s.capacity = new_capacity;
            } else {
                byte *new_indirect = reallocate(nullptr, sizeof(T) * new_capacity);
                T *src = direct_ptr(0);
                T *dst = reinterpret_cast<T *>(new_indirect);
                std::memcpy(dst, src, size() * sizeof(T));
                m_union.s.indirect = new_indirect;
                m_union.s.capacity = new_capacity;
                m_size += N + 1;
            }
        }
    }

    T *item_ptr(difference_type pos) noexcept {
        return is_direct() ? direct_ptr(pos) : indirect_ptr(pos);
    }
    const T *item_ptr(difference_type pos) const noexcept {
        return is_direct() ? direct_ptr(pos) : indirect_ptr(pos);
    }

    static void fill(T *dst, size_type count) noexcept {
        // always a trivially constructible type; we can use memset() to avoid looping.
        std::memset(dst, 0, count * sizeof(T));
    }

    static void fill(T *dst, size_type count, const T &value) noexcept(std::is_nothrow_copy_constructible_v<T>) {
        T * const endp = dst + count;
        while (dst < endp)
            new (static_cast<void *>(dst++)) T(value);
    }

    template <std::input_iterator It>
    static void fill(T *dst, It first, It last) {
        while (first != last)
            new (static_cast<void *>(dst++)) T(*first++);
    }

    void resize_common(const size_type new_size, const bool uninitialized) {
        const size_type cur_size = size();
        if (cur_size == new_size) {
            return;
        }
        if (cur_size > new_size) {
            erase(item_ptr(new_size), end());
            return;
        }
        if (new_size > capacity()) {
            change_capacity(new_size);
        }
        const size_type increase = new_size - cur_size;
        if (!uninitialized) fill(item_ptr(cur_size), increase);
        m_size += increase;
    }


public:
    void assign(size_type n, const T &val) {
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        m_size += n;
        fill(item_ptr(0), n, val);
    }

    template <std::random_access_iterator It>
    void assign(It first, It last) {
        size_type n = last - first;
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        m_size += n;
        fill(item_ptr(0), first, last);
    }

    constexpr prevector() noexcept = default;

    explicit prevector(size_type n) { resize(n); }

    explicit prevector(size_type n, const T &val) {
        change_capacity(n);
        m_size += n;
        fill(item_ptr(0), n, val);
    }

    template <std::random_access_iterator It>
    prevector(It first, It last) {
        size_type n = last - first;
        change_capacity(n);
        m_size += n;
        fill(item_ptr(0), first, last);
    }

    prevector(const prevector &other) {
        size_type n = other.size();
        change_capacity(n);
        m_size += n;
        fill(item_ptr(0), other.begin(), other.end());
    }

    prevector(prevector &&other) noexcept { swap(other); }

    prevector &operator=(const prevector &other) {
        if (&other == this) {
            return *this;
        }
        assign(other.begin(), other.end());
        return *this;
    }

    prevector &operator=(prevector &&other) noexcept {
        swap(other);
        return *this;
    }

    size_type size() const noexcept { return is_direct() ? m_size : m_size - N - 1; }

    bool empty() const noexcept { return size() == 0; }

    iterator begin() { return iterator(item_ptr(0)); }
    const_iterator begin() const { return const_iterator(item_ptr(0)); }
    iterator end() { return iterator(item_ptr(size())); }
    const_iterator end() const { return const_iterator(item_ptr(size())); }

    reverse_iterator rbegin() { return reverse_iterator(end()); }
    const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
    reverse_iterator rend() { return reverse_iterator(begin()); }
    const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }

    size_t capacity() const noexcept {
        if (is_direct()) {
            return N;
        } else {
            return m_union.s.capacity;
        }
    }

    static constexpr size_t static_capacity() { return N; }

    T &operator[](size_type pos) noexcept { return *item_ptr(pos); }

    const T &operator[](size_type pos) const noexcept { return *item_ptr(pos); }

    void resize(size_type new_size) { resize_common(new_size, false); }
    void resize_uninitialized(size_type new_size) { resize_common(new_size, true); }

    void reserve(size_type new_capacity) {
        if (new_capacity > capacity()) {
            change_capacity(new_capacity);
        }
    }

    void shrink_to_fit() { change_capacity(size()); }

    void clear() { resize(0); }

    iterator insert(iterator pos, const T &value) {
        size_type p = pos - begin();
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        T *ptr = item_ptr(p);
        std::memmove(ptr + 1, ptr, (size() - p) * sizeof(T));
        ++m_size;
        new (static_cast<void *>(ptr)) T(value);
        return iterator(ptr);
    }

    void insert(iterator pos, size_type count, const T &value) {
        size_type p = pos - begin();
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        T *ptr = item_ptr(p);
        std::memmove(ptr + count, ptr, (size() - p) * sizeof(T));
        m_size += count;
        fill(item_ptr(p), count, value);
    }

    template <std::random_access_iterator It>
    void insert(iterator pos, It first, It last) {
        size_type p = pos - begin();
        difference_type count = last - first;
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        T *ptr = item_ptr(p);
        std::memmove(ptr + count, ptr, (size() - p) * sizeof(T));
        m_size += count;
        fill(ptr, first, last);
    }

    iterator erase(iterator pos) { return erase(pos, pos + 1); }

    iterator erase(iterator first, iterator last) noexcept {
        // Erase is not allowed to the change the object's capacity. That means
        // that when starting with an indirectly allocated prevector with
        // size and capacity > N, the result may be a still indirectly allocated
        // prevector with size <= N and capacity > N. A shrink_to_fit() call is
        // necessary to switch to the (more efficient) directly allocated
        // representation (with capacity N and size <= N).
        iterator p = first;
        byte *const endp = reinterpret_cast<byte *>(&*end());
        m_size -= last - p;
        std::memmove(&*first, &*last, endp - reinterpret_cast<byte *>(&*last));
        return first;
    }

    template <typename... Args> void emplace_back(Args &&...args) {
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        new (item_ptr(size())) T(std::forward<Args>(args)...);
        ++m_size;
    }

    void push_back(const T &value) { emplace_back(value); }

    void pop_back() { erase(end() - 1, end()); }

    T &front() noexcept { return *item_ptr(0); }

    const T &front() const noexcept { return *item_ptr(0); }

    T &back() noexcept { return *item_ptr(size() - 1); }

    const T &back() const noexcept { return *item_ptr(size() - 1); }

    void swap(prevector &other) noexcept {
        if (&other != this) {
            std::swap(m_union, other.m_union);
            std::swap(m_size, other.m_size);
        }
    }

    ~prevector() noexcept {
        if (!is_direct()) {
            std::free(m_union.s.indirect);
            m_union.s.indirect = nullptr;
        }
    }

    // This is not exactly a lex compare. It is a size-wise compare and only if sizes are equal do we do a deep compare.
    auto operator<=>(const prevector &o) const {
        if (this == &o) return std::strong_ordering::equal; // short-circuit for same instance
        const auto sz = size(), osz = o.size();
        if (sz < osz) return std::strong_ordering::less;
        else if (sz > osz) return std::strong_ordering::greater;
        return std::lexicographical_compare_three_way(begin(), end(), o.begin(), o.end());
    }

    bool operator==(const prevector &other) const { return this->operator<=>(other) == 0; }

    size_t allocated_memory() const {
        if (is_direct()) {
            return 0;
        } else {
            return sizeof(T) * m_union.s.capacity;
        }
    }

    value_type *data() noexcept { return item_ptr(0); }

    const value_type *data() const noexcept { return item_ptr(0); }
};
} // namespace bitcoin
