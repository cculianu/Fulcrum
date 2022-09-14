// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 Calin A. Culianu <calin.culianu@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <algorithm>
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
    static_assert (std::is_pod_v<T> && std::is_trivially_destructible_v<T> && std::is_trivial_v<T>
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

    class iterator {
        T *ptr;

    public:
        using difference_type = Diff;
        using value_type = T;
        using pointer = T *;
        using reference = T &;
        using iterator_category = std::random_access_iterator_tag;
        iterator() : ptr(nullptr) {}
        iterator(T *ptr_) : ptr(ptr_) {}
        T &operator*() const { return *ptr; }
        T *operator->() const { return ptr; }
        T &operator[](size_type pos) { return ptr[pos]; }
        const T &operator[](size_type pos) const { return ptr[pos]; }
        iterator &operator++() {
            ++ptr;
            return *this;
        }
        iterator &operator--() {
            --ptr;
            return *this;
        }
        iterator operator++(int) {
            return iterator(ptr++);
        }
        iterator operator--(int) {
            return iterator(ptr--);
        }
        difference_type friend operator-(iterator a, iterator b) {
            return &*a - &*b;
        }
        iterator operator+(size_type n) { return iterator(ptr + n); }
        iterator &operator+=(size_type n) {
            ptr += n;
            return *this;
        }
        iterator operator-(size_type n) { return iterator(ptr - n); }
        iterator &operator-=(size_type n) {
            ptr -= n;
            return *this;
        }
        bool operator==(iterator x) const { return ptr == x.ptr; }
        bool operator!=(iterator x) const { return ptr != x.ptr; }
        bool operator>=(iterator x) const { return ptr >= x.ptr; }
        bool operator<=(iterator x) const { return ptr <= x.ptr; }
        bool operator>(iterator x) const { return ptr > x.ptr; }
        bool operator<(iterator x) const { return ptr < x.ptr; }
    };

    class reverse_iterator {
        T *ptr;

    public:
        using difference_type = Diff;
        using value_type = T;
        using pointer = T *;
        using reference = T &;
        using iterator_category = std::bidirectional_iterator_tag;
        reverse_iterator() : ptr(nullptr) {}
        reverse_iterator(T *ptr_) : ptr(ptr_) {}
        T &operator*() { return *ptr; }
        const T &operator*() const { return *ptr; }
        T *operator->() { return ptr; }
        const T *operator->() const { return ptr; }
        reverse_iterator &operator--() {
            ++ptr;
            return *this;
        }
        reverse_iterator &operator++() {
            --ptr;
            return *this;
        }
        reverse_iterator operator++(int) {
            return reverse_iterator(ptr--);
        }
        reverse_iterator operator--(int) {
            return reverse_iterator(ptr++);
        }
        bool operator==(reverse_iterator x) const { return ptr == x.ptr; }
        bool operator!=(reverse_iterator x) const { return ptr != x.ptr; }
    };

    class const_iterator {
        const T *ptr;

    public:
        using difference_type = Diff;
        using value_type = const T;
        using pointer = const T *;
        using reference = const T &;
        using iterator_category = std::random_access_iterator_tag;
        const_iterator() : ptr(nullptr) {}
        const_iterator(const T *ptr_) : ptr(ptr_) {}
        const_iterator(iterator x) : ptr(&(*x)) {}
        const T &operator*() const { return *ptr; }
        const T *operator->() const { return ptr; }
        const T &operator[](size_type pos) const { return ptr[pos]; }
        const_iterator &operator++() {
            ++ptr;
            return *this;
        }
        const_iterator &operator--() {
            --ptr;
            return *this;
        }
        const_iterator operator++(int) {
            return const_iterator(ptr++);
        }
        const_iterator operator--(int) {
            return const_iterator(ptr--);
        }
        difference_type friend operator-(const_iterator a, const_iterator b) {
            return &*a - &*b;
        }
        const_iterator operator+(size_type n) {
            return const_iterator(ptr + n);
        }
        const_iterator &operator+=(size_type n) {
            ptr += n;
            return *this;
        }
        const_iterator operator-(size_type n) {
            return const_iterator(ptr - n);
        }
        const_iterator &operator-=(size_type n) {
            ptr -= n;
            return *this;
        }
        bool operator==(const_iterator x) const { return ptr == x.ptr; }
        bool operator!=(const_iterator x) const { return ptr != x.ptr; }
        bool operator>=(const_iterator x) const { return ptr >= x.ptr; }
        bool operator<=(const_iterator x) const { return ptr <= x.ptr; }
        bool operator>(const_iterator x) const { return ptr > x.ptr; }
        bool operator<(const_iterator x) const { return ptr < x.ptr; }
    };

    class const_reverse_iterator {
        const T *ptr;

    public:
        using difference_type = Diff;
        using value_type = const T;
        using pointer = const T *;
        using reference = const T &;
        using iterator_category = std::bidirectional_iterator_tag;
        const_reverse_iterator() : ptr(nullptr) {}
        const_reverse_iterator(const T *ptr_) : ptr(ptr_) {}
        const_reverse_iterator(reverse_iterator x) : ptr(&(*x)) {}
        const T &operator*() const { return *ptr; }
        const T *operator->() const { return ptr; }
        const_reverse_iterator &operator--() {
            ++ptr;
            return *this;
        }
        const_reverse_iterator &operator++() {
            --ptr;
            return *this;
        }
        const_reverse_iterator operator++(int) {
            return const_reverse_iterator(ptr--);
        }
        const_reverse_iterator operator--(int) {
            return const_reverse_iterator(ptr++);
        }
        bool operator==(const_reverse_iterator x) const { return ptr == x.ptr; }
        bool operator!=(const_reverse_iterator x) const { return ptr != x.ptr; }
    };

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
    alignas(byte *) direct_or_indirect _union = {};
    size_type _size = 0;
    static_assert (alignof(byte *) % alignof(size_type) == 0 && sizeof(byte *) % alignof(size_type) == 0,
                   "size_type cannot have more restrictive alignment requirement than pointer");
    static_assert (alignof(byte *) % alignof(T) == 0,
                   "value_type T cannot have more restrictive alignment requirement than pointer");

    T *direct_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union.direct) + pos;
    }
    const T *direct_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union.direct) + pos;
    }
    T *indirect_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union.s.indirect) + pos;
    }
    const T *indirect_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union.s.indirect) + pos;
    }
    constexpr bool is_direct() const noexcept { return _size <= N; }

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
                _size -= N + 1;
            }
        } else {
            if (!is_direct()) {
                _union.s.indirect = reallocate(_union.s.indirect, sizeof(T) * new_capacity);
                _union.s.capacity = new_capacity;
            } else {
                byte *new_indirect = reallocate(nullptr, sizeof(T) * new_capacity);
                T *src = direct_ptr(0);
                T *dst = reinterpret_cast<T *>(new_indirect);
                std::memcpy(dst, src, size() * sizeof(T));
                _union.s.indirect = new_indirect;
                _union.s.capacity = new_capacity;
                _size += N + 1;
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

    template <typename InputIterator>
    static void fill(T *dst, InputIterator first, InputIterator last) {
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
        _size += increase;
    }


public:
    void assign(size_type n, const T &val) {
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        _size += n;
        fill(item_ptr(0), n, val);
    }

    template <typename InputIterator>
    void assign(InputIterator first, InputIterator last) {
        size_type n = last - first;
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        _size += n;
        fill(item_ptr(0), first, last);
    }

    constexpr prevector() noexcept = default;

    explicit prevector(size_type n) { resize(n); }

    explicit prevector(size_type n, const T &val) {
        change_capacity(n);
        _size += n;
        fill(item_ptr(0), n, val);
    }

    template <typename InputIterator>
    prevector(InputIterator first, InputIterator last) {
        size_type n = last - first;
        change_capacity(n);
        _size += n;
        fill(item_ptr(0), first, last);
    }

    prevector(const prevector &other) {
        size_type n = other.size();
        change_capacity(n);
        _size += n;
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

    size_type size() const noexcept { return is_direct() ? _size : _size - N - 1; }

    bool empty() const noexcept { return size() == 0; }

    iterator begin() { return iterator(item_ptr(0)); }
    const_iterator begin() const { return const_iterator(item_ptr(0)); }
    iterator end() { return iterator(item_ptr(size())); }
    const_iterator end() const { return const_iterator(item_ptr(size())); }

    reverse_iterator rbegin() { return reverse_iterator(item_ptr(size() - 1)); }
    const_reverse_iterator rbegin() const {
        return const_reverse_iterator(item_ptr(size() - 1));
    }
    reverse_iterator rend() { return reverse_iterator(item_ptr(-1)); }
    const_reverse_iterator rend() const {
        return const_reverse_iterator(item_ptr(-1));
    }

    size_t capacity() const noexcept {
        if (is_direct()) {
            return N;
        } else {
            return _union.s.capacity;
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
        _size++;
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
        _size += count;
        fill(item_ptr(p), count, value);
    }

    template <typename InputIterator>
    void insert(iterator pos, InputIterator first, InputIterator last) {
        size_type p = pos - begin();
        difference_type count = last - first;
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        T *ptr = item_ptr(p);
        std::memmove(ptr + count, ptr, (size() - p) * sizeof(T));
        _size += count;
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
        _size -= last - p;
        std::memmove(&*first, &*last, endp - reinterpret_cast<byte *>(&*last));
        return first;
    }

    template <typename... Args> void emplace_back(Args &&...args) {
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        new (item_ptr(size())) T(std::forward<Args>(args)...);
        _size++;
    }

    void push_back(const T &value) { emplace_back(value); }

    void pop_back() { erase(end() - 1, end()); }

    T &front() noexcept { return *item_ptr(0); }

    const T &front() const noexcept { return *item_ptr(0); }

    T &back() noexcept { return *item_ptr(size() - 1); }

    const T &back() const noexcept { return *item_ptr(size() - 1); }

    void swap(prevector &other) noexcept {
        if (&other != this) {
            std::swap(_union, other._union);
            std::swap(_size, other._size);
        }
    }

    ~prevector() noexcept {
        if (!is_direct()) {
            std::free(_union.s.indirect);
            _union.s.indirect = nullptr;
        }
    }

    bool operator==(const prevector &other) const {
        if (other.size() != size())
            return false;
        return std::equal(begin(), end(), other.begin());
    }

    bool operator!=(const prevector &other) const {
        return !(*this == other);
    }

    bool operator<(const prevector &other) const {
        if (size() < other.size())
            return true;
        if (size() > other.size())
            return false;
        auto [it, oit] = std::mismatch(begin(), end(), other.begin());
        return it != end() && *it < *oit;
    }

    size_t allocated_memory() const {
        if (is_direct()) {
            return 0;
        } else {
            return sizeof(T) * _union.s.capacity;
        }
    }

    value_type *data() noexcept { return item_ptr(0); }

    const value_type *data() const noexcept { return item_ptr(0); }
};
} // namespace bitcoin
