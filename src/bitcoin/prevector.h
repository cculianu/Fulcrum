// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2021 Calin A. Culianu <calin.culianu@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PREVECTOR_H
#define BITCOIN_PREVECTOR_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <new> // for std::bad_alloc
#include <type_traits>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#endif

namespace bitcoin {
#pragma pack(push,1) // push alignment 1 onto alignment stack /* Calin asks: Is this always safe on every arch?! */
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
    static_assert (std::is_pod_v<T> && std::is_trivially_destructible_v<T> && std::is_trivially_copyable_v<T>
                   && std::is_trivially_constructible_v<T> && sizeof(Size) == sizeof(Diff) && std::is_integral_v<Size>
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
    size_type _size;
    union direct_or_indirect {
        byte direct[sizeof(T) * N];
        struct {
            size_type capacity;
            byte *indirect;
        };
    } _union;

    T *direct_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union.direct) + pos;
    }
    const T *direct_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union.direct) + pos;
    }
    T *indirect_ptr(difference_type pos) noexcept {
        return reinterpret_cast<T *>(_union.indirect) + pos;
    }
    const T *indirect_ptr(difference_type pos) const noexcept {
        return reinterpret_cast<const T *>(_union.indirect) + pos;
    }
    constexpr bool is_direct() const noexcept { return _size <= N; }

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
                // FIXME: Because malloc/realloc here won't call new_handler if
                // allocation fails, assert success. These should instead use an
                // allocator or new/delete so that handlers are called as
                // necessary, but performance would be slightly degraded by
                // doing so.
                // Modified by Calin: the original code asserted here to check
                // malloc. Instead, we throw bad_alloc() on failed allocation.
                byte *new_indirect = static_cast<byte *>(std::realloc(_union.indirect, sizeof(T) * new_capacity));
                if (!new_indirect) throw std::bad_alloc();
                _union.indirect = new_indirect;
                _union.capacity = new_capacity;
            } else {
                byte *new_indirect = static_cast<byte *>(std::malloc(sizeof(T) * new_capacity));
                if (!new_indirect) throw std::bad_alloc();
                T *src = direct_ptr(0);
                T *dst = reinterpret_cast<T *>(new_indirect);
                std::memcpy(dst, src, size() * sizeof(T));
                _union.indirect = new_indirect;
                _union.capacity = new_capacity;
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

    constexpr prevector() noexcept : _size(0), _union{{}} {}

    explicit prevector(size_type n) : prevector() { resize(n); }

    explicit prevector(size_type n, const T &val) : prevector() {
        change_capacity(n);
        _size += n;
        fill(item_ptr(0), n, val);
    }

    template <typename InputIterator>
    prevector(InputIterator first, InputIterator last) : prevector() {
        size_type n = last - first;
        change_capacity(n);
        _size += n;
        fill(item_ptr(0), first, last);
    }

    prevector(const prevector &other) : prevector() {
        size_type n = other.size();
        change_capacity(n);
        _size += n;
        fill(item_ptr(0), other.begin(), other.end());
    }

    prevector(prevector &&other) noexcept : prevector() {
        swap(other);
    }

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
            return _union.capacity;
        }
    }

    T &operator[](size_type pos) noexcept { return *item_ptr(pos); }

    const T &operator[](size_type pos) const noexcept { return *item_ptr(pos); }

    void resize(size_type new_size) {
        size_type cur_size = size();
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
        size_type increase = new_size - cur_size;
        fill(item_ptr(cur_size), increase);
        _size += increase;
    }

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

    void push_back(const T &value) {
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        new (item_ptr(size())) T(value);
        _size++;
    }

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
            std::free(_union.indirect);
            _union.indirect = nullptr;
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
            return sizeof(T) * _union.capacity;
        }
    }

    value_type *data() noexcept { return item_ptr(0); }

    const value_type *data() const noexcept { return item_ptr(0); }
};
#pragma pack(pop) // pop back previous alignment
} // namespace bitcoin
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif // BITCOIN_PREVECTOR_H
