// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2020 The Bitcoin developers
// Copyright (c) 2021 Calin A. Culianu <calin.culianu@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#pragma once

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <type_traits>

/** A Span is an object that can refer to a contiguous sequence of objects.
 *
 * It implements a subset of C++20's std::span.
 */
template <typename C> class Span {
    C *m_data{};
    std::size_t m_size{};

public:
    constexpr Span() noexcept = default;
    constexpr Span(C *data, std::size_t size) noexcept : m_data(data), m_size(size) {}
    constexpr Span(C *data, C *end) noexcept : m_data(data), m_size(end >= data ? end - data : 0) {}

    /** Implicit conversion of spans between compatible types.
     *
     *  Specifically, if a pointer to an array of type O can be implicitly converted to a pointer to an array of type
     *  C, then permit implicit conversion of Span<O> to Span<C>. This matches the behavior of the corresponding
     *  C++20 std::span constructor.
     *
     *  For example this means that a Span<T> can be converted into a Span<const T>.
     */
    template <typename O, typename std::enable_if_t<std::is_convertible_v<O (*)[], C (*)[]>, int> = 0>
    constexpr Span(const Span<O>& other) noexcept : m_data(other.m_data), m_size(other.m_size) {}

    /** Default copy constructor. */
    constexpr Span(const Span&) noexcept = default;

    /** Default assignment operator. */
    Span& operator=(const Span& other) noexcept = default;

    constexpr C *data() const noexcept { return m_data; }
    constexpr C *begin() const noexcept { return m_data; }
    constexpr C *end() const noexcept { return m_data + m_size; }
    constexpr std::size_t size() const noexcept { return m_size; }
    constexpr bool empty() const noexcept { return size() == 0; }
    constexpr C &operator[](std::size_t pos) const noexcept { return m_data[pos]; }
    constexpr C &front() const noexcept { return *begin(); }
    constexpr C &back() const noexcept { return *(end()-1); }

    constexpr Span<C> subspan(std::size_t offset) const noexcept {
        return offset <= m_size ? Span<C>(m_data + offset, m_size - offset) : Span<C>(end(), std::size_t{0});
    }
    constexpr Span<C> subspan(std::size_t offset, std::size_t count) const noexcept {
        return offset + count <= m_size ? Span<C>(m_data + offset, count) : Span<C>(end(), std::size_t{0});
    }
    constexpr Span<C> first(std::size_t count) const noexcept {
        return count <= m_size ? Span<C>(m_data, count) : Span<C>(begin(), std::size_t{0});
    }
    constexpr Span<C> last(std::size_t count) const noexcept {
        return count <= m_size ? Span<C>(m_data + m_size - count, count) : Span<C>(end(), std::size_t{0});
    }

    /** Pop the last element off, and return a reference to that element.
        Span must not be empty(); span will decrease in size by 1, having its end() moved back by 1.
        Throws std::out_of_range if the span was empty. */
    constexpr C & pop_back() {
        if (empty()) throw std::out_of_range("Span pop_back failed: empty");
        return m_data[--m_size];
    }

    /** Pop the last element off, and return a reference to that element.
        Span must not be empty(); span will decrease in size by 1, having its begin() moved up by 1. */
    constexpr C & pop_front() {
        if (empty()) throw std::out_of_range("Span pop_back failed: empty");
        --m_size;
        return *m_data++;
    }

    friend constexpr bool operator==(const Span &a, const Span &b) noexcept {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
    }
    friend constexpr bool operator!=(const Span &a, const Span &b) noexcept {
        return !(a == b);
    }
    friend constexpr bool operator<(const Span &a, const Span &b) noexcept {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    }
    friend constexpr bool operator<=(const Span &a, const Span &b) noexcept {
        return !(b < a);
    }
    friend constexpr bool operator>(const Span &a, const Span &b) noexcept {
        return b < a;
    }
    friend constexpr bool operator>=(const Span &a, const Span &b) noexcept {
        return !(a < b);
    }

    /** Ensures the convertible-to constructor works */
    template <typename O> friend class Span;
};

/** Create a Span from a container exposing data() and size(), or from an array.
 *
 * This correctly deals with constness: the returned Span's element type will be
 * whatever data() returns a pointer to. If either the passed container is
 * const, or its element type is const, the resulting span will have a const
 * element type.
 *
 * std::span will have a constructor that implements this functionality
 * directly.
 */

/** Create a span from a C-style array */
template <typename A, std::size_t N>
constexpr Span<A> MakeSpan(A (&a)[N]) { return Span<A>(a, N); }

/** Like the above, but forces Span<const A> */
template <typename A, std::size_t N>
constexpr Span<A> MakeCSpan(const A (&a)[N]) { return Span<const A>(a, N); }

/** Create a Span from any container that has .data() and .size() */
template <typename V>
constexpr auto MakeSpan(V &v) {
    using ContainerValueType = typename std::remove_pointer_t<decltype(std::declval<V>().data())>;
    return Span<ContainerValueType>(v.data(), v.size());
}

/** Create a Span<const value_type> from any container that has .data() and .size() */
template <typename V>
constexpr auto MakeCSpan(const V &v) { return MakeSpan(v); }
