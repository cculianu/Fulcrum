//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <QByteArray>
#include <QChar>
#include <QString>

#include <algorithm>
#include <array>
#include <concepts> // for std::integral
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <type_traits>

/// A pointer & size pair... intended to be used to encapsulate arguments to
/// functions that accept generic byte blobs (such as a hasher, bloom filter,
/// etc).
///
/// The purpose of this class is to offer some automatic type conversions from
/// e.g. QByteArray, std::vector<podtype>, uint256, double, int... -> ByteView,
/// which then can get passed to a hasher function.
///
/// Warning: This class is just like string_view, except it holds a
/// `const std::byte *`.  As such, do *not* keep instances around unless the
/// data being pointed-to is guaranteed to live for longer than the lifetime of
/// the ByteView instance.
class ByteView
{
    template <typename CharT, typename T> requires (sizeof(CharT) == 1 && !std::is_same_v<CharT, bool>)
    static const CharT *ptr_cast(const T *t) noexcept {
        // This single line of code here prevents all the methods of this class from being constexpr :/
        return reinterpret_cast<const CharT *>(t);
    }
    // type trait to exclude C arrays but accept std::array
    template<typename T> struct is_std_array : std::false_type {};
    template<typename T, std::size_t N> struct is_std_array<std::array<T,N>> : std::true_type {};
    template<typename T> static constexpr bool is_std_array_v = is_std_array<T>::value;
    template<typename T> static constexpr bool is_pod_v = std::is_standard_layout_v<T> && std::is_trivial_v<T>; // C++20 deprecated std::is_pod_v so we must do this

public:
    using value_type = const std::byte;
    using size_type = std::size_t;
    using reference = value_type &;
    using pointer = value_type *;
    static constexpr auto npos = ~size_type{};

    constexpr ByteView() noexcept = default;
    constexpr ByteView(pointer p, size_type sz) noexcept : m_data{p}, m_size{sz} {}
    constexpr ByteView(const ByteView &) noexcept = default;
    constexpr ByteView & operator=(const ByteView &) noexcept = default;
    constexpr ByteView(ByteView &&) noexcept = default;
    constexpr ByteView & operator=(ByteView &&) noexcept = default;

    inline constexpr size_type size() const noexcept { return m_size; }
    inline constexpr pointer begin() const noexcept { return m_data; }
    inline constexpr pointer end() const noexcept { return m_data + m_size; }
    inline constexpr pointer data() const noexcept { return m_data; }

    inline constexpr bool empty() const noexcept { return m_size == 0u; }
    inline constexpr reference front() const noexcept { return m_data[0]; }
    inline constexpr reference back() const noexcept { return m_data[m_size - 1u]; }
    inline constexpr reference operator[](size_type i) const noexcept { return m_data[i]; }
    inline constexpr reference at(size_type i) const {
        if (i >= m_size) throw std::out_of_range("ByteView::at(): index out of range");
        return m_data[i];
    }

    /// Construct a ByteView from any POD data item or C array (but not a std::array)
    template<typename T> requires (is_pod_v<T> && !std::is_pointer_v<T> && !is_std_array_v<T>
                                   && std::has_unique_object_representations_v<T>
                                   && (!std::is_array_v<T> || !std::is_pointer_v<std::remove_all_extents_t<T>>))
    ByteView(const T &t) noexcept
        : ByteView(ptr_cast<std::byte>(&t), sizeof(t)) {}

    /// Construct a ByteView from any container that offers a .data() method that is a pointer to POD data,
    /// and a .size() method -- such as QByteArray, std::vector, QString, std::array, etc.
    template<typename T>
        requires std::is_same_v<QString, T> /* special case for QString */ ||
        requires(const T t) { requires std::is_pointer_v<decltype(t.data())>;
                              { t.size() } -> std::integral;
                              requires is_pod_v<std::remove_pointer_t<decltype(t.data())>>;
                              requires std::has_unique_object_representations_v<std::remove_pointer_t<decltype(t.data())>>;
                              requires !std::is_pointer_v<std::remove_pointer_t<decltype(t.data())>>; }
    ByteView(const T &t) noexcept
        : ByteView(ptr_cast<std::byte>(t.data()), t.size() * sizeof(*t.data())) {
        static_assert (!std::is_same_v<T, QString>
                       || (std::is_same_v<const QChar *, decltype(t.data())> && sizeof(QChar) == sizeof(uint16_t)
                           && std::has_unique_object_representations_v<QChar>),
                       "Assumption for QString is that QChar is essentially a uint16_t");
    }
    const char * charData() const noexcept { return ptr_cast<char>(data()); }
    const uint8_t * ucharData() const noexcept { return ptr_cast<uint8_t>(data()); }

    std::string_view toStringView() const noexcept { return std::string_view{charData(), size()}; }

    QByteArray toByteArray(bool deepCopy = true) const {
        return deepCopy ? QByteArray{charData(), QByteArray::size_type(size())}
                        : QByteArray::fromRawData(charData(), QByteArray::size_type(size()));
    }

    // Convnenience
    constexpr ByteView substr(size_type pos = 0, size_type count = npos) const noexcept {
        if (pos >= size()) return ByteView{};
        return ByteView(data() + pos, std::min(size() - pos, count));
    }

    constexpr int compare(const ByteView &o) const noexcept {
        auto p = begin(), e = end(), op = o.begin(), oe = o.end();
        if (data() == o.data()) { // fast-path for same ptr
            if (size() == o.size()) return 0;
            else if (size() < o.size()) return -1;
            return 1;
        }
        while (p != e && op != oe) {
            if (const int diff = static_cast<int>(*p++) - static_cast<int>(*op++); diff != 0)
                return diff < 0 ? -1 : 1;
        }
        if (p == e && op != oe) return -1;
        if (p != e && op == oe) return 1;
        return 0;
    }

    // Operators
    constexpr bool operator==(const ByteView &o) const noexcept {
        if (size() != o.size()) return false;
        if (data() == o.data()) return true; // fast-path for same ptr
        auto p = begin(), e = end(), op = o.begin();
        while (p != e) {
            if (*p++ != *op++) return false;
        }
        return true;
    }

    constexpr bool operator!=(const ByteView &o) const noexcept { return ! this->operator==(o); }

    constexpr bool operator<(const ByteView &o) const noexcept { return compare(o) < 0; }
    constexpr bool operator<=(const ByteView &o) const noexcept { return compare(o) <= 0; }
    constexpr bool operator>=(const ByteView &o) const noexcept { return compare(o) >= 0; }
    constexpr bool operator>(const ByteView &o) const noexcept { return compare(o) > 0; }

private:
    pointer m_data{};
    size_type m_size{};
};

/// String literal -> ByteView e.g.: "foo"_bv or "\x01\xff\x07\xab"_bv
inline ByteView operator "" _bv(const char *str, std::size_t len) noexcept {
    return std::string_view{str, len}; // goes through template c'tor above..
}
