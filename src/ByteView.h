//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>

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
class ByteView: public std::basic_string_view<std::byte>
{
    template <typename CharT, typename T, typename = std::enable_if_t<sizeof(CharT) == 1>>
    static const CharT *ptr_cast(const T *t) noexcept {
        // This single line of code here prevents all the methods of this class from being constexpr :/
        return reinterpret_cast<const CharT *>(t);
    }
    // type trait to exclude C arrays but accept std::array
    template<typename T> struct is_std_array : std::false_type {};
    template<typename T, std::size_t N> struct is_std_array<std::array<T,N>> : std::true_type {};
    template<typename T> static constexpr bool is_std_array_v = is_std_array<T>::value;

public:
    using Base = std::basic_string_view<std::byte>;
    using Base::basic_string_view; // inherit constructors

    /// Construct a ByteView from any POD data item or C array (but not a std::array)
    template<typename T, std::enable_if_t<std::is_pod_v<T> && !std::is_pointer_v<T> && !is_std_array_v<T>
                                          && std::has_unique_object_representations_v<T>
                                          && (!std::is_array_v<T> || !std::is_pointer_v<std::remove_all_extents_t<T>>), int> = 0>
    ByteView(const T &t) noexcept
        : ByteView(ptr_cast<std::byte>(&t), sizeof(t)) {}

    /// Construct a ByteView from any container that offers a .data() method that is a pointer to POD data,
    /// and a .size() method -- such as QByteArray, std::vector, QString, std::array, etc.
    template<typename T,
             std::enable_if_t<std::is_same_v<QString, T> /* special case for QString */ ||
                              (std::is_pointer_v<decltype(std::declval<const T>().data())>
                               && std::is_integral_v<decltype(std::declval<const T>().size())>
                               && std::is_pod_v<std::remove_pointer_t<decltype(std::declval<const T>().data())>>
                               && !std::is_pointer_v<std::remove_pointer_t<decltype(std::declval<const T>().data())>>), int> = 0>
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
        return deepCopy ? QByteArray{charData(), int(size())}
                        : QByteArray::fromRawData(charData(), int(size()));
    }
};

/// String literal -> ByteView e.g.: "foo"_bv or "\x01\xff\x07\xab"_bv
inline ByteView operator "" _bv(const char *str, std::size_t len) noexcept {
    return std::string_view{str, len}; // goes through template c'tor above..
}
