//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "ByteView.h"
#include "Span.h"

#include <QByteArray>
#include <QString>

#include <algorithm>
#include <array>
#include <bit>
#include <concepts> // for std::integral
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <type_traits>


/// A class for serializing an integer into a compact format, using a minimal encoding depending on the actual value of
/// the integer. Ints <= 247 serialize as 1 byte, ints > 247 and <= 255 serialize as 2, ints > 255 and <= 65535
/// serialize as 3, and so on. Ints up to 64-bits are supported, with a maximum encoded byte length of 9 in that case.
///
/// Signed ints are treated as 2's complement unsigned for the purposes of serialization, which is fine since
/// the value<Int>() template guarantees no data loss so long as the same type is supplied to it as was used to
/// serialize the data originally. The serialized format is in little endian byte order if UseBE == false, and in big
/// endian order otherwise.
template <bool UseBE>
class GenericVarInt
{
    /// The max payload length we support. Do not change this! Changing this value changes the binary format!
    static constexpr std::size_t maxBytes = 8u;
public:
    static constexpr auto maxSize = maxBytes + 1; // 1 extra byte for control byte
private:
    static_assert (maxBytes == sizeof(std::uint64_t)); ///< If this ever doesn't hold, must be a very weird platform.
    static_assert (-1 == ~0, "2's complement architecture required"); ///< We assume 2's complement for signed
    /// All values <= 0xf7 (247) are taken verbatim (no control byte). First control value for payloadlen=1 is 0xf8
    static constexpr std::uint8_t b1max = 0xffu - maxBytes;

    // default constructed value encapsulates the value 0
    std::uint8_t sz = 1; ///< actual used bytes of arr below
    std::array<std::byte, maxSize> arr = {std::byte{0}, };


    /// Returns the payload length if b validates, otherwise throws Exc.
    /// The returned value is always >= 0 and <= maxBytes.
    template <typename Exc>
    static constexpr std::size_t validate(const ByteView & b, bool allowExtraBytesAtEnd = false) {
        const int bsize = int(b.size());
        if (bsize <= 0)
            throw Exc("VarInt: Empty byte array");
        const std::uint8_t cbyte = static_cast<std::uint8_t>(*b.data());
        const int payloadLen = std::max(int(cbyte) - int(b1max), 0);
        const bool lengthCheckOk = !allowExtraBytesAtEnd ? payloadLen+1 == bsize : payloadLen+1 <= bsize;
        if (!lengthCheckOk || payloadLen > int(maxBytes))
            throw Exc("VarInt: Byte array has the wrong format");
        return std::size_t(payloadLen);
    }

    struct Unchecked {};
    /// Unchecked constructor, used by fromBytes()
    explicit GenericVarInt(Unchecked, const ByteView &b) noexcept {
        sz = std::min(arr.size(), b.size());
        std::memcpy(arr.data(), b.data(), sz);
    }

public:
    template <std::integral Int> requires (!std::is_same_v<std::remove_cv_t<Int>, bool>)
    constexpr GenericVarInt(const Int val) {
        using UInt = std::make_unsigned_t<Int>;
        static_assert (sizeof(UInt) <= maxBytes);
        static_assert (maxBytes <= 255u && maxBytes > 0u);
        const UInt uval = static_cast<UInt>(val);
        uint_fast8_t nbytes = !val ? 1u : (unsigned(std::bit_width(uval)) + 7u) / 8u;
        std::byte *payload = arr.data();
        if (nbytes > 1 || uval > b1max) {
            sz = nbytes + 1; // this can never exceed 9
            *payload++ = std::byte(b1max + nbytes);
        } else if (nbytes == 1 && uval <= b1max) {
            // 1 byte of data, no control byte because value is <= 247
            sz = 1;
        } else
            // this should never happen
            throw std::logic_error("VarInt internal error: Unexpected state! FIXME!");
        for (uint_fast8_t i = 0u; i < nbytes; ++i) {
            if constexpr ( ! UseBE)
                // little endian
                payload[i] = static_cast<std::byte>(uval >> UInt(i*8u) & UInt(0xffu));
            else
                // big endian
                payload[i] = static_cast<std::byte>(uval >> UInt((nbytes - i - 1u)*8u) & UInt(0xffu));
        }
    }

    /// Construct an instance from raw bytes such as QByteArray bytes. May throw std::invalid_argument if b is of the
    /// wrong format, or is empty.
    ///
    /// Note that b must note have extra data at the end. If deserializing a byte stream that may have more bytes at
    /// the end, use deserialize().
    static GenericVarInt fromBytes(const ByteView &b) {
        validate<std::invalid_argument>(b);
        // accepted, below c'tor takes a shallow copy
        return GenericVarInt{Unchecked{}, b};
    }

    /// Deserialize a byte sequence. May throw std::invalid_argument if b is of the wrong format or is empty.
    /// Note: Unlike fromBytes(), the specified byte sequence may contain extra data at the end.
    /// On success, Span b is updated to point after the consumed byte(s).
    template<typename Byte> requires (sizeof(Byte) == 1 && !std::is_same_v<std::remove_cv_t<Byte>, bool>)
    static GenericVarInt deserialize(Span<Byte> &b) {
        const std::size_t byteLen = validate<std::invalid_argument>(b, true) + 1;
        // accepted construct (takes a deep copy of bytes in span)
        const std::byte *spanAcceptedBytes = reinterpret_cast<const std::byte *>(const_cast<const Byte *>(b.data()));
        GenericVarInt ret(Unchecked{}, ByteView{spanAcceptedBytes, byteLen});
        b = b.subspan(byteLen); // update b (consume bytes)
        return ret;
    }

    constexpr GenericVarInt() noexcept = default; // default c'tor: represents the value 0
    constexpr GenericVarInt(const GenericVarInt &) noexcept = default;
    constexpr GenericVarInt(GenericVarInt &&) noexcept = default;
    constexpr GenericVarInt &operator=(const GenericVarInt &) noexcept = default;
    constexpr GenericVarInt &operator=(GenericVarInt &&) noexcept = default;

    // lexicographical comparison based on raw bytes
    constexpr auto operator<=>(const GenericVarInt &o) const noexcept { return byteView() <=> o.byteView(); }
    constexpr bool operator==(const GenericVarInt &o) const noexcept { return byteView() == o.byteView(); }

    constexpr const std::byte *data() const noexcept { return arr.data(); }
    constexpr std::size_t size() const noexcept { return sz; }

    // view of raw serialized bytes
    constexpr ByteView byteView() const noexcept { return ByteView{data(), size()}; }

    QByteArray byteArray(bool deepCopy = true) const { return byteView().toByteArray(deepCopy); }
    QString hex() const { return QString::fromUtf8(byteArray(false).toHex()); }


    /// Deserialize the VarInt, converting its data into the template return type.
    /// Note that this may throw std::overflow_error if the specified type would overflow
    /// and cannot hold the data in question.
    /// (NB: may throw std::logic_error if there are bugs in this code).
    template <std::integral Int> requires (!std::is_same_v<std::remove_cv_t<Int>, bool>)
    constexpr Int value() const {
        const std::size_t payloadLen = validate<std::logic_error>(byteView());
        if (payloadLen == 0) {
            // The control byte is the value itself; there is no payload, so take the byte before the payload
            // for the value and return it.
            return static_cast<Int>(arr[0]);
        } else if (payloadLen > sizeof(Int)) {
            // Impossible encoding, would overflow
            throw std::overflow_error("Overflow in converting VarInt to destination value");
        }
        const std::byte * const payload = arr.data() + 1;
        Int ret{};
        // proceed normally, converting only the bytes that fit
        for (std::size_t i = 0, nb = std::min(payloadLen, sizeof(Int)); i < nb; ++i) {
            using UInt = std::make_unsigned_t<Int>;
            if constexpr ( ! UseBE)
                // little endian
                ret |= Int(UInt(payload[i]) << UInt(i)*UInt(8u));
            else
                // big endian
                ret |= Int(UInt(payload[i]) << UInt(nb - i - 1)*UInt(8u));
        }
        return ret;
    }
};

using VarInt = GenericVarInt<false>;
using VarIntBE = GenericVarInt<true>;
