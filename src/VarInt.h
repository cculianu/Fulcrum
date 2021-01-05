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

#include "Span.h"

#include <QByteArray>
#include <QString>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>


/// A class for serializing an integer into a compact format, using a minimal encoding depending on the actual value of
/// the integer. Ints <= 247 serialize as 1 byte, ints > 247 and <= 255 serialize as 2, ints > 255 and <= 65535
/// serialize as 3, and so on. Ints up to 64-bits are supported, with a maximum encoded byte length of 9 in that case.
///
/// Signed ints are treated as 2's complement unsigned for the purposes of serialization, which is fine since
/// the value<Int>() template guarantees no data loss so long as the same type is supplied to it as was used to
/// serialize the data originally. The serialized format is in little endian byte order.
class VarInt
{
    QByteArray ba;

    /// The max payload length we support. Do not change this! Changing this value changes the binary format!
    static constexpr std::size_t maxBytes = 8u;
    static_assert (maxBytes == sizeof(std::uint64_t)); ///< If this ever doesn't hold, must be a very weird platform.
    static_assert (-1 == ~0, "2's complement architecture required"); ///< We assume 2's complement for signed
    /// All values <= 0xf7 (247) are taken verbatim (no control byte). First control value for payloadlen=1 is 0xf8
    static constexpr std::uint8_t b1max = 0xffu - maxBytes;

    /// Returns the payload length if b validates, otherwise throws Exc.
    /// The returned value is always >= 0 and <= maxBytes.
    template <typename Exc, typename BArray>
    static std::size_t validate(const BArray & b, bool allowExtraBytesAtEnd = false) {
        static_assert(sizeof(*b.data()) == 1);
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

    /// Unchecked constructor, used by fromBytes()
    explicit VarInt(const QByteArray &b) : ba(b) {}
    /// Unchecked constructor, used by fromBytes()
    explicit VarInt(QByteArray &&b) : ba(std::move(b)) {}

public:
    template <typename Int, std::enable_if_t<std::is_integral_v<Int> && !std::is_same_v<std::remove_cv_t<Int>, bool>, int> = 0>
    VarInt(Int val) {
        using UInt = std::make_unsigned_t<Int>;
        static_assert (sizeof(UInt) <= maxBytes);
        static_assert (maxBytes <= 255u && maxBytes > 0u);
        const UInt uval(val);
        uint_fast8_t nbytes;
        if (val == 0)
            nbytes = 1; // special case for val == 0, we must encode at least 1 byte of data
        else {
            // scan to determine the number of bytes we need, setting nbytes to that value
            for (nbytes = maxBytes; nbytes > 0u; --nbytes) {
                if (std::uint64_t(uval) & 0xffull << (nbytes-1ull)*8ull)
                    break;
            }
        }
        std::byte *payload;
        if (nbytes > 1 || uval > b1max) {
            // requires a payload, 1 byte(s) or more of data, we must prepend the control byte
            ba = QByteArray(nbytes + 1, Qt::Uninitialized);
            payload = reinterpret_cast<std::byte *>(ba.data());
            *payload++ = std::byte(b1max + nbytes);
        } else if (nbytes == 1 && uval <= b1max) {
            // 1 byte of data, no control byte because value is <= 247
            ba = QByteArray(1, Qt::Uninitialized);
            payload = reinterpret_cast<std::byte *>(ba.data());
        } else
            // this should never happen
            throw std::logic_error("VarInt internal error: Unexpected state! FIXME!");
        for (uint_fast8_t i = 0u; i < nbytes; ++i) {
            payload[i] = std::byte(std::uint64_t(uval) >> i*8ull & 0xffull);
        }
    }

    /// Construct an instance from raw bytes. May throw std::invalid_argument if b is of the wrong format, or is empty.
    ///
    /// Note that b must note have extra data at the end. If deserializing a byte stream that may have more bytes at
    /// the end, use deserialize().
    static VarInt fromBytes(const QByteArray &b) {
        validate<std::invalid_argument>(b);
        // accepted, below c'tor takes a shallow copy
        return VarInt(b);
    }
    /// Move-constructs an instance from raw bytes. May throw std::invalid_argument if b is of the wrong format, or is empty.
    ///
    /// Note that b must note have extra data at the end. If deserializing a byte stream that may have more bytes at
    /// the end, use deserialize().
    static VarInt fromBytes(QByteArray &&b) {
        validate<std::invalid_argument>(b);
        // accepted, move construct
        return VarInt(std::move(b));
    }

    /// Deserialize a byte sequence. May throw std::invalid_argument if b is of the wrong format or is empty.
    /// Note: Unlike fromBytes(), the specified byte sequence may contain extra data at the end.
    /// On success, Span b is updated to point after the consumed byte(s).
    template<typename Byte, std::enable_if_t<sizeof(Byte) == 1 && !std::is_same_v<std::remove_cv_t<Byte>, bool>, int> = 0>
    static VarInt deserialize(Span<Byte> &b) {
        const int byteLen = validate<std::invalid_argument>(b, true) + 1;
        // accepted construct (takes a deep copy of bytes in span)
        VarInt ret(QByteArray(reinterpret_cast<const char *>(const_cast<const Byte *>(b.data())), byteLen));
        b = b.subspan(std::size_t(byteLen)); // uodate b (consume bytes)
        return ret;
    }

    VarInt() : ba(1, char(0)) {} // default c'tor: represent the value 0
    VarInt(const VarInt &) = default;
    VarInt(VarInt &&) = default;
    VarInt &operator=(const VarInt &) = default;
    VarInt &operator=(VarInt &&) = default;

    // lexicographical comparison based on raw bytes
    bool operator==(const VarInt &o) const { return ba == o.ba; }
    bool operator!=(const VarInt &o) const { return ba != o.ba; }
    bool operator<(const VarInt &o) const { return ba < o.ba; }
    bool operator>=(const VarInt &o) const { return ba >= o.ba; }
    bool operator<=(const VarInt &o) const { return ba <= o.ba; }
    bool operator>(const VarInt &o) const { return ba > o.ba; }

    const QByteArray & bytes() const { return ba; }
    QString hex() const { return QString::fromUtf8(ba.toHex()); }

    /// Deserialize the VarInt, converting its data into the template return type.
    /// Note that this may throw std::overflow_error if the specified type would overflow
    /// and cannot hold the data in question.
    /// (NB: may throw std::logic_error if there are bugs in this code).
    template <typename Int>
    std::enable_if_t<std::is_integral_v<Int> && !std::is_same_v<std::remove_cv_t<Int>, bool>, Int>
    /* Int */ value() const {
        const std::size_t payloadLen = validate<std::logic_error>(ba);
        const std::byte * const payload = reinterpret_cast<const std::byte *>(ba.constData() + 1);
        if (payloadLen == 0) {
            // The control byte is the value itself; there is no payload, so take the byte before the payload
            // for the value and return it.
            return Int(payload[-1]);
        }
        Int ret{};
        // check if we must detect overflow before we proceed
        if (const auto intSize = std::ptrdiff_t(sizeof(Int)), overBytes = std::ptrdiff_t(payloadLen) - intSize; overBytes > 0) {
            // ensure that all bytes in the payload beyond the size of Int are 0
            for (std::ptrdiff_t i = 0; i < overBytes; ++i)
                if (payload[i + intSize] != std::byte{0})
                    // overflow detected
                    throw std::overflow_error("Overflow in converting VarInt to destination value");
        }
        // proceed normally, converting only the bytes that fit
        for (std::size_t i = 0, nb = std::min(payloadLen, sizeof(Int)); i < nb; ++i) {
            using UInt = std::make_unsigned_t<Int>;
            ret |= Int(UInt(payload[i]) << std::uint64_t(i)*std::uint64_t(8u));
        }
        return ret;
    }

};
