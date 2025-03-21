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

#include "BlockProcTypes.h"
#include "Util.h"

#include <QByteArray>
#include <QString>

#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash
#include <tuple> // for std::tuple

// -------------------------------------------------------------------------------------------------------------------
// ----- Some storage helper classes below.. (safe to ignore in rest of codebase outside of Storage.h / Storage.cpp)
// -------------------------------------------------------------------------------------------------------------------
[[maybe_unused]] inline constexpr int xxx_to_suppress_warning_1{}; /* needed otherwise below may warn (clang bug) */
#if defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 1)
#endif
/// Stogage subsystem "compact txo"
/// This is used internally by the "Storage" subsystem for storing TxNum <-> txhash associations on disk
struct CompactTXO {
    struct {
        /// tx index in the global tx table. First tx in blockchain is txNum 0, and so on (mapping of unique number to a txid hash, stored in db).
        /// Note this is really a 48 bit value covering the range [0, 281474976710655]
        std::uint64_t txNum : 48;
        /// The the 'N' (output index) for the tx itself as per bitcoin tx format. We support up to 24-bit IONums on-disk (16.7 million).
        /// If the on-disk byte count is 8, we serialize/deserialize IONums as 16-bit. If it is 9, we serialize/deserialize as 24-bit.
        std::uint32_t n : 24;
    } compact = { 0xff'ff'ff'ff'ff'ff, 0xff'ff'ff };
    constexpr CompactTXO() noexcept = default;
    CompactTXO(TxNum txNum, IONum n) noexcept : compact{txNum, n} {}
    CompactTXO(const CompactTXO & o) noexcept : compact{o.compact} {}
    CompactTXO & operator=(const CompactTXO & o) noexcept { compact.txNum = o.compact.txNum; compact.n = o.compact.n; return *this; }
    /// for most container types
    bool operator==(const CompactTXO &o) const noexcept { return compact.txNum == o.compact.txNum && compact.n == o.compact.n; }
    /// for ordered sets
    auto operator<=>(const CompactTXO &o) const noexcept  {
        return std::tuple(compact.txNum, compact.n) <=> std::tuple(o.compact.txNum, o.compact.n);
    }
    // convenience
    TxNum txNum() const noexcept { return TxNum(compact.txNum); }
    // convenience
    IONum N() const noexcept { return IONum(compact.n); }
    bool isValid() const { return *this != CompactTXO{}; }
    QString toString() const { return isValid() ? QStringLiteral("%1:%2").arg(txNum()).arg(N()) : QStringLiteral("<compact_txo_invalid>"); }

    /// Serialzied size is 8 bytes unless IONum is beyond 16-bit range, in which case it is 9 bytes. (If wide==true then always 9 bytes).
    size_t serializedSize(bool wide) const noexcept { return wide || compact.n > IONum16Max ? maxSize() : minSize(); }
    static constexpr size_t minSize() noexcept { return 8u; }
    static constexpr size_t maxSize() noexcept { return 9u; }

    /// Low-level serialization to a byte buffer in place.
    ///
    /// Note that bufsz must be >= serializedSize(wide) (which is 8 or 9 bytes, depending if IONum > 65535).
    /// If wide == true, then the buffer must be 9 bytes (maxSize() bytes).
    /// Number of bytes written is returned (8 or 9), or 0 if bufsz to small.
   size_t toBytesInPlace(std::byte *buf, size_t bufsz, bool wide) const noexcept {
        if (const auto sersize = serializedSize(wide); bufsz >= sersize) {
            txNumToCompactBytes(buf, compact.txNum);
            buf[6] = std::byte(compact.n >> 0u & 0xffu);
            buf[7] = std::byte(compact.n >> 8u & 0xffu);
            if (sersize == maxSize())
                buf[8] = std::byte(compact.n >> 16u & 0xffu);
            return sersize;
        }
        return 0;
    }
    /// If wide == false, result is 8 or 9 bytes depending on how large N() is. If wide == true, then it's always 9 bytes.
    QByteArray toBytes(bool wide) const {
        // the below is excessively wordy but it forces 8 byte little-endian style serialization
        QByteArray ret(serializedSize(wide), Qt::Uninitialized);
        toBytesInPlace(reinterpret_cast<std::byte *>(ret.data()), size_t(ret.size()), wide); // this should never fail
        return ret;
    }
    /// passed-in bufsz must be either minSize() (for 2-byte IONum <= 65535) or maxSize() (for 3-byte IONum)!
    static CompactTXO fromBytesInPlaceExactSizeRequired(const std::byte *buf, size_t bufsz)  {
        if (UNLIKELY(bufsz != minSize() && bufsz != maxSize()))
            throw InternalError(QString("CompactTXO::fromBytesInPlaceExactSizeRequired was given an invalid size: %1").arg(bufsz));
        return fromBytes(QByteArray::fromRawData(reinterpret_cast<const char *>(buf), int(bufsz)));
    }
    /// passed-in QByteArray must be exactly 8 or 9 bytes else nothing is converted
    static CompactTXO fromBytes(const QByteArray &b) {
        // the below is excessively wordy but it forces 8 byte little-endian style deserialization
        CompactTXO ret;
        if (const auto sz = b.size(); sz == minSize() || sz == maxSize()) {
            static_assert (maxSize() - minSize() == 1, "Assumption here is that minSize and maxSize differ in size by 1");
            const std::byte * cur = reinterpret_cast<const std::byte *>(b.constData());
            ret.compact.txNum = txNumFromCompactBytes(cur);
            ret.compact.n = IONum(cur[6]) | IONum(IONum(cur[7]) << 8u);
            if (sz == maxSize())
                ret.compact.n |= IONum(IONum(cur[8]) << 16u);
        }
        return ret;
    }

    static constexpr size_t compactTxNumSize() noexcept { return 6; }

    /// Converts: TxNum (8 bytes) <- from a 6-byte buffer. Uses little-endian ordering.
    static inline TxNum txNumFromCompactBytes(const std::byte bytes[6]) noexcept
    {
        return    (TxNum(bytes[0]) <<  0u)
                | (TxNum(bytes[1]) <<  8u)
                | (TxNum(bytes[2]) << 16u)
                | (TxNum(bytes[3]) << 24u)
                | (TxNum(bytes[4]) << 32u)
                | (TxNum(bytes[5]) << 40u);
    }
    /// Converts: TxNum (8 bytes) -> into a 6-byte buffer. Uses little-endian ordering.
    static inline void txNumToCompactBytes(std::byte bytes[6], TxNum num) noexcept
    {
        bytes[0] = std::byte(num >>  0u & 0xffu);
        bytes[1] = std::byte(num >>  8u & 0xffu);
        bytes[2] = std::byte(num >> 16u & 0xffu);
        bytes[3] = std::byte(num >> 24u & 0xffu);
        bytes[4] = std::byte(num >> 32u & 0xffu);
        bytes[5] = std::byte(num >> 40u & 0xffu);
    }
};
#if defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

/// specialization of std::hash to be able to add struct CompactTXO to any unordered_set or unordered_map
template<> struct std::hash<CompactTXO> {
    std::size_t operator()(const CompactTXO &ctxo) const noexcept {
        const std::uint64_t val1 = ctxo.txNum();
        const std::uint32_t val2 = ctxo.N();
        // We must copy the txNum and the ionum to a temporary buffer and hash that.
        // Previously, we put these two items in a struct but it didn't have a unique
        // objected repr and that led to bugs.  See Fulcrum issue #47 on GitHub.
        std::array<std::byte, sizeof(val1) + sizeof(val2)> buf;
        std::memcpy(buf.data()               , reinterpret_cast<const char *>(&val1), sizeof(val1));
        std::memcpy(buf.data() + sizeof(val1), reinterpret_cast<const char *>(&val2), sizeof(val2));
        // below hashes the above 12-byte buffer using CityHash64 (or MurMur3 if on 32-bit)
        return Util::hashForStd(buf);
    }
};
