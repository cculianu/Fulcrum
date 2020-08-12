//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
        /// The the 'N' (output index) for the tx itself as per bitcoin tx format
        std::uint16_t n;
    } compact = { 0xffff'ffff'ffff, 0xffff };
    constexpr CompactTXO() noexcept = default;
    CompactTXO(TxNum txNum, IONum n) noexcept : compact{txNum, n} {}
    CompactTXO(const CompactTXO & o) noexcept : compact{o.compact} {}
    CompactTXO & operator=(const CompactTXO & o) noexcept { std::memcpy(&compact, &o.compact, sizeof(compact)); return *this; }
    /// for most container types
    bool operator==(const CompactTXO &o) const noexcept { return compact.txNum == o.compact.txNum && compact.n == o.compact.n; }
    bool operator!=(const CompactTXO &o) const noexcept { return !(*this == o); }
    /// for ordered sets
    bool operator<(const CompactTXO &o) const noexcept  { return compact.txNum == o.compact.txNum ? compact.n < o.compact.n : compact.txNum < o.compact.txNum;  }
    // convenience
    TxNum txNum() const noexcept { return TxNum(compact.txNum); }
    // convenience
    IONum N() const noexcept { return IONum(compact.n); }
    bool isValid() const { return *this != CompactTXO{}; }
    static constexpr size_t serSize() noexcept { return 8; }
    QString toString() const { return isValid() ? QStringLiteral("%1:%2").arg(txNum()).arg(N()) : QStringLiteral("<compact_txo_invalid>"); }
    /// Low-level serialization to a byte buffer in place.  Note that bufsz must be >= serSize().
    /// Number of bytes written is returned, or 0 if bufsz to small.
   size_t toBytesInPlace(std::byte *buf, size_t bufsz) const {
        if (bufsz >= serSize()) {
            txNumToCompactBytes(buf, compact.txNum);
            buf[6] = std::byte((compact.n >> 0u) & 0xffu);
            buf[7] = std::byte((compact.n >> 8u) & 0xffu);
            return serSize();
        }
        return 0;
    }
    QByteArray toBytes() const {
        // the below is excessively wordy but it forces 8 byte little-endian style serialization
        QByteArray ret(serSize(), Qt::Uninitialized);
        toBytesInPlace(reinterpret_cast<std::byte *>(ret.data()), size_t(ret.size())); // this should never fail
        return ret;
    }
    static CompactTXO fromBytes(const std::byte *buf, size_t bufsz) {
        return fromBytes(QByteArray::fromRawData(reinterpret_cast<const char *>(buf), int(std::min(bufsz, serSize()))));
    }
    /// passed-in QByteArray must be exactly serSize() bytes else nothing is converted
    static CompactTXO fromBytes(const QByteArray &b) {
        // the below is excessively wordy but it forces 8 byte little-endian style deserialization
        CompactTXO ret;
        if (b.size() == serSize()) {
            const std::byte * cur = reinterpret_cast<const std::byte *>(b.data());
            ret.compact.txNum = txNumFromCompactBytes(cur);
            ret.compact.n = IONum(cur[6]) | IONum(IONum(cur[7]) << 8u);
        }
        return ret;
    }

    static constexpr size_t compactTxNumSize() { return 6; }

    /// Converts: TxNum (8 bytes) <- from a 6-byte buffer. Uses little-endian ordering.
    static inline TxNum txNumFromCompactBytes(const std::byte bytes[6])
    {
        return    (TxNum(bytes[0]) <<  0u)
                | (TxNum(bytes[1]) <<  8u)
                | (TxNum(bytes[2]) << 16u)
                | (TxNum(bytes[3]) << 24u)
                | (TxNum(bytes[4]) << 32u)
                | (TxNum(bytes[5]) << 40u);
    }
    /// Converts: TxNum (8 bytes) -> into a 6-byte buffer. Uses little-endian ordering.
    static inline void txNumToCompactBytes(std::byte bytes[6], TxNum num)
    {
        bytes[0] = std::byte((num >>  0u) & 0xffu);
        bytes[1] = std::byte((num >>  8u) & 0xffu);
        bytes[2] = std::byte((num >> 16u) & 0xffu);
        bytes[3] = std::byte((num >> 24u) & 0xffu);
        bytes[4] = std::byte((num >> 32u) & 0xffu);
        bytes[5] = std::byte((num >> 40u) & 0xffu);
    }
};
#if defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

namespace std {
/// specialization of std::hash to be able to add struct CompactTXO to any unordered_set or unordered_map
template<> struct hash<CompactTXO> {
    size_t operator()(const CompactTXO &ctxo) const noexcept {
        const auto val1 = ctxo.txNum();
        const auto val2 = ctxo.N();
        // We must copy the hash bytes and the ionum to a temporary buffer and hash that.
        // Previously, we put these two items in a struct but it didn't have a unique
        // objected repr and that led to bugs.  See Fulcrum issue #47 on GitHub.
        std::array<std::byte, sizeof(val1) + sizeof(val2)> buf;
        std::memcpy(buf.data()               , reinterpret_cast<const char *>(&val1), sizeof(val1));
        std::memcpy(buf.data() + sizeof(val1), reinterpret_cast<const char *>(&val2), sizeof(val2));
        // below hashes the above 10-byte buffer using CityHash64
        return Util::hashForStd(buf);
    }
};
} // namespace std
