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

#include <QByteArray>
#include <QString>

#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash

// -------------------------------------------------------------------------------------------------------------------
// ----- Some storage helper classes below.. (safe to ignore in rest of codebase outside of Storage.h / Storage.cpp)
// -------------------------------------------------------------------------------------------------------------------
[[maybe_unused]] inline constexpr int xxx_to_suppress_warning_1{}; /* needed otherwise below may warn (clang bug) */
#ifdef __GNUC__
#pragma pack(push, 1)
#endif
/// Stogage subsystem "compact txo"
/// This is used internally by the "Storage" subsystem for storing TxNum <-> txhash associations on disk
struct CompactTXO {
    static constexpr std::uint64_t initval = ~0ULL; ///< indicates !isValid()
    // pack paranoia -- not strictly needed since this packs anyway the way we want on gcc and/or clang.
    union {
        struct {
            /// tx index in the global tx table. First tx in blockchain is txNum 0, and so on (mapping of unique number to a txid hash, stored in db).
            /// Note this is really a 48 bit value covering the range [0, 17592186044415]
            std::uint64_t txNum : 48;
            /// The the 'N' (output index) for the tx itself as per bitcoin tx format
            std::uint16_t n;
        } compact;
        std::uint64_t asU64 = initval;
    } u;
    CompactTXO() = default;
    CompactTXO(TxNum txNum, IONum n) { u.compact.txNum = txNum; u.compact.n = n; }
    CompactTXO(const CompactTXO & o) { *this = o; }
    CompactTXO & operator=(const CompactTXO & o) noexcept { std::memcpy(&u.compact, &o.u.compact, sizeof(u.compact)); return *this; }
    /// for most container types
    bool operator==(const CompactTXO &o) const noexcept { return u.compact.txNum == o.u.compact.txNum && u.compact.n == o.u.compact.n; }
    /// for ordered sets
    bool operator<(const CompactTXO &o) const noexcept  { return u.compact.txNum == o.u.compact.txNum ? u.compact.n < o.u.compact.n : u.compact.txNum < o.u.compact.txNum;  }
    // convenience
    TxNum txNum() const noexcept { return TxNum(u.compact.txNum); }
    // convenience
    IONum N() const noexcept { return IONum(u.compact.n); }
    bool isValid() const { return u.asU64 != initval; }
    static constexpr size_t serSize() noexcept { return 8; }
    QString toString() const { return isValid() ? QStringLiteral("%1:%2").arg(txNum()).arg(N()) : QStringLiteral("<compact_txo_invalid>"); }
    /// Low-level serialization to a byte buffer in place.  Note that bufsz must be >= serSize().
    /// Number of bytes written is returned, or 0 if bufsz to small.
   size_t toBytesInPlace(void *buf, size_t bufsz) const {
        if (bufsz >= serSize()) {
            uint8_t * cur = reinterpret_cast<uint8_t *>(buf);
            txNumToCompactBytes(cur, u.compact.txNum);
            cur[6] = (u.compact.n >> 0) & 0xff;
            cur[7] = (u.compact.n >> 8) & 0xff;
            return serSize();
        }
        return 0;
    }
    QByteArray toBytes() const {
        // the below is excessively wordy but it forces 8 byte little-endian style serialization
        QByteArray ret(serSize(), Qt::Uninitialized);
        toBytesInPlace(ret.data(), size_t(ret.size())); // this should never fail
        return ret;
    }
    static CompactTXO fromBytes(const void *buf, size_t bufsz) {
        return fromBytes(QByteArray::fromRawData(reinterpret_cast<const char *>(buf),int(std::min(bufsz, serSize()))));
    }
    /// passed-in QByteArray must be exactly serSize() bytes else nothing is converted
    static CompactTXO fromBytes(const QByteArray &b) {
        // the below is excessively wordy but it forces 8 byte little-endian style deserialization
        CompactTXO ret;
        if (b.size() == serSize()) {
            const uint8_t * cur = reinterpret_cast<const uint8_t *>(b.data());
            ret.u.compact.txNum = txNumFromCompactBytes(cur);
            ret.u.compact.n = IONum(cur[6]) | IONum(IONum(cur[7]) << 8);
        }
        return ret;
    }

    /// Converts: TxNum (8 bytes) <- from a 6-byte buffer. Uses little-endian ordering.
    static inline TxNum txNumFromCompactBytes(const uint8_t bytes[6])
    {
        return (TxNum(bytes[0])<<0)
                | (TxNum(bytes[1])<<8)
                | (TxNum(bytes[2])<<16)
                | (TxNum(bytes[3])<<24)
                | (TxNum(bytes[4])<<32)
                | (TxNum(bytes[5])<<40);
    }
    /// Converts: TxNum (8 bytes) -> into a 6-byte buffer. Uses little-endian ordering.
    static inline void txNumToCompactBytes(uint8_t bytes[6], TxNum num)
    {
        bytes[0] = (num >> 0) & 0xff;
        bytes[1] = (num >> 8) & 0xff;
        bytes[2] = (num >> 16) & 0xff;
        bytes[3] = (num >> 24) & 0xff;
        bytes[4] = (num >> 32) & 0xff;
        bytes[5] = (num >> 40) & 0xff;
    }

    static constexpr size_t compactTxNumSize() { return 6; }
};
#ifdef __GNUC__
#pragma pack(pop)
#endif

namespace std {
/// specialization of std::hash to be able to add struct CompactTXO to any unordered_set or unordered_map
template<> struct hash<CompactTXO> {
    size_t operator()(const CompactTXO &txo) const noexcept {
        static_assert (sizeof(txo.u.asU64) == sizeof(txo.u.compact),
                       "Unknown platform or struct packing. Expected CompactTXO.u.prevout size to be 64 bytes.");
        // just return the hash of the packed asU64.
        return hasher64(txo.u.asU64);
    }
private:
    hash<uint64_t> hasher64;
};
} // namespace std
