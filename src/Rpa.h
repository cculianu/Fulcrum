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

#include "ByteView.h"
#include "PackedNumView.h"

#include <QByteArray>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <tuple>
#include <vector>
#include <variant>

namespace bitcoin { class CTxIn; } // forward decl. used below

namespace Rpa {

// Spec limit: number of inputs we index is limited to 30 per txn to reduce DoS vector.
static constexpr size_t InputIndexLimit = 30u;

static constexpr size_t PrefixBits = 16u; // hard-coded in Fulcrum for now
static constexpr size_t PrefixBitsMin = 4u; // the smallest prefix is a nybble
static constexpr size_t PrefixBytes = PrefixBits / 8u;

// Check some current implementation limitations
static_assert(PrefixBitsMin > 0u && PrefixBitsMin <= PrefixBits);
static_assert(PrefixBits >= 8u && PrefixBits <= 16u, "PrefixBits may not be less than 8 or greater than 16");
static_assert(PrefixBytes * 8u == PrefixBits, "PrefixBits must be a multiple of 8");

/// An Rpa hash is a double sha256 hash of a serialized bitcoin::CTxIn
/// Note that it may also be a short hash (<2 bytes) if being used to construct a sub-16-bit prefix.
struct Hash : QByteArray {
    using QByteArray::QByteArray;

    Hash(const Hash &o) : QByteArray(o) {}
    explicit Hash(const QByteArray &o) : QByteArray(o) {}
    // Serialize a CTxIn and take its hash
    explicit Hash(const bitcoin::CTxIn &in);

    Hash & operator=(const QByteArray & o) noexcept { QByteArray::operator=(o); return *this; }
};

/// Encapsulates a "prefix" which is used for searching the PrefixTable. A prefix is a 4 to 16 bit value. If it's
/// 16-bits, it corresponds to a single index in the prefix table. Lower bits means we search the prefix table
/// within a range of indices.
class Prefix {
    uint8_t bits; // the number of active bits for this prefix. If == PrefixBits, then this->value() is a single index
    uint16_t n; // host byte order
    using Bytes = std::array<uint8_t, PrefixBytes>;
    Bytes bytes; // big endian
    static_assert(sizeof(n) == PrefixBytes);
public:
    explicit Prefix(uint16_t num, uint8_t bits_ = PrefixBits);
    explicit Prefix(const Hash & h);

    /// Specifies a prefix range: [begin, end)
    struct Range {
        uint32_t begin{}, end{};
        Range() = default;
        Range(uint32_t b, uint32_t e) : begin{b}, end{e} {}
        uint32_t size() const { return end - begin; }

        bool operator==(const Range &o) const { return std::tuple(begin, end) == std::tuple(o.begin, o.end); }
        bool operator!=(const Range &o) const { return ! this->operator==(o); }
    };

    // Returns the [begin, end) range for this prefix. If end - begin == 1 then this->value() is a concrete index
    // rather than a range of indices
    Range range() const;

    unsigned getBits() const { return bits; }

    // the integer value of this prefix (can be used as in index into PrefixTable below)
    uint16_t value() const { return n; }
    // the raw big-endian bytes for this prefix (not truncated according to bits)
    ByteView byteView() const { return bytes; }

    // return the big-endian ordered bytes for this prefix (may take a deep or shallow copy), truncated to 1 character if bits <= 8
    QByteArray toByteArray(bool deepCopy = true, bool truncate = false) const {
        auto bv = byteView();
        if (truncate && bits <= 8u) bv = bv.substr(0, std::max<unsigned>(bits, 8u) / 8u); // truncate to bits
        return bv.toByteArray(deepCopy);
    }

    // Returns the truncated hex (respecting bits, so it may return e.g.: 'a' for bits==4, 'ab' for bits=8, 'abc' for bits=12, etc)
    QByteArray toHex() const;

    // Parses the hex and returns an optional Prefix object. It the optional is empty, it means there was a parse error, or the hex is too long, etc.
    static std::optional<Prefix> fromHex(const QString &);

    bool operator==(const Prefix &o) const { return std::tuple(bits, n) == std::tuple(o.bits, o.n); }
    bool operator!=(const Prefix &o) const { return ! this->operator==(o); }


    /* -- Some generic prefix-related utility functions --*/

    /// Returns the number as a big-endian array, with high nybble at position 0 and low nybble at position 1.
    /// Assumption: num's "bits" are already normalized to 16.
    static constexpr auto numToBytes(uint16_t num) noexcept -> Bytes { return {pfxN<0>(num), pfxN<1>(num)}; }

    /// Usage: pfxN<0>(val) or pfxN<1>(val) to extract either the hi nybble (position 0) or lo nybble (position 1)
    /// from any arbitrary number. Assumption: num's "bits" are already normalized to 16.
    template <unsigned N> static constexpr uint8_t pfxN(uint16_t num) noexcept {
        constexpr auto MaxN = sizeof(num) - 1u; // == 1
        static_assert(N <= MaxN); // N must be 0 or 1
        return static_cast<uint8_t>((num >> (8u * (MaxN - N))) & 0xffu);
    }

};

static constexpr size_t PrefixTableSize = 1u << PrefixBits;
static constexpr unsigned SerializedTxIdxBits = 24u; // Allows for up to ~3GB blocks. Consensus limit is 2GB anyway so this is fine for the foreseeable future.
using TxIdx = std::conditional_t<SerializedTxIdxBits <= 32u, uint32_t, uint64_t>;
using PNV = PackedNumView<SerializedTxIdxBits>;
using VecTxIdx = std::vector<TxIdx>;
static constexpr uint64_t MaxTxIdx = (uint64_t{0x1u} << SerializedTxIdxBits) - uint64_t{1u}; //< Due to SerialixedTxIdxBits limits, we only support entries <= this value.

/// The size of this table is always 65536, and it encapsulates a mapping of a 16-bit "prefix" to a vector of
/// TxIdx. The table may be ReadWrite (as it is populated during block processing), or ReadOnly (lookup from DB).
/// ReadOnly tables are lazily read on-demand from a backing byte buffer (which is intended to come from the DB).
class PrefixTable {
    struct ReadWrite {
        std::vector<VecTxIdx> rows{PrefixTable::numRows(), VecTxIdx{}};
        ReadWrite() = default;
    };
    struct ReadOnly {
        QByteArray serializedData;
        mutable std::vector<PNV> rows{PrefixTable::numRows(), PNV{}};

        struct Toc {
            std::vector<uint64_t> prefix0Offsets;
            Toc() : prefix0Offsets(size_t(1 << 8), uint64_t{}) {}
        };

        Toc toc;

        ReadOnly() = default;
        ReadOnly(const ReadOnly &o) : serializedData(o.serializedData), toc(o.toc) /* intentionally don't copy rows */ {}
        ReadOnly(ReadOnly &&) = default;

        ReadOnly & operator=(const ReadOnly &o);
        ReadOnly & operator=(ReadOnly &&) = default;
    };

    std::variant<ReadWrite, ReadOnly> var;

public:
    PrefixTable() : var(std::in_place_type<ReadWrite>) {}

    // Construct from serialized data, turns this class into a read-only "view" into the data
    explicit PrefixTable(const QByteArray &serData);

    static constexpr size_t numRows() { return 0x1u << PrefixBits; }

    void clear() { var.emplace<ReadWrite>(); }

    bool isReadOnly() const { return std::holds_alternative<ReadOnly>(var); }
    bool isReadWrite() const { return std::holds_alternative<ReadWrite>(var); }

    size_t elementCount() const;
    bool empty() const { return elementCount() == 0u; }

    // Adds txIdx to all entries matching prefix. If prefix length is 16 bits, then just adds to 1 entry at index prefix.value().
    void addForPrefix(const Prefix & prefix, TxIdx TxIdx);
    // Returns a vector of all txNums matching a particular prefix, optionally sorted and uniqueified.
    // If prefix length is 16 bits, then just returns the entry at index prefix.value().
    VecTxIdx searchPrefix(const Prefix &prefix, bool sortAndMakeUnique = false) const;
    // Removes all entries matching a particular prefix. If prefix length is 16 bits, then just clears the vector at index prefix.value().
    // Returns the number of TxIdxs removed.
    size_t removeForPrefix(const Prefix & prefix);

    // Returns a pointer to a row if this instance is ReadWrite, and index <= numRows(), or nullptr otherwise.
    VecTxIdx * getRowPtr(size_t index);
    const VecTxIdx * getRowPtr(size_t index) const;

    QByteArray serializeRow(size_t index, bool deepCopy = true) const;

    QByteArray serialize() const;

    bool operator==(const PrefixTable &o) const;
    bool operator!=(const PrefixTable &o) const { return ! this->operator==(o); }

private:
    /// ReadOnly mode only: Lazy-loads row at index, if it has not already been loaded (otherwise is a no-op).
    /// ReadWrite mode: Is a no-op.
    void lazyLoadRow(size_t index) const;
};

static_assert(PrefixTableSize - 1u == std::numeric_limits<uint16_t>::max());

} // namespace Rpa
