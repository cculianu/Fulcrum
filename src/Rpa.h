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

#include "BlockProcTypes.h"
#include "ByteView.h"

#include "bitcoin/transaction.h"

#include <QByteArray>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace Rpa {

static constexpr size_t PrefixBits = 16u; // hard-coded in Fulcrum for now
static constexpr size_t PrefixBytes = PrefixBits / 8u;

// Check some current implementation limitations
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

class Prefix {
    uint8_t bits; // the number of active bits for this prefix. If == PrefixBits, then this->value() is a single index
    uint16_t n; // host byte order
    std::array<uint8_t, PrefixBytes> bytes; // big endian
    static_assert(sizeof(n) == PrefixBytes);
public:
    explicit Prefix(uint16_t num, uint8_t bits_ = PrefixBits);
    explicit Prefix(const Hash & h);

    /// Specifies a prefix range: [begin, end)
    struct Range {
        uint32_t begin{}, end{};
        Range() = default;
        Range(uint32_t b, uint32_t e) : begin{b}, end{e} {}
    };

    // Returns the [begin, end) range for this prefix. If end - begin == 1 then this->value() is a concrete index
    // rather than a range of indices
    Range range() const;

    unsigned getBits() const { return bits; }

    // the integer value of this prefix (can be used as in index into PrefixTable below)
    uint16_t value() const { return n; }
    // the raw big-endian bytes for this prefix (not truncated according to bits)
    ByteView byteView() const { return bytes; }

    // returns the big-endian ordered bytes for this prefix, optionally truncated to 1 character if bits == 8
    std::string toString(bool truncate = false) const {
        auto sv = byteView().toStringView();
        if (truncate && bits < PrefixBits) sv = sv.substr(0, bits / 8u); // truncate to bits
        return std::string{sv};
    }
    // return the big-endian ordered bytes for this prefix (may take a deep or shallow copy), truncated to 1 character if bits == 8
    QByteArray toByteArray(bool deepCopy = true, bool truncate = false) const {
        auto bv = byteView();
        if (truncate && bits < PrefixBits) bv = bv.substr(0, bits / 8u); // truncate to bits
        return bv.toByteArray(deepCopy);
    }

    bool operator<(const Prefix &o) const { return n < o.n; }
    bool operator==(const Prefix &o) const { return n == o.n; }
    bool operator<=(const Prefix &o) const { return this->operator==(o) || this->operator<(o); }
    bool operator>(const Prefix &o) const { return ! this->operator<=(o); }
    bool operator>=(const Prefix &o) const { return ! this->operator<(o); }
};

static constexpr size_t PrefixTableSize = 1u << PrefixBits;
using PrefixTableBase = std::array<std::vector<TxNum>, PrefixTableSize>;

struct PrefixTable : PrefixTableBase {
    using PrefixTableBase::PrefixTableBase;

    void clear() { fill({}); }

    size_t elementCount() const;
    bool empty() const { return elementCount() == 0u; }

    // Adds txNum to all entries matching prefix. If prefix length is 16 bits, then just adds to 1 entry at index prefix.value().
    void addForPrefix(const Prefix & prefix, TxNum txNum);
    // Returns a vector of all txNums matching a particular prefix, optionally sorted and uniqueified.
    // If prefix length is 16 bits, then just returns the entry at index prefix.value().
    std::vector<TxNum> searchPrefix(const Prefix &prefix, bool sortAndMakeUnique = false) const;
    // Removes all entries matching a particular prefix. If prefix length is 16 bits, then just clears the vector at index prefix.value().
    // Returns the number of TxNums removed.
    size_t removeForPrefix(const Prefix & prefix);

    static constexpr unsigned SerializedTxNumBits = 48u; // when serializing only the low-order 48 bits end up in the data (6 byte packed TxNums)

    template <typename Ret /* must be either: QByteArray or std::string */>
    Ret serializeRow(size_t index) const;
};

static_assert(PrefixTableSize - 1u == std::numeric_limits<uint16_t>::max());

} // namespace Rpa
