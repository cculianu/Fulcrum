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

#include "bitcoin/uint256.h"

#include <QByteArray>

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

/**
 * RollingBloomFilter is a probabilistic "keep track of most recently inserted"
 * set. Construct it with the number of items to keep track of, and a
 * false-positive rate. Unlike CBloomFilter, by default nTweak is set to a
 * cryptographically secure random value for you. Similarly rather than clear()
 * the method reset() is provided, which also changes nTweak to decrease the
 * impact of false-positives.
 *
 * contains(item) will always return true if item was one of the last N to 1.5*N
 * insert()'ed ... but may also return true for items that were not inserted.
 *
 * It needs around 1.8 bytes per element per factor 0.1 of false positive rate.
 * (More accurately: 3/(log(256)*log(2)) * log(1/fpRate) * nElements bytes)
 *
 * This class is adapted from Bitcoin Cash Node sources commit hash:
 *    c5b142c20500d8aa3a1dd9bfb1fa048cef0f5c2e
 */
class RollingBloomFilter {
public:
    /// Our canonical data type that we operate on, the std::byte opaque byte type.
    using byte = std::byte;

    /// No default c'tor
    RollingBloomFilter() = delete;

    /// The rolling bloom filter calls QRandomGenerator::global->generate() at
    /// construction.
    ///
    /// If we are seeding the global generator somehow, then don't create
    /// global RollingBloomFilter objects before the global seed is set.
    RollingBloomFilter(const uint32_t nElements, const double nFPRate);

    /// Implementation expects a std::byte * pointer to operate on,
    /// which gets hashed using MurmurHash3 to a uint32_t key for insertion
    /// into the bloom set.
    void insert(const byte *bytes, size_t len);

    // -- Convenient overloads for `insert` --

    /// Insert any vector of POD data e.g. vector<char>, vector<int64_t>, etc
    template <typename T>
    std::enable_if_t<std::is_pod_v<T>, void>
    /* void */ insert(const std::vector<T> &vKey) {
        insert(reinterpret_cast<const byte *>(vKey.data()), vKey.size() * sizeof(T));
    }
    /// insert any bitcoin base_blob e.g. hash256 & hash160
    template<unsigned int N>
    void insert(const bitcoin::base_blob<N> &hash) {
        insert(reinterpret_cast<const byte *>(hash.begin()), hash.size());
    }
    /// insert any QByteArray
    void insert(const QByteArray &ba) {
        insert(reinterpret_cast<const byte *>(ba.constData()), static_cast<std::size_t>(ba.size()));
    }

    /// Real implementation -- expects a std::byte array to operator on.
    bool contains(const byte *bytes, size_t len) const;

    // -- Convenient overloads for `contains` --

    /// for any vector of POD data e.g. vector<char>, vector<int64_t>, etc
    template <typename T>
    std::enable_if_t<std::is_pod_v<T>, bool>
    /* bool */ contains(const std::vector<T> &vKey) const {
        return contains(reinterpret_cast<const byte *>(vKey.data()), vKey.size() * sizeof(T));
    }
    /// for e.g. hash256 & hash160
    template<unsigned int N>
    bool contains(const bitcoin::base_blob<N> &hash) const {
        return contains(reinterpret_cast<const byte *>(hash.begin()), hash.size()); }
    /// for QByteArray
    bool contains(const QByteArray &ba) const {
        return contains(reinterpret_cast<const byte *>(ba.constData()), static_cast<std::size_t>(ba.size()));
    }

    /// Returns an imprecise estimate of the number of entries that have been
    /// inserted (this count eventually resets to 0 when the filter rolls).
    /// Note that this count is not necessarily the number of elements for
    /// which this set will return a true contains() result.
    unsigned count() const;
    /// Returns a rough estimate of the number of elements one can insert
    /// before the filter will roll over.
    unsigned capacity() const { return unsigned(nEntriesPerGeneration * 2); }

    void reset(); ///< clears the filter of all insertions (but keeps it valid)

    /// Invalid RollingBloomFilter occurs if pathological parameters are passed
    /// to c'tor, or if invalidate() was called.
    ///
    /// Invalid filters are always no-ops on insert(), and contains() always
    /// returns false.
    bool isValid() const { return !data.empty(); }

    /// Releases filter memory and makes the filter invalid.
    /// Subsequent operations will be no-ops
    void invalidate() { if (!data.empty()) data.clear(); }

    /// Returns the number of bytes taken by this filter.
    /// This value doesn't change throughout a valid filter's lifetime.
    std::size_t memoryUsage() const;

private:
    int nEntriesPerGeneration{1};
    int nEntriesThisGeneration{};
    int nGeneration{1};
    std::vector<uint64_t> data;
    uint32_t nTweak{};
    int nHashFuncs{1};
};
