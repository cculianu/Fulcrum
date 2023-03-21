//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <cstdint>
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
    /// No default c'tor
    RollingBloomFilter() = delete;

    /// The rolling bloom filter calls QRandomGenerator::global->generate() at
    /// construction.
    ///
    /// If we are seeding the global generator somehow, then don't create
    /// global RollingBloomFilter objects before the global seed is set.
    RollingBloomFilter(const uint32_t nElements, const double nFPRate);

    /// Implementation expects a ByteView (std::byte * pointer + size) to operate on;
    /// data gets hashed using MurmurHash3 to a uint32_t key for insertion
    /// into the bloom set.
    void insert(const ByteView &bv);

    /// Expects a ByteView to operator on. Checks set membership.
    bool contains(const ByteView &bv) const;

    /// Returns an imprecise estimate of the number of entries that have been
    /// inserted (this count eventually resets to 0 when the filter rolls).
    /// Note that this count is not necessarily the number of elements for
    /// which this set will return a true contains() result.
    unsigned count() const;
    /// Returns a rough estimate of the number of elements one can insert
    /// before the filter will roll over.
    unsigned capacity() const { return unsigned(nEntriesPerGeneration * 2); }

    /// Returns the number of times contains() returned true. This value is not reset across resets.
    unsigned hits() const { return nHits; }
    /// Returns the number of times contains() returned false. This value is not reset across resets.
    unsigned misses() const { return nMisses; }

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

    // stats, added by Calin
    mutable uint32_t nHits{}, nMisses{};
};
