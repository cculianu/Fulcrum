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
#include "RollingBloomFilter.h"
#include "Util.h"

#include "bitcoin/hash.h"

#include <QRandomGenerator>

#include <algorithm>
#include <cmath>
#include <limits>

RollingBloomFilter::RollingBloomFilter(const uint32_t nElements, const double fpRate) {
    constexpr auto EPSILON = std::numeric_limits<double>::epsilon();
    const Defer deferredIsValidChecker([&] {
        if (!isValid())
            Warning() << "Warning: RollingBloomFilter was passed invalid arguments: "
                      << "(" << nElements << ", " << fpRate << ")";
    });
    if (std::fabs(fpRate) <= EPSILON || nElements == 0) {
        // refuse to proceed on fpRate == 0 or fpRate is subnormal or nElements == 0,
        // filter will be .isValid() == false and will forever be a no-op
        return;
    }
    const double logFpRate = std::log(fpRate);
    /* The optimal number of hash functions is log(fpRate) / log(0.5), but
     * restrict it to the range 1-50. */
    nHashFuncs = std::max(1, std::min<int>(std::round(logFpRate / std::log(0.5)), 50));
    /* In this rolling bloom filter, we'll store between 2 and 3 generations of
     * nElements / 2 entries. */
    nEntriesPerGeneration = (nElements + 1) / 2;
    const uint32_t nMaxElements = nEntriesPerGeneration * 3;
    /* The maximum fpRate = pow(1.0 - exp(-nHashFuncs * nMaxElements /
     * nFilterBits), nHashFuncs)
     * =>          pow(fpRate, 1.0 / nHashFuncs) = 1.0 - exp(-nHashFuncs *
     * nMaxElements / nFilterBits)
     * =>          1.0 - pow(fpRate, 1.0 / nHashFuncs) = exp(-nHashFuncs *
     * nMaxElements / nFilterBits)
     * =>          log(1.0 - pow(fpRate, 1.0 / nHashFuncs)) = -nHashFuncs *
     * nMaxElements / nFilterBits
     * =>          nFilterBits = -nHashFuncs * nMaxElements / log(1.0 -
     * pow(fpRate, 1.0 / nHashFuncs))
     * =>          nFilterBits = -nHashFuncs * nMaxElements / log(1.0 -
     * exp(logFpRate / nHashFuncs))
     */
    // defensive programming to prevent crash on pathological values
    if (const double factor = 1.0 - std::exp(logFpRate / nHashFuncs);
            std::fabs(factor) <= EPSILON)
    {
        // invalid parameter passed
        return;
    }
    else if (const double logFactor = std::log(factor);
                 std::fabs(logFactor) <= EPSILON)
    {
        // also invalid parameter
        return;
    }
    else
    {
        // valid parameters
        static_assert (sizeof(decltype(data)::value_type)*8 == 64,
                       "This code assumes a 64-bit value type for the data vector");
        const auto nFilterBits = std::size_t(std::ceil(-1.0 * nHashFuncs * nMaxElements / logFactor));
        /* For each data element we need to store 2 bits. If both bits are 0, the
         * bit is treated as unset. If the bits are (01), (10), or (11), the bit is
         * treated as set in generation 1, 2, or 3 respectively. These bits are
         * stored in separate integers: position P corresponds to bit (P & 63) of
         * the integers data[(P >> 6) * 2] and data[(P >> 6) * 2 + 1]. */
        data.resize(((nFilterBits + 63UL) / 64UL) << 1UL);
        reset();
    }
}

/* Similar to CBloomFilter::Hash */
static inline uint32_t
RollingBloomHash(uint32_t nHashNum, uint32_t nTweak, const ByteView &data) {
    return bitcoin::MurmurHash3(nHashNum * 0xFBA4C795 + nTweak,
                                data.ucharData(), data.size());
}

// A replacement for x % n. This assumes that x and n are 32bit integers, and x
// is a uniformly random distributed 32bit value which should be the case for a
// good hash. See
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
static inline uint32_t FastMod(uint32_t x, size_t n) {
    return (uint64_t(x) * uint64_t(n)) >> 32;
}

void RollingBloomFilter::insert(const ByteView &bv) {
    if (!isValid())
        return;

    if (nEntriesThisGeneration >= nEntriesPerGeneration) {
        nEntriesThisGeneration = 0;
        if (++nGeneration == 4) {
            nGeneration = 1;
        }
        uint64_t nGenerationMask1 = 0 - uint64_t(nGeneration & 1);
        uint64_t nGenerationMask2 = 0 - uint64_t(nGeneration >> 1);
        /* Wipe old entries that used this generation number. */
        for (uint32_t p = 0; p < data.size(); p += 2) {
            uint64_t p1 = data[p], p2 = data[p + 1];
            uint64_t mask = (p1 ^ nGenerationMask1) | (p2 ^ nGenerationMask2);
            data[p] = p1 & mask;
            data[p + 1] = p2 & mask;
        }
    }
    nEntriesThisGeneration++;

    for (int n = 0; n < nHashFuncs; n++) {
        uint32_t h = RollingBloomHash(n, nTweak, bv);
        int bit = h & 0x3F;
        /* FastMod works with the upper bits of h, so it is safe to ignore that
         * the lower bits of h are already used for bit. */
        uint32_t pos = FastMod(h, data.size());
        /* The lowest bit of pos is ignored, and set to zero for the first bit,
         * and to one for the second. */
        data[pos & ~1] = (data[pos & ~1] & ~(uint64_t(1) << bit)) |
                         uint64_t(nGeneration & 1) << bit;
        data[pos | 1] = (data[pos | 1] & ~(uint64_t(1) << bit)) |
                        uint64_t(nGeneration >> 1) << bit;
    }
}

bool RollingBloomFilter::contains(const ByteView &bv) const {
    if (!isValid())
        return false;

    for (int n = 0; n < nHashFuncs; n++) {
        uint32_t h = RollingBloomHash(n, nTweak, bv);
        int bit = h & 0x3F;
        uint32_t pos = FastMod(h, data.size());
        /* If the relevant bit is not set in either data[pos & ~1] or data[pos |
         * 1], the filter does not contain vKey */
        if (!(((data[pos & ~1] | data[pos | 1]) >> bit) & 1)) {
            ++nMisses;
            return false;
        }
    }
    ++nHits;
    return true;
}

void RollingBloomFilter::reset() {
    if (!isValid())
        return;

    //nTweak = GetRand(std::numeric_limits<unsigned int>::max()); // <-- original code
    nTweak = static_cast<uint32_t>(QRandomGenerator::global()->generate());
    nEntriesThisGeneration = 0;
    nGeneration = 1;
    std::fill(data.begin(), data.end(), 0);
}

unsigned RollingBloomFilter::count() const {
    if (!isValid())
        return 0;
    return unsigned(nEntriesThisGeneration) + unsigned(nEntriesPerGeneration*std::max<int>(nGeneration-1, 0));
}

std::size_t RollingBloomFilter::memoryUsage() const {
    return data.size()*sizeof(decltype(data)::value_type) + sizeof(*this);
}
