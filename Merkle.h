#pragma once

#include "BlockProcTypes.h"
#include "BTC.h"

#include <QByteArray>

#include <cmath>
#include <optional>
#include <utility>
#include <vector>


#include <QByteArray>

/// Utility functions for merkle tree computations
namespace Merkle
{
    // some typedefs
    using Hash = QByteArray; // 32-byte sha256 double hash
    using HashVec = std::vector<Hash>;
    using BranchAndRootPair = std::pair<HashVec, Hash>;

    constexpr unsigned MaxDepth = 24; ///< the maximum depth of the merkle tree, which would be a tree of 16.7 million items.

    /// return the length of a merkle branch given a hash count (which must be >= 1!)
    constexpr unsigned branchLength(unsigned count) {
        return count < 1 ? 0 : unsigned(std::ceil(std::log2(count)));
    }

    /// return the depth of a merkle tree given a hash count (which must be >= 1!)
    /// The returned depth is always >= 1
    constexpr unsigned treeDepth(unsigned count) {
        return branchLength(count) + 1;
    }

    /// Return a (merkle branch, merkle root) pair given a list of hashes, and the index of one of those hashes.
    /// Specify an optional length which must be >= the tree's natural branch length, or nothing which defaults the
    /// branch length to the natural length.  Returns a default-constructed pair with nothing in it on error
    /// (out-of-range index or length, bad hashes, etc).
    BranchAndRootPair branchAndRoot(const HashVec &hashes, unsigned index, const std::optional<unsigned> & length = {});

    /// Convenient alias -- return just the merkle root of a non-empty vector of hashes.
    inline Hash root(const HashVec & hashes, const std::optional<unsigned> & length = {}) {
        return branchAndRoot(hashes, 0, length).second;
    }

    /// Returns a level of the merkle tree of hashes the given depth higher than the bottom row of the original tree.
    HashVec level(const HashVec &hashes, unsigned depthHigher);

    /**
     * Return a (merkle branch, merkle root) pair when a merkle-tree has a level cached.
     *
     * To maximally reduce the amount of data hashed in computing a merkle branch, cache a tree of depth N at level
     * N / 2.
     *
     * level is a list of hashes in the middle of the tree (returned by level())
     *
     * leafHashes are the leaves needed to calculate a partial branch up to level.
     *
     * depthHigher is how much higher level is than the leaves of the tree
     *
     * index is the index in the full list of hashes of the hash whose merkle branch we want.
    */
    BranchAndRootPair branchAndRootFromLevel(const HashVec & level, const HashVec & leafHashes, unsigned index, unsigned depthHigher);

    // -- For Testing --

    /// Used for testing. Return the merkle root given a hash, a merkle branch to it, and its index in the hashes array.
    Hash rootFromProof(const Hash & hash, const HashVec &branch, unsigned index);
    /// Used for testing.
    void test();
};

