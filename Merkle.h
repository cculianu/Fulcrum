#pragma once

#include "BlockProcTypes.h"
#include "BTC.h"

#include <QByteArray>

#include <cmath>
#include <optional>
#include <shared_mutex>
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

    constexpr unsigned MaxDepth = 28; ///< the maximum depth of the merkle tree, which would be a tree of ~134 million items.

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

    /// EX work-alike merkle cache. We do it this way because pretty much the protocol demands this approach.
    /// The public methods of this class are all thread-safe (except for the constructor).
    class Cache {
    public:
        using GetHashesFunc = std::function<HashVec(unsigned, unsigned, QString *)>;

        /// may throw BadArgs if !func
        Cache(const GetHashesFunc & func);

        bool isInitialized() const { return initialized; }

        /// initialize the cache to length hashes
        void initialize(unsigned length); ///< takes exclusive lock, may throw
        /// initialize the cache using a set of hashes
        void initialize(const HashVec &hashes); ///< takes exclusive lock, may throw

        BranchAndRootPair branchAndRoot(unsigned length, unsigned index); ///< takes exclusive lock, may throw

        /// truncate the cache to at most length hashes
        void truncate(unsigned length); ///< takes exclusive lock, may throw

        size_t size() const { SharedLockGuard g(lock); return level.size(); }

    private:
        using RWLock = std::shared_mutex;
        using SharedLockGuard = std::shared_lock<RWLock>;
        using ExclusiveLockGuard = std::lock_guard<RWLock>;

        mutable RWLock lock;
        const GetHashesFunc getHashesFunc;
        unsigned length = 0, depthHigher = 0;
        HashVec level;
        std::atomic_bool initialized{false};

        // takes no locks, may throw
        void initialize_nolock(const HashVec &);

        // takes no locks, may throw
        HashVec getHashes(unsigned from, unsigned count) const;

        HashVec getLevel(const HashVec &) const; ///< takes no locks
        inline unsigned segmentLength() const { return 1 << depthHigher; }
        inline unsigned leafStart(unsigned index) const { return (index >> depthHigher) << depthHigher; }
        void extendTo(unsigned length); ///< takes no locks
        HashVec levelFor(unsigned length) const; ///< takes no locks, may throw

    };

    // -- For Testing --

    /// Used for testing. Return the merkle root given a hash, a merkle branch to it, and its index in the hashes array.
    Hash rootFromProof(const Hash & hash, const HashVec &branch, unsigned index);
    /// Used for testing.
    void test();
};

