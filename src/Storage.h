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

// ---
// See the large comment at the end of this file for an overview of the
// rocksdb database layout used by this program.
// ---


#include "BlockProc.h"
#include "Merkle.h"
#include "Mempool.h"
#include "Mgr.h"
#include "Mixins.h"
#include "Options.h"
#include "Span.h"
#include "TXO.h"

#include "bitcoin/amount.h"

#include <QByteArray>
#include <QFlags>
#include <QPointer>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <utility>
#include <vector>

// fwd decls used by Storage private(s)
namespace rocksdb {
class DB;
class ColumnFamilyHandle;
class WriteBatch;
}

namespace BTC { class HeaderVerifier; } // fwd decl used below. #include "BTC.h" to see this type
namespace Rpa { class Prefix; } // fwd decl, use "Rpa.h" to see this type

/// Generic database error
struct DatabaseError : public Exception { using Exception::Exception; ~DatabaseError() override; };
/// Key was not found in the database
struct DatabaseKeyNotFound : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseKeyNotFound() override; };
/// Key was found but deserialization of key failed when reading from the db, or serializing to a db slice failed.
struct DatabaseSerializationError : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseSerializationError() override; };
/// The database appears to be of the wrong format / unrecognized.
struct DatabaseFormatError : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseFormatError() override; };

/// Thrown by addBlock if the block in question cannot be added because its prevoutHash does not match the latestTip.
/// The caller should probably rewind the chain if this is thrown by calling Storage::undoLatestBlock().
struct HeaderVerificationFailure : public Exception { using Exception::Exception; ~HeaderVerificationFailure() override; };
/// Thrown by undoLatestBlock() if undo info is missing from the db for said block (this would indicate we tried to
/// rewind too far back or some other unforeseen circumstance).
struct UndoInfoMissing : public Exception { using Exception::Exception; ~UndoInfoMissing() override; };
/// Thrown by internally by getHistory and listUnspent if the history is too large (larger than max_history from config).
struct HistoryTooLarge : public Exception { using Exception::Exception; ~HistoryTooLarge() override; };

class ScriptHashSubsMgr;
class DSProofSubsMgr;
class TransactionSubsMgr;

/// Manages the db and all storage-related facilities.  Most of its public methods are fully reentrant and thread-safe.
class Storage final : public Mgr, public ThreadObjectMixin
{
public:
    Storage(const std::shared_ptr<const Options> & options);
    ~Storage() override;

    // Mgr interface
    void startup() override;
    void cleanup() override;
    // /Mgr

    /// returns a string of the form "6.14.6-ed43161" for the rocksdb version that this application is compiled against
    /// NB: The version number is from headers (compile-time) but the commit hash comes from the lib itself (runtime).
    static QString rocksdbVersion();

    // locking types
    using RWLock = std::shared_mutex;
    using Lock = std::mutex;
    using ExclusiveLockGuard = std::unique_lock<RWLock>;
    using SharedLockGuard = std::shared_lock<RWLock>;
    using LockGuard = std::unique_lock<Lock>;

    // Public interface -- unless otherwise specified all functions below are thread-safe

    // -- Header-related
    using Header = QByteArray;
    using HeaderHash = QByteArray;

    /// 100 million max headers for now.
    static constexpr size_t MAX_HEADERS = 100'000'000;

    /// Hard-coded to 100 blocks of undo in older Fulcrum.  Now it can be configured from a conf file setting: max_reorg
    inline unsigned configuredUndoDepth() const { return options->maxReorg; }
    /// True if the DB contains any undo entries for blocks
    bool hasUndo() const;


    /// Thread safe. May hit the database (or touch a cache).  Returns the header for the given height or nothing if
    /// height > latestTip().first.  May also fail on low-level db error. Use the optional arg *err to see why if failed.
    std::optional<Header> headerForHeight(BlockHeight height, QString *err = nullptr) const;
    /// Convenient batched alias for above. Returns a set of headers starting at height. May return < count if not
    /// all headers were found. Thread safe.  This is potentially much faster than calling headerForHeight in a loop
    /// since it uses the RocksDB MultiGet API. Does not throw.
    std::vector<Header> headersFromHeight(BlockHeight height, unsigned count, QString *err = nullptr) const;

    /// Implicitly takes a lock to return this. Thread safe. Breakdown of info returned:
    ///   .first - the latest valid height we have synched or -1 if no headers.
    ///   .second - the latest valid chainTip 32-byte sha256 double hash of the header (the chainTip as it's called in
    ///             bitcoind parlance), in bitcoind REVERSED memory order (that is, big endian order, ready for json
    ///             sending/receiving). (Empty if no headers yet).
    std::pair<int, HeaderHash> latestTip(Header *header = nullptr) const;

    /// Returns the current block height, or an empty optional if no genesisHash and no blocks;
    std::optional<BlockHeight> latestHeight() const;

    /// eg 'main' or 'test' (or even possibly 'regtest') or may be empty string if new db (thread safe)
    QString getChain() const;
    void setChain(const QString &); // implicitly calls db save of 'meta' (thread safe)

    /// Will be one of: "BCH", "BTC" or "" on a newly initialized DB. Note Controller class must use this to match
    /// the coin with the bitcoind it is connected to.  It sets the Coin via setCoin on first connection to a bitcoind.
    QString getCoin() const;
    /// Controller calls this the first time it connects to a bitcoind if the current coin is Coin::Unknown in order
    /// to save the Coin to the DB.
    void setCoin(const QString &); // implicitly calls db save of 'meta' (thread safe)

    /// Thread-safe. Returns a reversed hash (ready for hex encoding) of block 0's header.  Always succeeds if we have
    /// block 0, never throws. (If we have not seen block 0, returns an empty HeaderHash).
    HeaderHash genesisHash() const;

    enum class SaveItem : uint32_t {
        Meta = 0x1, ///< save Meta object to the meta table

        All = 0xffffffff, ///< save everything
        None = 0x00, ///< No-op
    };
    Q_DECLARE_FLAGS(SaveSpec, SaveItem)

    /// schedules updates to be written to disk immediately when control returns to this
    /// object's thread's event loop.
    void save(SaveSpec = SaveItem::All);

    // --- Block Processing

    /// Thread-safe. Call this from the Controller thread or any thread. Will return on success, or throw on failure.
    ///
    /// The most likely failure reason would be a HeaderVerificationFailure (due to a reorg).  If
    /// HeaderVerificationFailure is thrown, the db and Storage state is sane and the caller can/should proceed
    /// to try and rewind the blocks in the db via successive calls to undoLatestBlock().
    ///
    /// If any other exception is thrown, the db and Storage state is not guaranteed to be in a sane state and the
    /// user will probably have to resynch the entire chain. (TODO FIXME).
    ///
    /// This function will mutate the pased-in pre-processed block and fill in all the inputs from the utxo set,
    /// as well as modify the utxo set with spends / new outputs, and generate undo info for the block in the db if
    /// the block is accepted.  A successful return from this function without throwing indicates success.
    ///
    /// Note: you can only add blocks in serial sequence from 0 -> latest.
    void addBlock(PreProcessedBlockPtr ppb, bool alsoSaveUnfoInfo, unsigned num2ReserveAfter = 0, bool notifySubs = false,
                  bool trackRecentBlockTxHashes = false);

    /// Thread-safe.  Will attempt to undo the latest block that was previously added via a successfully completed call
    /// to addBlock().  This should be called if addBlock throws HeaderVerificationFailure. This function may throw
    /// on low-level database error or if undo information has been exhausted and the latest tip cannot be rolled back.
    /// At that point it's a fatal error (and the app should probably quit?).
    ///
    /// Returns the new BlockHeight .. which is the current height - 1 (after this call returns, this will be
    ///  the same int value as latestTip().first).
    BlockHeight undoLatestBlock(bool notifySubs = false);

    /// returns the "next" TxNum (thread safe, lock-free)
    TxNum getTxNum() const;
    /// convenience method  (thread safe, lock-free)
    bool isNewlyInitialized() const { return getTxNum() == 0; }

    /// Helper for TxNum. Resolve a 64-bit TxNum to a TxHash -- this may throw a DatabaseError if throwIfMissing=true (thread safe, takes no class-level locks)
    std::optional<TxHash> hashForTxNum(TxNum, bool throwIfMissng = false, bool *wasCached = nullptr, bool skipCache = false) const;
    /// Given a TxNum, returns the block height for the TxNum's block (if it exists).
    /// Used to resolve scripthash_history -> block height for get_history. (thread safe, takes blkInfo lock)
    std::optional<unsigned> heightForTxNum(TxNum) const;
    /// Given a block height and a position in the block (txIdx), return a TxHash.  Never throws. Returns !has_value if
    /// height/posInBlock pair is not found (or in very unlikely cases, if there was an underlying low-level error).
    /// Thread safe, takes class-level locks.
    /// @param existingBlocksLock - set to non-nullptr if you already took the class-level `blocksLock` from calling code (this param is for internal use only)
    std::optional<TxHash> hashForHeightAndPos(BlockHeight height, uint32_t posInBlock,
                                              const SharedLockGuard *existingBlocksLock = nullptr) const;

    /// Given a height and an array of positions in a block, returns a vector of the TxHashes for the positions in question.
    /// Never throws. Missing or not found positions are marked with an empty optional in the resultant vector.
    /// Returns an empty vector if height exceeds the chain tip height.
    /// Thread safe, takes class-level locks.
    /// @param existingBlocksLock - set to non-nullptr if you already took the class-level `blocksLock` from calling code (this param is for internal use only)
    std::vector<std::optional<TxHash>> hashesForHeightAndPosVec(BlockHeight height, Span<const uint32_t> positionsInBlock,
                                                                const SharedLockGuard *existingBlocksLock = nullptr) const;

    /// Given a block height, return all of the TxHashes in a block, in bitcoind memory order.
    ///
    /// NOTE: Unlike all of the other functions in this class, the returned hashes are in bitcoind memory order
    /// (rather than reversed hex-encode-ready memory order as we use everywhere else).  This is because this function
    /// is designed to be used with the "Merkle" set of functions directly.  It internally caches its results as well.
    ///
    /// Never throws. Returns an empty vector if height is not found (or in very unlikely cases, if there was an
    /// underlying low-level error).
    ///
    /// Thread safe, takes class-level locks.
    std::vector<TxHash> txHashesForBlockInBitcoindMemoryOrder(BlockHeight height) const;

    /// Returns the known size of the utxo set (for now this is a signed value -- to debug underflow errors)
    int64_t utxoSetSize() const;
    /// Returns the known size of the utxo set in millions of bytes
    double utxoSetSizeMB() const;

    //-- scritphash history
    struct HistoryItem {
        TxHash hash;
        int height = 0; ///< block height. 0 = unconfirmed, -1 = unconfirmed with unconfirmed parent. Note this is ambiguous with block 0 :(
        std::optional<bitcoin::Amount> fee; ///< fee, if known. this is only ever populated with a value for unconfirmed (mempool) tx's

        HistoryItem(const TxHash & h = {}, int ht = 0, const std::optional<bitcoin::Amount> & f = std::nullopt)
            : hash(h), height(ht), fee(f) {}

        // for sort & maps
        bool operator<(const HistoryItem &o) const noexcept;
        bool operator==(const HistoryItem &o) const noexcept;
    };
    using History = std::vector<HistoryItem>;

    /// Thread-safe. Will return an empty vector if the confirmed history size exceeds max_history, or a truncated
    /// vector if the confirmed + unconfirmed history exceeds max_history.
    History getHistory(const HashX &, bool includeConfirmed, bool includeMempool, BlockHeight fromHeight = 0,
                       std::optional<BlockHeight> optToHeight = std::nullopt) const;

    /// Thread-safe. Will return a truncated vector if the history size exceeds rpa_max_history. Range is [from, end)
    History getRpaHistory(const Rpa::Prefix &prefix, bool includeConfirmed, bool includeMempool,
                          BlockHeight fromHeight = 0, std::optional<BlockHeight> endHeight = std::nullopt) const;

    struct UnspentItem : HistoryItem {
        IONum tx_pos = 0;
        bitcoin::Amount value;
        TxNum txNum = 0; ///< the global txNum. This + tx_pos defines the order
        bitcoin::token::OutputDataPtr tokenDataPtr; ///< may be null, not null for outputs containing tokens

        // for sort & maps
        bool operator<(const UnspentItem &o) const noexcept;
        bool operator==(const UnspentItem &o) const noexcept;
    };
    using UnspentItems = std::vector<UnspentItem>;

    enum class TokenFilterOption { IncludeTokens, ExcludeTokens, OnlyTokens };

    /// Thread-safe. Will return an empty vector if the confirmed unspent size exceeds MaxHistory items. It may also
    /// return a truncated vector if the overflow is as a result of confirmed+unconfirmed exceeding MaxHistory.
    UnspentItems listUnspent(const HashX &, TokenFilterOption) const;

    /// thread safe -- returns confirmd, unconfirmed balance for a scripthash
    std::pair<bitcoin::Amount, bitcoin::Amount> getBalance(const HashX &, TokenFilterOption) const;

    //-- scriptHash first use
    struct FirstUse {
        TxHash txHash;
        int height; ///< block height. 0 = unconfirmed, -1 = unconfirmed with unconfirmed parent. Note this is ambiguous with block 0 :(
        BlockHash blockHash; ///< the hash of the block at `height`. Will be 32-bytes of 0 for mempool txn.
        FirstUse(const TxHash &th, int h, const BlockHash &bh) : txHash(th), height(h), blockHash(bh) {}
    };

    /// Thread-safe. Will return the first time a scripthash was used (as an output) either from the blockchain or
    /// in mempool if never seen in a confirmed block, or a std::nullopt if the scriptHash in question was never used
    /// as an output to a txn.
    std::optional<FirstUse> getFirstUse(const HashX & scriptHash) const;

    /// thread safe, called from controller when we are up-to-date
    void updateMerkleCache(unsigned height);

    /// thread safe, returns a BranchAndRootPair for headers from height, cp_height. May throw in rare circumstances
    /// if there was a reorg and cp_height is no longer <= chain height.
    Merkle::BranchAndRootPair headerBranchAndRoot(unsigned height, unsigned cp_height);

    /// Caller must hold the returned SharedLockGuard for as long as they use the reference otherwise bad things happen!
    std::pair<const Mempool &, SharedLockGuard> mempool() const;
    /// Caller must hold the returned ExclusiveLockGuard for as long as they use the reference otherwise bad things happen!
    std::pair<Mempool &, ExclusiveLockGuard> mutableMempool();

    /// Returns true if txhash is in the mempool or in a recent block, false otherwise. Note that "recent block"
    /// tracking is not always enabled, so a false result may not necessarily mean the txn is not in the latest block.
    /// Thread-safe (takes mempool shared lock and/or blocks lock internally).
    bool isMaybeRecentlySeenTx(const TxHash &txhash) const;

    /// Thread-safe. Query db (but not mempool) for a UTXO, and return its info if found.  May throw on database error.
    /// (Does not take the blocks lock)
    std::optional<TXOInfo> utxoGetFromDB(const TXO &, bool throwIfMissing = false);

    /// Thread-safe. Query the mempool and the DB for a TXO. If the TXO is unspent, will return a valid
    /// optional.  If the TXO is spent or non-existant, will return a !has_value optional. May throw on internal
    /// or database error. (Does not take the blocks lock)
    ///
    /// If the returned optional has a value, then check its TXOInfo::confirmedHeight member to determine if it is a
    /// mempool or confirmed UTXO (mempool UTXOs will have an invalid optional for TXOInfo::confirmedHeight).
    std::optional<TXOInfo> utxoGet(const TXO &);

    /// This pointer is guaranteed to always be valid once this instance has been constructed. It points to the
    /// subsmgr unique_ptr which this instance owns.
    ///
    /// It is exposed this way publicly because other classes that hold references to Storage need to access
    /// the shared SubsMgr (which itself exposes a public thread-safe interface intented to be called from multiple
    /// subsystems and multiple threads).
    ScriptHashSubsMgr * subs() const { return subsmgr.get(); }
    /// Identical to above, but points to the DSProofSubsMgr for this instance.
    DSProofSubsMgr * dspSubs() const { return dspsubsmgr.get(); }
    /// Identical to above, but points to the TransactionSubsMgr for this instance.
    TransactionSubsMgr * txSubs() const { return txsubsmgr.get(); }

    /// called from a timer periodically from Controller (see Controller.cpp)
    /// -- takes locks, updates compact fee histogram for the mempool
    void refreshMempoolHistogram();

    /// Takes a shared lock and returns the cached mempool histogram (calculated periodically in refreshMempoolHistogram above)
    Mempool::FeeHistogramVec mempoolHistogram() const;

    // -- Tx Hash index based methods
    using TxHeightsResult = std::vector<std::optional<BlockHeight>>;

    /// Thread-safe. Does take mempool, blkInfo, and blocksLock locks in shared mode. Returns an array whose length is
    /// equal to txHashes.size(), and for each element: if the optional is valid, then BlockHeight=0 means mempool, and
    /// >0 means a confirmed height. If a particular TxHash was not found in the mempool or blockchain, that element
    /// will have a std::nullopt.
    ///
    /// May throw DatabaseError (unlikely) or some other Exception subclass. Note that txHashes should contain 0 or
    /// more 32-byte hashes in big-endian (JSON) memory order, otherwise this may throw if the hashes are of the wrong
    /// length.
    TxHeightsResult getTxHeights(const std::vector<TxHash> &txHashes) const;
    /// Convenience function. Same as above but optimized to query a single txhash.
    std::optional<BlockHeight> getTxHeight(const TxHash &) const;

    /// Thread-safe. Retrieve the block header and block height for a confirmed transaction.
    std::optional<std::pair<BlockHeight, Header>> getConfirmedTxBlockHeightAndHeader(const TxHash &) const;

    // --- DUMP methods --- (used for debugging, largely)

    using DumpProgressFunc = std::function<void(size_t)>;
    /// Thread-safe. Call this from any thread, but ideally call it from a threadPool worker thread, since it may take
    /// a while. Dumps all scripthashes as JSON data to output device outDev as an array of hex-encoded JSON strings,
    /// optionally indented by `indent*indentLevel` spaces. If indent is 0, the output will all be on 1 line with no
    /// padding.
    size_t dumpAllScriptHashes(QIODevice *outDev, unsigned indent=0, unsigned indentLevel=0, const DumpProgressFunc & = {}, size_t progInterval = 100000) const;

    struct UTXOSetStats {
        BlockHeight block_height;
        BlockHash block_hash;
        size_t utxo_db_ct{}, shunspent_db_ct{};
        size_t utxo_db_size_bytes{}, shunspent_db_size_bytes{};
        QByteArray utxo_db_shasum, shunspent_db_shasum; // sha256d sum of all key/value pairs in both dbs
    };
    /// Thread-safe. Call this from any thread, but ideally call it from a threadPool worker thread, since it may take
    /// a while. Will iterate over the entire utxoset db and scripthash_unspent db and return some stats. Used by
    /// the /debug HTTP endpoint.
    UTXOSetStats calcUTXOSetStats(const DumpProgressFunc & = {}, size_t progInterval = 100000) const;

    /// Thread-safe. Returns true if RPA index is enabled, false otherwise. May return false before app is fully
    /// initted and if the requested RPA mode is "auto" and we haven't yet decided if on or off based on "Coin".
    bool isRpaEnabled() const;

    /// Thread-safe. Returns the height from which user wants to begin indexing RPA data, or -1 if RPA is disabled.
    /// Note: this doesn't necessarily indicate we *have* this height indexed (yet!); it's just what the user wants.
    int getConfiguredRpaStartHeight() const;

    /// Type used only by getRpaDBHeightRange() but maybe useful in the future for other methods, hence the typedef.
    using HeightRange = std::pair<BlockHeight, BlockHeight>;
    /// Thread-safe. Returns a pair of {fromHeight, toHeight} which is the current inclusive range of heights that the
    /// RPA index covers in the DB. Will return a nullopt if either: (1) RPA indexing is disabled, or (2) The index is
    /// enabled but the index is empty (which can happen if the configured start height > current tip height, for
    /// instance).  As the DB synchs with RPA enabled the results of this call will be current to reflect the latest DB
    /// state.
    ///
    /// Note: This function is intended only to be called from the Controller thread. Calling it from other code may
    /// risk a potentially inconsistent view since it just reads 2 atomic ints separately with no locks held.
    std::optional<HeightRange> getRpaDBHeightRange() const;

    /// Called by Controller as it does its independent RPA synch. Thread-safe (takes blocksLock).
    void addRpaDataForHeight(BlockHeight height, const QByteArray &serializedRpaPrefixTable);

    /// Called by Controller. Ensures the RPA db doesn't have entries outside the range [from, to]. In other words,
    /// deletes all entries < from and all entries > to.
    void clampRpaEntries(BlockHeight from, BlockHeight to);

    /// Called by Controller. Sets the "rpaNeedsFullCheck" flag to true
    void flagRpaIndexAsPotentiallyInconsistent();

    /// Called by Controller. If the "rpaNeedsFullCheck" flag was somehow set at some point, will do the slow DB health
    /// checks with a lock held.  Returns true if it did such slow checks, false otherwise. Note: do not call this
    /// unless the RPA index is definitely enabled in the app (Controller respects this criterion).
    bool runRpaSlowCheckIfDBIsPotentiallyInconsistent(BlockHeight configuredStartHeight, BlockHeight tipHeight);

protected:
    virtual Stats stats() const override; ///< from StatsMixin

    // -- Header and misc

    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard> headerVerifier();
    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<const BTC::HeaderVerifier &, SharedLockGuard> headerVerifier() const;


    // -- the below are used inside addBlock (and undoLatestBlock) to maintain the UTXO set & Headers
    class UTXOCache;

    /// Used to manage updates to a rocksdb::WriteBatch; used for updating the db in an abstracted fashion so as to support
    /// UTXOCache. Called internally from addBlock and undoLatestBlock().
    struct UTXOBatch {
        UTXOBatch(rocksdb::WriteBatch &batch, rocksdb::ColumnFamilyHandle &utxoset, rocksdb::ColumnFamilyHandle &shunspent,
                  std::atomic_int64_t &utxoCtr);
        UTXOBatch(UTXOBatch &&);
        /// Enqueue an add of a utxo -- does not take effect in db until p->batch is written to db (for non-UTXOCache mode),
        /// or until the cache is written to db if in UTXOCache mode -- may throw.
        void add(TXO &&, TXOInfo &&, const CompactTXO &);
        /// Enqueue a removal -- does not take effect in db until p->batch is committed to db (for non-UTXOCache mode),
        /// or until the cache is written to db if in UTXOCache mode -- may throw.
        void remove(const TXO &, const HashX &, const CompactTXO &);

    private:
        friend class Storage;
        UTXOBatch(const UTXOBatch &) = delete;
        UTXOBatch & operator=(const UTXOBatch &) = delete;
        struct P;
        std::unique_ptr<P> p;
    };

    /// Internally called by addBlock. Call this with the heaverVerifier lock held.
    /// Appends header h to the database at height. Note that it is undefined to call this function
    /// if height already exists in the database or if height is more than 1+ latestTip().first. For internal use
    /// in addBlock, basically.
    void appendHeader(rocksdb::WriteBatch &batch, const Header &h, BlockHeight height);
    /// Internally called by undoLatestBlock. Call this with the headerVerifier lock held.
    /// Rewinds the headers until the latest header is at the specified height.  May throw on error.
    void deleteHeadersPastHeight(rocksdb::WriteBatch &batch, BlockHeight height);

    /// Internally called by LoadCheckRpaDB and undoLatestBlock. Call this with the blocksLock held if in multi-threaded
    /// mode, to ensure DB consistency. Deletes any rpa entries >= height. Returns true on success, false on failure.
    bool deleteRpaEntriesFromHeight(rocksdb::WriteBatch *batch, BlockHeight height, bool flush = false, bool force = false);

    /// Internally called. Call this with the blocksLock held if in multi-threaded mode, to ensure DB consistency.
    /// Deletes any rpa entries <= height. Returns true on success, false on failure.
    bool deleteRpaEntriesToHeight(rocksdb::WriteBatch *batch, BlockHeight height, bool flush = false, bool force = false);

    void clampRpaEntries_nolock(rocksdb::WriteBatch *batch, BlockHeight from, BlockHeight to);

    /// This is set in addBlock and undoLatestBlock while we do a bunch of updates, then cleared when updates are done,
    /// for each block. Thread-safe, may throw.
    void setDirty(rocksdb::WriteBatch &batch, bool dirtyFlag);
    /// If this is true on startup, we know the db must be inconsistent and we refuse to continue, exiting with an
    /// error. Thread-safe, may throw.
    bool isDirty() const;

    /// Called by addBlock and undoLatestBlock to update the utxo_count in the Meta db. Thread-safe, may throw.
    void saveUtxoCt(rocksdb::WriteBatch &batch);
    /// Reads the UtxoCt from the meta db. If they key is missing it will return 0.  May throw on low-level db error.
    int64_t readUtxoCtFromDB() const;

    /// This is set in addBlock and in other places if we find the RPA database may be inconsistent, and should
    /// be checked (possibly on next app startup). Immediately saves a bool to the DB meta table. Thread-safe, may throw.
    void setRpaNeedsFullCheck(bool b);
    /// If this is true on startup, we know the RPA index must be inconsistent and we will run a full health check on
    /// the rpa table and attempt to fix it. Thread-safe, may throw.
    bool isRpaNeedsFullCheck() const;

private:
    const std::shared_ptr<const Options> options;
    const std::unique_ptr<ScriptHashSubsMgr> subsmgr;
    const std::unique_ptr<DSProofSubsMgr> dspsubsmgr;
    const std::unique_ptr<TransactionSubsMgr> txsubsmgr;

    struct Pvt;
    const std::unique_ptr<Pvt> p;

    void save_impl(SaveSpec override = SaveItem::None); ///< may abort app on database failure (unlikely).
    void saveMeta_impl(); ///< This may throw if db error. Caller should hold locks or be in single-threaded mode.

    bool isDirty_impl(rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf) const;

    void checkFulc1xUpgradeDB(); ///< may throw -- must be called from startup() before the below...
    void loadCheckHeadersInDB(); ///< may throw -- called from startup()
    void loadCheckUTXOsInDB(); ///< may throw -- called from startup()
    void loadCheckShunspentInDB(); ///< may throw -- called from startup()
    void loadCheckRpaDB(); ///< may throw -- called from startup()
    void loadCheckTxNumsDRAAndBlkInfo(); ///< may throw -- called from startup()
    void loadCheckTxHash2TxNumMgr(); ///< may throw -- called from startup()
    void loadCheckEarliestUndo(); ///< may throw -- called from startup()
    void checkUpgradeDBVersion(); ///< may throw -- called from startup() as the last thing

    std::optional<Header> headerForHeight_nolock(BlockHeight height, QString *errMsg = nullptr) const;
    std::vector<Header> headersFromHeight_nolock_nocheck(BlockHeight height, unsigned count, QString *errMsg = nullptr) const;

    /// thread-safe helper that returns hashed headers starting from start up until count (hashes are in bitcoin memory order)
    std::vector<QByteArray> merkleCacheHelperFunc(unsigned start, unsigned count, QString *err);

    /// Called from startup. Opens and/or creates the DB and sets up all column families, etc.
    void openOrCreateDB(bool bulkLoad = false);
    /// Called from cleanup. Does some flushing and gently closes all open column families and closes the DB.
    void gentlyCloseDB();

    /// Only does something if options->compactDBs is true (iff --compact-dbs specified on CLI)
    void compactAllDBs();

    // Called by heightForTxNum which calls this with the blockInfo lock held
    std::optional<unsigned> heightForTxNum_nolock(TxNum) const;

    /// Writes to the RPA table. Called from addBlock()
    void addRpaDataForHeight_nolock(rocksdb::WriteBatch &batch, BlockHeight height, const QByteArray &serializedRpaPrefixTable);
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Storage::SaveSpec)

/**

Data model for Fulcrum:  (120 column editor width recommended here)

RocksDB: "meta"
  Purpose:  metadata and sanity checks (see Storage.cpp)

RocksDB: "headers"
  Purpose:  Data store for headers.
  Data layout:  Each header is 80 bytes and they are laid out 1 after the other in buckets of size 8. See
  DBRecordArray.cpp for how this data layout works.

RocksDB: "txnum2txhash"
  Purpose:  Mapping of TxNum -> TxId(hash)
  Data layout: Each TxHash is 32 bytes and the hashes are laid out one after another in buckets of size 16. See DBRecordArray.cpp.
  Key: record number -> txid_raw_bytes  ; maps a "txnum" to its 32-byte txid. Each tx on the blockchain has a
  monotonically increasing txnum based on where it appeared on the blockchain. Block 0, tx 0 has "txnum" 0, up until
  the last tx N in block 0, which has "txnum" N. Tx 0 in block 1 then follows with "txnum" N+1, and so on.

RocksDB: "blkinfo"
  Purpose:  Allow for undoing on reorg and store some metadata for each block
  Key:  "num_blocks" -> value (uint32) one past the last block height saved (eg the latest valid block_height
  to use above would be one less than this number).
  Key:  block_height (serialized uint32 of the height in question) -> values:  txNum0, nTx
  Discussion:  Undoing involves going to the height to undo, getting the list of scripthashes, then hitting the
  scripthash_history table (and other scripthash related tables) for each one touched and removing the history entry
  for this block.  TODO: Finish this section...

RocksDB: "undo"
  We store max 10-1000 of these or so for undoing on reorg
  Key: block_height (uint32) (see Storage.cpp)
  Value: a serialized structure that captures the undo info (see struct UnfoInfo in Storage.cpp).. such as
  scripthashes, txo outs, txo ins (spends), etc.  The idea is to be able to roll back the utxoset to the state it had
  before this block occurred, as well as roll back the scripthash history and the txids

RocksDB: "scripthash_history"
  Purpose: the place where the history is stored for eg scripthash_status and get_history
  Key: scripthash_raw_bytes (32 bytes)
  -> values: An ordered list of unique txNums: 6-byte txNums (txNum [uint48] , ... ), for all tx's spending from or to
  a scripthash.

RocksDB: "utxoset"
  Purpose: serialize the UTXOSet structure as seen in the sources. loading this involves iterating over entire table.
  Key: "prevoutHash+outN (see struct TXO) (34 or 35 bytes)
  Value:  8-byte amount , 32-byte hashX .. see struct TXOInfo.

RocksDB: "scripthash_unspent"
  Key: scripthash_raw_bytes + serialized CompactTXO (40 or 41 bytes)
  Value: 8-byte amount field (64-bit signed integer), plus optional tokenData (prefixed by 0xef)
  Comments: It turns out scanning by prefix over a table is blazingly fast in rocksdb, so we can easily do listunspent
  using this scheme. I tried a read-modify-write approach (keying off just HashX) and it was painfully slow on synch.
  This is much faster to synch.

RocksDB: "txhash2txnum"
  Key: The last 6 bytes of the txhash in question (txhash bytes being in big endian byte order, i.e. JSON byte order).
  Value: One or more serialized VarInts. Each VarInt represents a "TxNum" (which tells us where the actual hash lives
    in the txnum2txhash flat file).
  Comments: This table is basically a hash table of txhash -> txNum and it allows us to answer questions such as whether
    a particular tx exists in the blockchain, and if so, which block it was confirmed in.  Used by some of the newer
    RPCs. Note that to save space the keys of our hash table are just the last 6 bytes of the txhash, which is fine
    since collisions will be relatively rare for quite some time in the future. If there is a collision then simply
    there will be more than 1 VarInt(TxNum) in that particular bucket, and we have to check each txNum in the bucket
    for that key in series versus the txnum flat-file.  The performance penalty for this is extremely small since the
    txnum flat-file is extremely fast to query given a txNum.

RocksDB: "rpa"
  Purpose: store tx indices referenced by prefix in the Rpa::PrefixTable structure for allowing for reusable address queries
  Key: 32-bit height (big endian byte order)
  Value: A single serialized Rpa::PrefixTable for this block height.
  Comments: The Rpa::PrefixTable stores 24-bit txIdx values in a table containing 65536 (possibly empty) rows for
    supporting up to 16-bit integer prefixes. See Rpa.h.

A note about ACID: (atomic, consistent, isolated, durable)

Abrupt program termination is ok (becasue rocksdb uses journaling internally), so long as we didn't experience a
complete OS crash. In order to guard against OS crashes, one would have to enable rocksdb synch flushing on writes,
which degrades performance

*/
