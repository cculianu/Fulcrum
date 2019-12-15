#ifndef STORAGE_H
#define STORAGE_H

#include "BlockProc.h"
#include "Mgr.h"
#include "Mixins.h"
#include "Options.h"
#include "TXO.h"

#include <QByteArray>
#include <QFlags>

#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <utility>
#include <vector>

namespace BTC { class HeaderVerifier; } // fwd decl used below. #include "BTC.h" to see this type

/// Generic database error
struct DatabaseError : public Exception { using Exception::Exception; ~DatabaseError() override; };
/// Key was not found in the database
struct DatabaseKeyNotFound : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseKeyNotFound() override; };
/// Key was found but deserialization of key failed when reading from the db, or serializing to a db slice failed.
struct DatabaseSerializationError : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseSerializationError() override; };
/// The database appears to be of the wrong format / unrecognized.
struct DatabaseFormatError : public DatabaseError { using DatabaseError::DatabaseError; ~DatabaseFormatError() override; };


class Storage final : public Mgr, public ThreadObjectMixin
{
public:
    Storage(const std::shared_ptr<Options> & options);
    ~Storage() override;

    // Mgr interface
    void startup() override;
    void cleanup() override;
    // /Mgr

    // Public interface -- unless otherwise specified all functions below are thread-safe

    // -- Header-related
    using Header = QByteArray;
    using HeaderHash = QByteArray;

    /// Thread safe. May hit the database (or touch a cache).  Returns the header for the given height or nothing if
    /// height > latestTip().first.  May also fail on low-level db error. Use the optional arg *err to see why if failed.
    std::optional<Header> headerForHeight(unsigned height, QString *err = nullptr);
    /// Convenient batched alias for above. Returns a set of headers starting at height. May return < count if not
    /// all headers were found. Thead safe.
    std::vector<Header> headersFromHeight(unsigned height, unsigned count, QString *err = nullptr);

    /// Implicitly takes a lock to return this. Thread safe. Breakdown of info returned:
    ///   .first - the latest valid height we have synched or -1 if no headers.
    ///   .second - the latest valid chainTip 32-byte sha256 double hash of the header (the chainTip as it's called in
    ///             bitcoind parlance), in bitcoind REVERSED memory order (that is, ready for json sending/receiving).
    ///             (Empty if no headers yet).
    std::pair<int, HeaderHash> latestTip() const;

    /// eg 'main' or 'test' or may be empty string if new db (thread safe)
    QString getChain() const;
    void setChain(const QString &); // implicitly calls db save of 'meta' (thread safe)

    enum class SaveItem : uint32_t {
        Meta = 0x1, ///< save meta

        All = 0xffffffff, ///< save everything
        None = 0x00, ///< No-op
    };
    Q_DECLARE_FLAGS(SaveSpec, SaveItem)

    /// schedules updates to be written to disk immediately when control returns to this
    /// object's thread's event loop.
    void save(SaveSpec = SaveItem::All);

    // --- Block Processing (still a WIP)

    /// Thread-safe. Call this from the Controller thread or any thread. Returns the empty string on success,
    /// or a string containing an error message on failure.  A common failure reason would be a header verification
    /// failure.  Note: you can only add blocks in serial sequence from 0 -> latest.
    /// This function will mutate the pased-in pre-processed block and fill in all the inputs from the utxo set,
    /// as well as modify the utxo set with spends / new outputs.
    QString addBlock(PreProcessedBlockPtr ppb, bool alsoSaveUnfoInfo, unsigned num2ReserveAfter = 0);

    /// returns the "next" TxNum (thread safe)
    TxNum getTxNum() const;

    /// Helper for TxNum. Resolve a 64-bit TxNum to a TxHash -- this may throw a DatabaseError if throwIfMissing=true (thread safe)
    std::optional<TxHash> hashForTxNum(TxNum, bool throwIfMissng = false, bool *wasCached = nullptr, bool skipCache = false) const;
    /// Given a TxNum, returns the block height for the TxNum's block (if it exists).
    /// Used to resolve scripthash_history -> block height for get_history. (thread safe)
    std::optional<unsigned> heightForTxNum(TxNum) const;

    /// Returns the known size of the utxo set (for now this is a signed value -- to debug underflow errors)
    int64_t utxoSetSize() const;
    /// Returns the known size of the utxo set in millions of bytes
    double utxoSetSizeMiB() const;

    //-- scritphash history (WIP)
    struct HistoryItem {
        TxHash hash;
        unsigned height = 0;

        // for sort & maps
        bool operator<(const HistoryItem &o) const noexcept;
        bool operator==(const HistoryItem &o) const noexcept;
    };
    using History = std::vector<HistoryItem>;

    // thread safe
    History getHistory(const HashX &) const;

    struct UnspentItem : HistoryItem {
        IONum tx_pos = 0;
        bitcoin::Amount value;
        TxNum txNum = 0; ///< the global txNum. This + tx_pos defines the order

        // for sort & maps
        bool operator<(const UnspentItem &o) const noexcept;
        bool operator==(const UnspentItem &o) const noexcept;
    };
    using UnspentItems = std::vector<UnspentItem>;

    // thread safe
    UnspentItems listUnspent(const HashX &) const;

protected:
    virtual Stats stats() const override; ///< from StatsMixin

    // -- Header and misc
    // some types
    using RWLock = std::shared_mutex;
    using Lock = std::mutex;
    using ExclusiveLockGuard = std::unique_lock<RWLock>;
    using SharedLockGuard = std::shared_lock<RWLock>;
    using LockGuard = std::unique_lock<Lock>;

    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard> headerVerifier();
    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<const BTC::HeaderVerifier &, SharedLockGuard> headerVerifier() const;


    // -- the below are used inside addBlock to maintain the UTXO set & Headers

    /// Thread-safe. Immediately save a UTXO to the db. May throw on database error. Also updates scripthash_unspent.
    void utxoAddToDB(const TXO &, const TXOInfo &, const CompactTXO &);
    /// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
    std::optional<TXOInfo> utxoGetFromDB(const TXO &, bool throwIfMissing = false);
    /// Delete a Utxo from the db. Will throw only on database error (but not if it was missing). Also deletes from scripthash_unspent.
    void utxoDeleteFromDB(const TXO &, const HashX &, const CompactTXO &);

    /// Internally called by addBlock. Call this with the heaverVerifier lock held.
    /// Appends header h to the database at height. Note that it is undefined to call this function
    /// if height already exists in the database or if height is more than 1+ latestTip().first. For internal use
    /// in addBlock, basically.
    void appendHeader(const Header &h, unsigned height);

private:
    const std::shared_ptr<Options> options;

    struct Pvt;
    std::unique_ptr<Pvt> p;

    void save_impl(SaveSpec override = SaveItem::None); ///< may abort app on database failure (unlikely).
    void saveMeta_impl(); ///< This may throw if db error. Caller should hold locks or be in single-threaded mode.

    void loadCheckHeadersInDB(); ///< may throw -- called from startup()
    void loadCheckUTXOsInDB(); ///< may throw -- called from startup()
    void loadCheckTxNumsFileAndBlkInfo(); ///< may throw -- called from startup()
    void loadCheckEarliestUndo(); ///< may throw -- called from startup()
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Storage::SaveSpec)

#endif // STORAGE_H
