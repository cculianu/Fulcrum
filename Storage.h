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

    // some types
    using Headers = std::vector<QByteArray>; ///< each header is 80 bytes
    using RWLock = std::shared_mutex;
    using Lock = std::mutex;
    using ExclusiveLockGuard = std::unique_lock<RWLock>;
    using SharedLockGuard = std::shared_lock<RWLock>;
    using LockGuard = std::unique_lock<Lock>;

    /// Returns a reference to the headers in our memory cache, locked in exclusive mode.
    /// Be sure to keep the ExclusiveLockGuard in scope until the updates to the vector are complete in order to keep
    /// the data structure locked.
    /// This is howe we update the headers vector.
    /// Be sure to call save(Hdrs) if you have mutated the headers and want the updates saved to disk.
    std::pair<Headers &, ExclusiveLockGuard> mutableHeaders();
    /// How we read headers from our memory cache. The lock is locked in shared mode.
    std::pair<const Headers &, SharedLockGuard> headers() const;

    /// Implicitly takes a lock to return this. Thread safe. Breakdown of info returned:
    ///   .first - the latest valid height we have synched or -1 if no headers.
    ///   .second - the latest valid chainTip 32-byte sha256 double hash of the header (the chainTip as it's called in
    ///             bitcoind parlance), in bitcoind REVERSED memory order (that is, ready for json sending/receiving).
    ///             (Empty if no headers yet).
    std::pair<int, QByteArray> latestTip() const;

    /// eg 'main' or 'test' or may be empty string if new db (thread safe)
    QString getChain() const;
    void setChain(const QString &); // implicitly calls db save of 'meta' (thread safe)

    enum class SaveItem : uint32_t {
        Hdrs = 0x1,  ///< save headers
        Meta = 0x2, ///< save meta

        All = 0xffffffff, ///< save everything
        None = 0x00, ///< No-op
    };
    Q_DECLARE_FLAGS(SaveSpec, SaveItem)

    /// Keep the returned LockGuard in scope while you use the HeaderVerifier
    std::pair<BTC::HeaderVerifier &, LockGuard> headerVerifier();

    /// schedules updates to be written to disk immediately when control returns to this
    /// object's thread's event loop.
    void save(SaveSpec = SaveItem::All);


    // --- Block Processing (still a WIP)

    std::pair<UTXOSet &, ExclusiveLockGuard> mutableUtxoSet();
    std::pair<const UTXOSet &, SharedLockGuard> utxoSet() const;

    /// Thread-safe. Call this from the controller thread or any thread. Returns the empty string on success,
    /// or a string containing an error message on failure.  A common failure reason would be a header verification
    /// failure.  Note: you can only add blocks in serial sequence from 0 -> latest.
    /// This function will mutate the pased-in pre-processed block and fill in all the inputs from the utxo set,
    /// as well as modify the utxo set with spends / new outputs.
    QString addBlock(PreProcessedBlockPtr ppb, unsigned num2ReserveAfter = 0);

    /// returns the "next" TxNum (thread safe)
    TxNum getTxNum() const;

protected:
    virtual Stats stats() const override; ///< from StatsMixin

private:
    const std::shared_ptr<Options> options;

    struct Pvt;
    std::unique_ptr<Pvt> p;

    void save_impl(); ///< may abort app on database failure (unlikely).
    void saveHeaders_impl(const Headers &); ///< This may throw on database error. Caller should pass a copy of the headers or hold the lock (if passing reference to p->headers).
    void saveMeta_impl(); ///< This may throw if db error. Caller should hold locks or be in single-threaded mode.

    void loadHeadersFromDB(); // may throw -- called from startup()

    // some helpers for TxNum -- these may throw DatabaseError
    std::optional<TxNum> txNumForHash(const TxHash &, bool throwIfMissing = false);
    std::optional<TxHash> hashForTxNum(TxNum, bool throwIfMissng = false);

};

Q_DECLARE_OPERATORS_FOR_FLAGS(Storage::SaveSpec)

#endif // STORAGE_H
