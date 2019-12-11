#include "BTC.h"
#include "LRUCache.h"
#include "Storage.h"

#include "rocksdb/db.h"
#include "rocksdb/iterator.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"

#include <QByteArray>
#include <QDir>

#include <atomic>
#include <list>
#include <optional>
#include <shared_mutex>
#include <tuple>
#include <type_traits>
#include <vector>

DatabaseError::~DatabaseError(){} // weak vtable warning suppression
DatabaseSerializationError::~DatabaseSerializationError() {} // weak vtable warning suppression
DatabaseFormatError::~DatabaseFormatError() {} // weak vtable warning suppression
DatabaseKeyNotFound::~DatabaseKeyNotFound() {} // weak vtable warning suppression

namespace {
    /// Encapsulates the 'meta' db table
    struct Meta {
        uint32_t magic = 0xf33db33f, version = 0x1;
        QString chain; ///< "test", "main", etc
    };

    // some database keys we use -- todo: if this grows large, move it elsewhere
    static const rocksdb::Slice kMeta{"meta"}, kNumHeaders{"num_headers"}, kTxNumNext{"TxNumNext"};
    static constexpr size_t MAX_HEADERS = 100000000; // 100 mln max headers for now.

    /// NOTE: the byte array should live as long as the slice does. slice is just a weak ref into the byte array
    inline rocksdb::Slice ToSlice(const QByteArray &ba) { return rocksdb::Slice(ba.constData(), size_t(ba.size())); }
    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return QByteArray::fromRawData(s.data(), int(s.size())); }
    /// Turn a number eg uint64_t into a db slice directly by just pointing to its memory.
    /// NOTE: The Scalar s should live at least as long as the Slice.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    inline rocksdb::Slice ScalarToSlice(const Scalar &s) { return rocksdb::Slice(reinterpret_cast<const char *>(&s), sizeof(s)); }

    // serialize/deser -- for basic types we use QDataStream, but we also have specializations at the end of this file
    template <typename Type>
    QByteArray Serialize(const Type & n) {
        QByteArray ba;
        if constexpr (std::is_same_v<Type, QByteArray>) {
            ba = n;
        } else {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            ds << n;
        }
        return ba;
    }
    template <typename Type>
    Type Deserialize(const QByteArray &ba, bool *ok = nullptr) {
        Type ret{};
        if constexpr (std::is_same_v<Type, QByteArray>) {
            ret = ba;
        } else {
            QDataStream ds(ba);
            ds >> ret;
            if (ok)
                *ok = ds.status() == QDataStream::Status::Ok;
        }
        return ret;
    }
    /// Serialize a simple value such as an int directly, without using the space overhead that QDataStream imposes.
    /// This is less safe but is more compact since the bytes of the passed-in value are written directly to the
    /// returned QByteArray, without any encapsulation.  Note that use of this mechanism makes all data in the database
    /// no longer platform-neutral, which is ok. The presumption is users can re-synch their DB if switching
    /// architectures.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalar [[maybe_unused]] (const Scalar & s) {
        return QByteArray(reinterpret_cast<const char *>(&s), sizeof(s));
    }
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalarNoCopy (const Scalar &s) {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(&s), sizeof(s));
    }
    /// Inverse of above.  Pass in an optional 'pos' pointer if you wish to continue reading raw scalars from the same
    /// QByteArray during subsequent calls to this template function.  *ok, if specified, is set to false if we ran off
    /// the QByteArray's bounds, and a default-constructed value of 'Scalar' is returned.  No other safety checking is
    /// done.  On successful deserialization of the scalar, *pos (if specified) is updated to point just past the
    /// last byte of the successuflly converted item.  On failure, *pos is always set to point past the end of the
    /// QByteArray.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    Scalar DeserializeScalar(const QByteArray &ba, bool *ok = nullptr, int *pos_out = nullptr) {
        Scalar ret{};
        int dummy = 0;
        int & pos = pos_out ? *pos_out : dummy;
        if (pos >= 0 && pos + int(sizeof(ret)) <= ba.size()) {
            if (ok) *ok = true;
            ret = *reinterpret_cast<const Scalar *>(ba.data() + pos);
            pos += sizeof(ret);
        } else {
            if (ok) *ok = false;
            pos = ba.size();
        }
        return ret;
    }

    // specializations
    template <> QByteArray Serialize(const Meta &);
    template <> Meta Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXO &);
    template <> TXO Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXOInfo &);
    template <> TXOInfo Deserialize(const QByteArray &, bool *);

    /// DB read/write helpers
    /// NOTE: these may throw DatabaseError
    /// If missingOk=false, then the returned optional is guaranteed to have a value if this function returns without throwing.
    /// If missingOk=true, then if there was no other database error and the key was not found, the returned optional !has_value()
    ///
    /// Template arg "safeScalar", if true, will deserialize scalar int, float, etc data using the Deserialize<>
    /// function (uses QDataStream, is platform neutral, but is slightly slower).  If false, we will use the
    /// DeserializeScalar<> fast function for scalars such as ints. It's important to read from the DB in the same
    /// 'safeScalar' mode as was written!
    template <typename RetType, bool safeScalar = false>
    std::optional<RetType> GenericDBGet(rocksdb::DB *db, const rocksdb::Slice & key, bool missingOk = false,
                                        const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                                        bool acceptExtraBytesAtEndOfData = false,
                                        const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions()) ///< if true, we are ok with extra unparsed bytes in data. otherwise we throw. (this check is only done for !safeScalar mode on basic types)
    {
        rocksdb::PinnableSlice datum;
        std::optional<RetType> ret;
        if (UNLIKELY(!db)) throw InternalError("GenericDBGet was passed a null pointer!");
        const auto status = db->Get(ropts, db->DefaultColumnFamily(), key, &datum);
        if (status.IsNotFound()) {
            if (missingOk)
                return ret; // optional will not has_value() to indicate missing key
            throw DatabaseKeyNotFound(QString("%1: %2")
                                      .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Key not found in db")
                                      .arg(QString::fromStdString(status.ToString())));
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error reading a key from the db")
                                .arg(QString::fromStdString(status.ToString())));
        } else {
            // ok status
            if constexpr (std::is_base_of_v<QByteArray, std::remove_cv_t<RetType> >) {
                static_assert (!safeScalar, "safeScalar=true mode is not supported for QByteArrays (it only is useful for scalar types)" );
                // special compile-time case for QByteArray subclasses -- return a deep copy of the data bytes directly.
                // TODO: figure out a way to do this without the 1 extra copy! (PinnableSlice -> ret).
                ret.emplace( reinterpret_cast<const char *>(datum.data()), QByteArray::size_type(datum.size()) );
            } else if constexpr (!safeScalar && std::is_scalar_v<RetType> && !std::is_pointer_v<RetType>) {
                if (!acceptExtraBytesAtEndOfData && datum.size() > sizeof(RetType)) {
                    // reject extra stuff at end of data stream
                    throw DatabaseFormatError(QString("%1: Extra bytes at the end of data")
                                              .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Database format error"));
                }
                bool ok;
                ret.emplace( DeserializeScalar<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized as a scalar '%2'")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error deserializing a scalar from db")
                                .arg(typeid (RetType).name()));
                }
            } else {
                if (UNLIKELY(acceptExtraBytesAtEndOfData))
                    Debug() << "Warning:  Caller misuse of function '" << __FUNCTION__
                            << "'. 'acceptExtraBytesAtEndOfData=true' is ignored when deserializing using QDataStream.";
                bool ok;
                ret.emplace( Deserialize<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error deserializing an object from db"));
                }
            }
        }
        return ret;
    }
    /// Conveneience for above with the missingOk flag set to false. Will always throw or return a real value.
    template <typename RetType, bool safeScalar = false>
    RetType GenericDBGetFailIfMissing(rocksdb::DB * db, const rocksdb::Slice &k, const QString &errMsgPrefix = QString(), bool extraDataOk = false,
                                      const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions())
    {
        return GenericDBGet<RetType, safeScalar>(db, k, false, errMsgPrefix, extraDataOk, ropts).value();
    }

    /// Throws on all errors. Otherwise writes to db.
    template <bool safeScalar = false, typename KeyType, typename ValueType>
    void GenericDBPut(rocksdb::DB *db, const KeyType & key, const ValueType & value,
                      const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                      const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        if constexpr (safeScalar) {
            auto st = db->Put(opts, ToSlice(Serialize(key)), ToSlice(Serialize(value)));
            if (!st.ok()) {
                throw DatabaseError(QString("%1: %2")
                                    .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error writing object to db")
                                    .arg(QString::fromStdString(st.ToString())));
            }
        } else {
            // raw/unsafe scalar
            QByteArray serKey, serVal;
            if constexpr (std::is_scalar_v<KeyType> && !std::is_pointer_v<KeyType>)
                serKey = SerializeScalarNoCopy(key);
            else
                serKey = Serialize(key);
            if constexpr (std::is_scalar_v<ValueType> && !std::is_pointer_v<ValueType>)
                serVal = SerializeScalarNoCopy(value);
            else
                serVal = Serialize(value);
            auto st = db->Put(opts, ToSlice(serKey), ToSlice(serVal));
            if (!st.ok()) {
                throw DatabaseError(QString("%1: %2")
                                    .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error writing object to db")
                                    .arg(QString::fromStdString(st.ToString())));
            }
        }
    }


    // some helper data structs
    struct BlkInfo {
        TxNum txNum0 = 0;
        unsigned nTx = 0, nIns = 0, nOuts = 0;
    };
}

struct Storage::Pvt
{
    const int blockHeaderSize = BTC::GetBlockHeaderSize();

    Meta meta;
    Lock metaLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBs {
        const rocksdb::ReadOptions defReadOpts; ///< avoid creating this each time
        const rocksdb::WriteOptions defWriteOpts; ///< avoid creating this each time

        std::unique_ptr<rocksdb::DB> meta, headers, txnums, blkinfo, utxoset, shist;
    } db;

    BTC::HeaderVerifier headerVerifier;
    mutable RWLock headerVerifierLock;

    std::atomic<TxNum> txNumNext{0};

    //std::vector<BlkInfo> blkInfos; ///< not used (yet!)

    std::atomic<int64_t> utxoCt = 0;

    static constexpr size_t nCacheMax = 100000, nCacheElasticity = 50000;
    LRU::Cache<true, TxNum, TxHash> lruNum2Hash{nCacheMax, nCacheElasticity};
};

Storage::Storage(const std::shared_ptr<Options> & options)
    : Mgr(nullptr), options(options), p(new Pvt)
{
    setObjectName("Storage");
    _thread.setObjectName(objectName());
}

Storage::~Storage() { Debug("%s", __FUNCTION__); cleanup(); }

void Storage::startup()
{
    {   // open all db's ...

        rocksdb::Options opts;
        // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
        opts.IncreaseParallelism(int(Util::getNPhysicalProcessors()));
        opts.OptimizeLevelStyleCompaction();
        // create the DB if it's not already present
        opts.create_if_missing = true;
        opts.error_if_exists = false;
        //opts.max_open_files = 50; ///< testing -- seems this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112
        opts.keep_log_file_num = 5; // ??
        opts.compression = rocksdb::CompressionType::kNoCompression; // for now we test without compression. TODO: characterize what is fastest and best..

        using DBInfoTup = std::tuple<QString, std::unique_ptr<rocksdb::DB> &>;
        const std::list<DBInfoTup> dbs2open = {
            { "meta", p->db.meta },
            { "headers", p->db.headers },
            { "txnums" , p->db.txnums },
            { "blkinfo" , p->db.blkinfo },
            { "utxoset", p->db.utxoset },
            { "scripthash_history", p->db.shist },
        };
        const auto OpenDB = [this, &opts](const DBInfoTup &tup) {
            auto & [name, uptr] = tup;
            rocksdb::DB *db = nullptr;
            rocksdb::Status s;
            // try and open database
            const QString path = options->datadir + QDir::separator() + name;
            s = rocksdb::DB::Open(opts, path.toStdString(), &db);
            if (!s.ok() || !db)
                throw DatabaseError(QString("Error opening %1 database: %2 (path: %3)")
                                    .arg(name).arg(QString::fromStdString(s.ToString())).arg(path));
            uptr.reset(db);
        };

        // open all db's defined above
        for (auto & tup : dbs2open)
            OpenDB(tup);

    }  // /open db's

    // load/check meta
    {
        Meta m_db;
        static const QString errMsg{"Incompatible database format -- delete the datadir and resynch. RocksDB error"};
        if (auto opt = GenericDBGet<Meta>(p->db.meta.get(), kMeta, true, errMsg);
                opt.has_value())
        {
            m_db = opt.value();
            if (m_db.magic != p->meta.magic || m_db.version != p->meta.version) {
                throw DatabaseFormatError(errMsg);
            }
            p->meta = m_db;
            Debug () << "Read meta from db ok";
        } else {
            // ok, did not exist .. write a new one to db
            saveMeta_impl();
        }
    }

    Log() << "Loading database ...";
    // load headers -- may throw
    loadCheckHeadersInDB();
    // count utxos
    loadCheckUTXOsInDB();
    // check txnums
    loadCheckTxNumsInDB();

    start(); // starts our thread
}

void Storage::cleanup()
{
    stop(); // joins our thread

    // TODO: unsaved/"dirty state" detection here -- and forced save, if needed.
}


auto Storage::stats() const -> Stats
{
    // TODO ...
    return Stats();
}

// Keep returned LockGuard in scope while you use the HeaderVerifier
auto Storage::headerVerifier() -> std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard>
{
    return std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard>( p->headerVerifier, p->headerVerifierLock );
}
auto Storage::headerVerifier() const -> std::pair<const BTC::HeaderVerifier &, SharedLockGuard>
{
    return std::pair<const BTC::HeaderVerifier &, SharedLockGuard>( p->headerVerifier, p->headerVerifierLock );
}



QString Storage::getChain() const
{
    LockGuard l(p->metaLock);
    return p->meta.chain;
}

void Storage::setChain(const QString &chain)
{
    {
        LockGuard l(p->metaLock);
        p->meta.chain = chain;
    }
    save(SaveItem::Meta);
}

/// returns the "next" TxNum
TxNum Storage::getTxNum() const { return p->txNumNext.load(); }

auto Storage::latestTip() const -> std::pair<int, HeaderHash> {
    std::pair<int, HeaderHash> ret = headerVerifier().first.lastHeaderProcessed(); // ok; lock stays locked until statement end.

    if (ret.second.isEmpty() || ret.first < 0) {
        ret.first = -1;
        ret.second.clear();
    } else {
        // .ret now has the actual header but we want the hash
        ret.second = BTC::HashRev(ret.second);
    }
    return ret;
}

void Storage::save(SaveSpec typed_spec)
{
    using IntType = decltype(p->pendingSaves.load());
    // enqueue save on event loop if not previously enqueued (we know it was previously enqueued if the p->pendingSaves
    // atomic variable is not 0).
    if (const auto spec = IntType(typed_spec); ! p->pendingSaves.fetch_or(spec))
    {
        QTimer::singleShot(0, this, [this]{save_impl();});
    }
}

void Storage::save_impl(SaveSpec override)
{
    if (const auto flags = SaveSpec(p->pendingSaves.exchange(0))|override; flags) { // atomic clear of flags, grab prev val
        try {
            if (flags & SaveItem::Meta) { // Meta
                LockGuard l(p->metaLock);
                saveMeta_impl();
            }
        } catch (const std::exception & e) {
            Fatal() << e.what(); // will abort app...
        }
    }
}

void Storage::saveMeta_impl()
{
    if (!p->db.meta) return;
    if (auto status = p->db.meta->Put(p->db.defWriteOpts, kMeta, ToSlice(Serialize(p->meta))); !status.ok()) {
        throw DatabaseError("Failed to write meta to db");
    }

    Debug() << "Wrote new metadata to db";
}

void Storage::appendHeader(const Header &h, unsigned int height)
{
    const auto targetHeight = GenericDBGet<uint32_t, true>(p->db.headers.get(), kNumHeaders, true, // missing ok
                                                           "Error reading header count from database").value_or(0);
    if (UNLIKELY(height != targetHeight))
        throw InternalError(QString("Bad use of appendHeader -- expected height %1, got height %2").arg(targetHeight).arg(height));
    rocksdb::WriteBatch batch;
    if (auto stat = batch.Put(ScalarToSlice(uint32_t(height)), ToSlice(h)); !stat.ok())
        throw DatabaseError(QString("Error writing header %1: %2").arg(height).arg(QString::fromStdString(stat.ToString())));
    if (auto stat = batch.Put(kNumHeaders, ToSlice(Serialize(uint32_t(height+1)))); !stat.ok())
        throw DatabaseError(QString("Error writing header size key: %1").arg(QString::fromStdString(stat.ToString())));
    if (auto stat = p->db.headers->Write(p->db.defWriteOpts, &batch); !stat.ok())
        throw DatabaseError(QString("Error writing header %1: %2").arg(height).arg(QString::fromStdString(stat.ToString())));
}

auto Storage::headerForHeight(unsigned height, QString *err) -> std::optional<Header>
{
    std::optional<Header> ret;
    if (int(height) <= latestTip().first) {
        static const QString errMsg("Failed to retrieve header from db");
        try {
            ret.emplace(
                GenericDBGetFailIfMissing<QByteArray>(
                    p->db.headers.get(), ScalarToSlice(uint32_t(height)), errMsg, false, p->db.defReadOpts));
            if (UNLIKELY(ret.value().size() != p->blockHeaderSize)) {
                ret.reset();
                throw DatabaseSerializationError("Bad header read from db. Wrong size!"); // jumps to below catch
            }
        } catch (const std::exception &e) {
            if (err) *err = e.what();
        }
    }
    return ret;
}

/// Convenient batched alias for above. Returns a set of headers starting at height. May return < count if not
/// all headers were found. Thead safe.
auto Storage::headersFromHeight(unsigned height, unsigned count, QString *err) -> std::vector<Header>
{
    std::vector<Header> ret;
    int num = std::min(1 + latestTip().first - int(height), int(count));
    if (num > 0) {
        if (err) *err = "";
        ret.reserve(unsigned(num));
        for (int i = 0; i < num; ++i) {
            auto opt = headerForHeight(height + unsigned(i), err);
            if (!opt.has_value())
                break;
            ret.emplace_back(std::move(opt.value()));
        }
    } else if (err) *err = "No headers in the specified range";
    ret.shrink_to_fit();
    return ret;
}


void Storage::loadCheckHeadersInDB()
{
    FatalAssert(!!p->db.headers) << __FUNCTION__ << ": Headers db is not open";

    Log() << "Verifying headers ...";
    uint32_t num = 0;
    const auto t0 = Util::getTimeNS();
    {
        auto * const db = p->db.headers.get();

        num = GenericDBGet<uint32_t, true>(db, kNumHeaders, true, "Error reading header count from database").value_or(0); // missing ok
        if (num > MAX_HEADERS)
            throw DatabaseFormatError(QString("Header count (%1) in database exceeds MAX_HEADERS! This is likely due to"
                                              " a database format mistmatch. Delete the datadir and resynch it.")
                                      .arg(num));
        // verify headers: hashPrevBlock must match what we actually read from db
        if (num) {
            auto [verif, lock] = headerVerifier();
            Debug() << "Verifying " << num << " " << Util::Pluralize("header", num) << " ...";

            const QString errMsg("Error retrieving header from db");
            QString err;
            // read db
            for (uint32_t i = 0; i < num; ++i) {
                // guaranteed to return a value or throw
                const auto bytes = GenericDBGetFailIfMissing<QByteArray>(db, ScalarToSlice(uint32_t(i)), errMsg, false, p->db.defReadOpts);
                if (UNLIKELY(bytes.size() != p->blockHeaderSize))
                    throw DatabaseFormatError(QString("Error reading header %1, wrong size: %2").arg(i).arg(bytes.size()));
                if (!verif(bytes, &err))
                    throw DatabaseError(QString("%1. Possible databaase corruption. Delete the datadir and resynch.").arg(err));
            }
        }
    }
    if (num) {
        const auto elapsed = Util::getTimeNS();

        Debug() << "Read & verified " << num << " " << Util::Pluralize("header", num) << " from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
    }
}

void Storage::loadCheckUTXOsInDB()
{
    FatalAssert(!!p->db.utxoset) << __FUNCTION__ << ": Utxo set db is not open";

    Log() << "Verifying utxo set ...";

    const auto t0 = Util::getTimeNS();
    {
        const int currentHeight = latestTip().first;

        std::unique_ptr<rocksdb::Iterator> iter(p->db.utxoset->NewIterator(p->db.defReadOpts));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the utxo set db");
        iter->SeekToFirst();
        p->utxoCt = 0;
        for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
            // TODO: the below checks may be too slow. See about removing them and just counting the iter.
            const auto txo = Deserialize<TXO>(FromSlice(iter->key()));
            if (!txo.isValid()) {
                throw DatabaseSerializationError("Read an invalid txo from the utxo set database."
                                                 " This may be due to a database format mismatch."
                                                 "\n\nDelete the datadir and resynch to bitcoind.\n");
            }
            auto info = Deserialize<TXOInfo>(FromSlice(iter->value()));
            if (!info.isValid())
                throw DatabaseSerializationError(QString("Txo %1 has invalid metadata in the db."
                                                        " This may be due to a database format mismatch."
                                                        "\n\nDelete the datadir and resynch to bitcoind.\n")
                                                 .arg(txo.toString()));
            if (info.confirmedHeight.has_value() && int(info.confirmedHeight.value()) > currentHeight) {
                // TODO: reorg? Inconsisent db?  FIXME
                QString msg;
                {
                    QTextStream ts(&msg);
                    ts << "Inconsistent database: txo " << txo.toString() << " at height: "
                       << info.confirmedHeight.value() << " > current height: " << currentHeight << "."
                       << "\n\nThe database has been corrupted. Please delete the datadir and resynch to bitcoind.\n";
                }
                throw DatabaseError(msg);
            }
            if (0 == ++p->utxoCt % 100000) {
                *(0 == p->utxoCt % 2500000 ? std::make_unique<Log>() : std::make_unique<Debug>()) << "Verified " << p->utxoCt << " utxos ...";
            }
        }
        const auto ct = utxoSetSize();
        if (ct)
            Log() << "UTXO set: "  << ct << Util::Pluralize(" utxo", ct)
                  << ", " << QString::number(utxoSetSizeMiB(), 'f', 3) << " MiB";
    }
    const auto elapsed = Util::getTimeNS();
    Debug() << "Read txos from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
}

void Storage::loadCheckTxNumsInDB()
{
    // read txNumNext from db. TODO: maybe some verification here to make sure it's not corrupted? Check counts?
    // iterate over all txNums? etc?  FIXME
    if (auto opt = GenericDBGet<TxNum, true>(p->db.txnums.get(), kTxNumNext, true,
                                             "Error reading txNumNext from db", false, p->db.defReadOpts);
            opt.has_value())
    {
        p->txNumNext = opt.value();
        Debug() << "Read TxNumNext from db: " << p->txNumNext.load();
    } else if (latestTip().first > -1) {
        throw DatabaseFormatError("Database is missing the TxNumNext key.\n\nDelete the datadir and resynch to bitcoind.\n");
    }
}



/// Thread-safe. Immediately save a UTXO to the db. May throw on database error.
void Storage::utxoAddToDB(const TXO &txo, const TXOInfo &info)
{
    assert(bool(p->db.utxoset));
    if (txo.isValid()) {
        auto stat = p->db.utxoset->Put(p->db.defWriteOpts, ToSlice(Serialize(txo)), ToSlice(Serialize(info)));
        if (!stat.ok()) {
            throw DatabaseError(QString("Failed to write a utxo (%1:%2) to the db: %3")
                                .arg(QString(txo.prevoutHash.toHex())).arg(txo.prevoutN).arg(QString::fromStdString(stat.ToString())));
        }
        ++p->utxoCt;
    }
}
/// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
std::optional<TXOInfo> Storage::utxoGetFromDB(const TXO &txo, bool throwIfMissing)
{
    assert(bool(p->db.utxoset));
    return GenericDBGet<TXOInfo>(p->db.utxoset.get(), ToSlice(Serialize(txo)), !throwIfMissing, QString(), false, p->db.defReadOpts);
}
/// Delete a Utxo from the db. Will throw only on database error (but not if it was missing).
void Storage::utxoDeleteFromDB(const TXO &txo)
{
    assert(bool(p->db.utxoset));
    auto stat = p->db.utxoset->Delete(rocksdb::WriteOptions(), ToSlice(Serialize(txo)));
    if (!stat.ok()) {
        throw DatabaseError(QString("Failed to delete a utxo (%1:%2) from the db: %3")
                            .arg(QString(txo.prevoutHash.toHex())).arg(txo.prevoutN).arg(QString::fromStdString(stat.ToString())));
    }
    --p->utxoCt;
}

int64_t Storage::utxoSetSize() const { return p->utxoCt; }
double Storage::utxoSetSizeMiB() const {
    constexpr int64_t elemSize = TXO::serSize() + TXOInfo::serSize();
    return (utxoSetSize()*elemSize) / 1e6;
}

QString Storage::addBlock(PreProcessedBlockPtr ppb, unsigned nReserve [[maybe_unused]])
{
    assert(bool(ppb) && bool(p));

    QString errRet;

    std::scoped_lock guard(p->headerVerifierLock); // take all locks now.. todo: add more locks here
    const auto verifUndo = p->headerVerifier; // keep a copy for undo purposes in case this fails

    try {
        // Verify header chain makes sense (by checking hashes, using the shared header verifier)
        QByteArray rawHeader;
        {
            QString errMsg;
            if (!p->headerVerifier(ppb->header, &errMsg) ) {
                // XXX possible reorg point. FIXME TODO
                // reorg here? TODO: deal with this better.
                throw Exception(errMsg);
            }
            // save raw header back to our buffer
            rawHeader = p->headerVerifier.lastHeaderProcessed().second;
        }


        // set up batch update of txnums -- we update the p->nextTxNum after all of this succeeds..
        //auto t0 = Util::getTimeNS();
        constexpr bool useWriteBatch = true; // set this flag to test either codepath
        if constexpr (useWriteBatch) {
            rocksdb::WriteBatch batch;
            const TxNum txNum0 = p->txNumNext;
            for (size_t i = 0; i < ppb->txInfos.size(); ++i) {
                const TxNum txnum = txNum0 + i;
                const TxHash & hash = ppb->txInfos[i].hash;
                // txnums are keyed off of uint64_t txNum -- note we save the raw uint64 value here without any QDataStream encapsulation
                if (auto stat = batch.Put(ScalarToSlice(txnum), ToSlice(hash)); !stat.ok())
                    throw DatabaseError(QString("Error writing txNum -> txHash for txNum %1: %2").arg(txNum0 + i).arg(QString::fromStdString(stat.ToString())));
            }
            if (auto stat = p->db.txnums->Write(p->db.defWriteOpts, &batch); !stat.ok())
                throw DatabaseError(QString("Error writing txNums batch: %1").arg(QString::fromStdString(stat.ToString())));
        } else {
            const TxNum txNum0 = p->txNumNext;
            for (size_t i = 0; i < ppb->txInfos.size(); ++i) {
                const TxNum txnum = txNum0 + i;
                const TxHash & hash = ppb->txInfos[i].hash;
                static const QString errMsg1("Error writing a txNum -> txHash entry to the db"),
                                     errMsg2("Error writing a txHash -> txNum entry to the db");
                // txnums are keyed off of uint64_t txNum -- note we save the raw uint64 value here without any
                // QDataStream encapsulation -- note these may throw
                GenericDBPut<false>(p->db.txnums.get(), txnum, hash, errMsg1, p->db.defWriteOpts);
            }
        }
        //auto elapsed = Util::getTimeNS() - t0;
        //Debug() << "Wrote " << ppb->txInfos.size() << " new TxNums to db in " << QString::number(elapsed/1e6, 'f', 3) << " msec";

        constexpr bool debugPrt = false;

        // update utxoSet
        {
            // add outputs

            for (const auto & [hashX, ag] : ppb->hashXAggregated) {
                std::unordered_set<unsigned> outputsSpentInSameBlock;
                for (const auto iidx : ag.ins) {
                    if (const auto & opt = ppb->inputs[iidx].parentTxOutIdx; opt.has_value())
                        outputsSpentInSameBlock.insert(opt.value());
                }
                for (const auto oidx : ag.outs) {
                    if (outputsSpentInSameBlock.count(oidx)) {
                        if constexpr (debugPrt)
                            Debug() << "Skipping output #: " << oidx << " (was spent in same block)";
                        continue;
                    }
                    const auto & out = ppb->outputs[oidx];
                    const TxHash & hash = ppb->txInfos[out.txIdx].hash;
                    TXOInfo info;
                    info.hashX = hashX;
                    info.amount = out.amount;
                    info.confirmedHeight = ppb->height;
                    const TXO txo{ hash, out.outN };
                    utxoAddToDB(txo, info); // add to db
                    if constexpr (debugPrt)
                        Debug() << "Added txo: " << txo.toString()
                                << " (txid: " << hash.toHex() << " height: " << ppb->height << ") "
                                << " amount: " << info.amount.ToString() << " for HashX: " << info.hashX.toHex();
                }
            }

            // add spends (process inputs)
            std::unordered_set<HashX, HashHasher> newHashXInputsResolved;
            unsigned inum = 0;
            for (auto & in : ppb->inputs) {
                const TXO txo{in.prevoutHash, in.prevoutN};
                if (!inum) {
                    // coinbase.. skip
                } else if (in.parentTxOutIdx.has_value()) {
                    // was an input that was spent in this block so it's ok to skip.. we never added it to utxo set
                    if constexpr (debugPrt)
                        Debug() << "Skipping input " << txo.toString() << ", spent in this block (output # " << in.parentTxOutIdx.value() << ")";
                } else if (const auto opt = utxoGetFromDB(txo); opt.has_value()) {
                    const auto & info = opt.value();
                    if (info.confirmedHeight.has_value() && info.confirmedHeight.value() != ppb->height) {
                        // was a prevout from a previos block.. so the ppb didn't have it in the touched set..
                        // mark the spend as having touched this hashX for this ppb now.
                        ppb->hashXAggregated[info.hashX].ins.emplace_back(inum);
                        newHashXInputsResolved.insert(info.hashX);
                    }
                    if constexpr (debugPrt) {
                        const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                        Debug() << "Spent " << txo.toString() << " amount: " << info.amount.ToString()
                                << " in txid: "  << dbgTxIdHex << " height: " << ppb->height
                                << " input number: " << ppb->numForInputIdx(inum).value_or(0xffff)
                                << " HashX: " << info.hashX.toHex();
                    }
                    // delete from db
                    utxoDeleteFromDB(txo);
                } else {
                    QString s;
                    {
                        const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                        QTextStream ts(&s);
                        ts << "Failed to spend: " << in.prevoutHash.toHex() << ":" << in.prevoutN << " (spending txid: " << dbgTxIdHex << ")";
                    }
                    throw Exception(s);
                }
                ++inum;
            }

            // sort and shrink_to_fit new hashX inputs added
            for (const auto & hashX : newHashXInputsResolved) {
                auto & ag = ppb->hashXAggregated[hashX];
                std::sort(ag.ins.begin(), ag.ins.end()); // make sure they are sorted
                ag.ins.shrink_to_fit();
            }

            if constexpr (debugPrt)
                Debug() << "utxoset size: " << utxoSetSize() << " block: " << ppb->height;
        }

        // save blkInfos -- disabled for now since we aren't using it (yet!)
        /*
        if (nReserve) {
            if (const auto size = p->blkInfos.size(); size + nReserve < p->blkInfos.capacity())
                p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
        }

        p->blkInfos.emplace_back(BlkInfo{
            p->txNumNext, // .txNum0
            unsigned(ppb->txInfos.size()),
            unsigned(ppb->inputs.size()),
            unsigned(ppb->outputs.size())
        });
        */

        // update txNum after everything checks out
        p->txNumNext += ppb->txInfos.size();

        appendHeader(rawHeader, ppb->height);

        // save txNumNext to db so on next startup we have it from where we left off.
        GenericDBPut<true>(p->db.txnums.get(), FromSlice(kTxNumNext), TxNum(p->txNumNext), "Error writing txNumNext to db", p->db.defWriteOpts);

    } catch (const std::exception & e) {
        errRet = e.what();
        p->headerVerifier = verifUndo; // undo header verifier state
    }

    return errRet;
}

std::optional<TxHash> Storage::hashForTxNum(TxNum n, bool throwIfMissing, bool *wasCached, bool skipCache)
{
    std::optional<TxHash> ret;
    if (!skipCache) ret = p->lruNum2Hash.tryGet(n);
    if (ret.has_value()) {
        if (wasCached) *wasCached = true;
        return ret;
    } else if (wasCached) *wasCached = false;

    static const QString kErrMsg ("Error reading hashForTxNum from db");
    ret = GenericDBGet<TxHash, false>(p->db.txnums.get(), ScalarToSlice(n), !throwIfMissing, kErrMsg);
    if (!skipCache && ret.has_value()) {
        // save in cache
        p->lruNum2Hash.insert(n, ret.value());
    }
    return ret;
}


namespace {
    // specializations of Serialize/Deserialize
    template <> QByteArray Serialize(const Meta &m)
    {
        QByteArray ba;
        {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            // we serialize the 'magic' value as a simple scalar as a sort of endian check for the DB
            ds << SerializeScalarNoCopy(m.magic) << m.version << m.chain;
        }
        return ba;
    }
    template <> Meta Deserialize(const QByteArray &ba, bool *ok_ptr)
    {
        bool dummy;
        bool &ok (ok_ptr ? *ok_ptr : dummy);
        ok = false;
        Meta m{0, 0, {}};
        {
            QDataStream ds(ba);
            QByteArray magicBytes;
            ds >> magicBytes; // read magic as raw bytes.
            if ((ok = ds.status() == QDataStream::Status::Ok)) {
                m.magic = DeserializeScalar<decltype (m.magic)>(magicBytes, &ok);
                if (ok) {
                    ds >> m.version >> m.chain;
                    ok = ds.status() == QDataStream::Status::Ok;
                }
            }
        }
        return m;
    }

    template <> QByteArray Serialize (const TXO &txo) { return txo.toBytes(); }
    template <> TXO Deserialize(const QByteArray &ba, bool *ok) {
        TXO ret = TXO::fromBytes(ba);
        if (ok) *ok = ret.isValid();
        return ret;
    }

    template <> QByteArray Serialize(const TXOInfo &inf) { return inf.toBytes(); }
    template <> TXOInfo Deserialize(const QByteArray &ba, bool *ok)
    {
        TXOInfo ret = TXOInfo::fromBytes(ba);
        if (ok) *ok = ret.isValid();
        return ret;
    }
}
