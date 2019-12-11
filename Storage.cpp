#include "BTC.h"
#include "LRUCache.h"
#include "RecordFile.h"
#include "Storage.h"

#include "rocksdb/db.h"
#include "rocksdb/iterator.h"
#include "rocksdb/merge_operator.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"

#include <QByteArray>
#include <QDir>

#include <atomic>
#include <cstring> // for memcpy
#include <list>
#include <optional>
#include <shared_mutex>
#include <string>
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
    static const rocksdb::Slice kMeta{"meta"}, kNumHeaders{"num_headers"};
    static constexpr size_t MAX_HEADERS = 100000000; // 100 mln max headers for now.

    // serialize/deser -- for basic types we use QDataStream, but we also have specializations at the end of this file
    template <typename Type>
    QByteArray Serialize(const Type & n) {
        QByteArray ba;
        if constexpr (std::is_base_of_v<QByteArray, Type>) {
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
        if constexpr (std::is_base_of_v<QByteArray, Type>) {
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

    using TxNumVec = std::vector<TxNum>;
    // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
    template <> QByteArray Serialize(const TxNumVec &);
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize(const QByteArray &, bool *);

    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return QByteArray::fromRawData(s.data(), int(s.size())); }

    /// Generic conversion from any type we operate on to a rocksdb::Slice. Note that the type in question should have
    /// a conversion function written (eg Serialize) if it is anything other than a QByteArray or a scalar.
    template<bool safeScalar=false, typename Thing>
    auto ToSlice(const Thing &thing) {
        if constexpr (std::is_base_of_v<rocksdb::Slice, Thing>) {
            // same type, no-op, return ref to thing (const Slice &)
            return static_cast<const rocksdb::Slice &>(thing);
        } else if constexpr (std::is_base_of_v<QByteArray, Thing>) {
            // QByteArray conversion, return reference to data in QByteArray
            return rocksdb::Slice(thing.constData(), size_t(thing.size()));
        } else if constexpr (!safeScalar && std::is_scalar_v<Thing> && !std::is_pointer_v<Thing>) {
            return rocksdb::Slice(reinterpret_cast<const char *>(&thing), sizeof(thing)); // returned slice points to raw scalar memory itself
        } else {
            // the purpose of this holder is to keep the temporary QByteArray alive for as long as the slice itself is alive
            struct BagOfHolding {
                QByteArray bytes;
                rocksdb::Slice slice;
                operator const rocksdb::Slice &() const { return slice; }
            } h { Serialize(thing), ToSlice(h.bytes) };
            return h; // this holder type "acts like" a Slice due to its operator const Slice &()
        }
    };

    /// DB read/write helpers
    /// NOTE: these may throw DatabaseError
    /// If missingOk=false, then the returned optional is guaranteed to have a value if this function returns without throwing.
    /// If missingOk=true, then if there was no other database error and the key was not found, the returned optional !has_value()
    ///
    /// Template arg "safeScalar", if true, will deserialize scalar int, float, etc data using the Deserialize<>
    /// function (uses QDataStream, is platform neutral, but is slightly slower).  If false, we will use the
    /// DeserializeScalar<> fast function for scalars such as ints. It's important to read from the DB in the same
    /// 'safeScalar' mode as was written!
    template <typename RetType, bool safeScalar = false, typename KeyType>
    std::optional<RetType> GenericDBGet(rocksdb::DB *db, const KeyType & keyIn, bool missingOk = false,
                                        const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                                        bool acceptExtraBytesAtEndOfData = false,
                                        const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions()) ///< if true, we are ok with extra unparsed bytes in data. otherwise we throw. (this check is only done for !safeScalar mode on basic types)
    {
        rocksdb::PinnableSlice datum;
        std::optional<RetType> ret;
        if (UNLIKELY(!db)) throw InternalError("GenericDBGet was passed a null pointer!");
        const auto status = db->Get(ropts, db->DefaultColumnFamily(), ToSlice<safeScalar>(keyIn), &datum);
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
    template <typename RetType, bool safeScalar = false, typename KeyType>
    RetType GenericDBGetFailIfMissing(rocksdb::DB * db, const KeyType &k, const QString &errMsgPrefix = QString(), bool extraDataOk = false,
                                      const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions())
    {
        return GenericDBGet<RetType, safeScalar>(db, k, false, errMsgPrefix, extraDataOk, ropts).value();
    }

    /// Throws on all errors. Otherwise writes to db.
    template <bool safeScalar = false, typename KeyType, typename ValueType>
    void GenericDBPut
                (rocksdb::DB *db, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                 const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Put(opts, ToSlice<safeScalar>(key), ToSlice<safeScalar>(value));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error writing object to db")
                                .arg(QString::fromStdString(st.ToString())));
    }

    //// A helper data structs -- written to the blkinfo table. This helps localize a txnum to a specific position in
    /// a block.  The table is keyed off of block_height(uint32_t) -> serialized BlkInfo (raw bytes)
    struct BlkInfo {
        TxNum txNum0 = 0;
        unsigned nTx = 0;
    };
    // serializes as raw bytes from struct
    template <> QByteArray Serialize(const BlkInfo &);
    // deserializes as raw bytes from struct
    template <> BlkInfo Deserialize(const QByteArray &, bool *);

    // Associative merge operator used for scripthash history concatenation
    // The simpler, associative merge operator.
    class ConcatOperator : public rocksdb::AssociativeMergeOperator {
    public:
        ~ConcatOperator() override;

        mutable std::atomic<uint64_t> merges = 0;

        // Gives the client a way to express the read -> modify -> write semantics
        // key:           (IN) The key that's associated with this merge operation.
        // existing_value:(IN) null indicates the key does not exist before this op
        // value:         (IN) the value to update/merge the existing_value with
        // new_value:    (OUT) Client is responsible for filling the merge result
        // here. The string that new_value is pointing to will be empty.
        // logger:        (IN) Client could use this to log errors during merge.
        //
        // Return true on success.
        // All values passed in will be client-specific values. So if this method
        // returns false, it is because client specified bad data or there was
        // internal corruption. The client should assume that this will be treated
        // as an error by the library.
        bool Merge(const rocksdb::Slice& key, const rocksdb::Slice* existing_value,
                   const rocksdb::Slice& value, std::string* new_value,
                   rocksdb::Logger* logger) const override;
        const char* Name() const override { return "ConcatOperator"; /* NOTE: this must be the same for the same db each time it is opened! */ }
    };
}

ConcatOperator::~ConcatOperator() {} // weak vtable warning prevention

bool ConcatOperator::Merge(const rocksdb::Slice& key, const rocksdb::Slice* existing_value,
                           const rocksdb::Slice& value, std::string* new_value, rocksdb::Logger* logger) const
{
    (void)key; (void)logger;
    ++merges;
    new_value->resize( (existing_value ? existing_value->size() : 0) + value.size() );
    char *cur = new_value->data();
    if (existing_value) {
        std::memcpy(cur, existing_value->data(), existing_value->size());
        cur += existing_value->size();
    }
    std::memcpy(cur, value.data(), value.size());
    return true;
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

        rocksdb::Options opts, shistOpts;

        std::unique_ptr<rocksdb::DB> meta, headers, blkinfo, utxoset, shist;
    } db;

    std::unique_ptr<RecordFile> txNumsFile;

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

        rocksdb::Options & opts(p->db.opts), &shistOpts(p->db.shistOpts);
        // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
        opts.IncreaseParallelism(int(Util::getNPhysicalProcessors()));
        opts.OptimizeLevelStyleCompaction();
        // create the DB if it's not already present
        opts.create_if_missing = true;
        opts.error_if_exists = false;
        //opts.max_open_files = 50; ///< testing -- seems this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112
        opts.keep_log_file_num = 5; // ??
        opts.compression = rocksdb::CompressionType::kNoCompression; // for now we test without compression. TODO: characterize what is fastest and best..
        shistOpts = opts; // copy what we just did
        shistOpts.merge_operator = std::make_shared<ConcatOperator>(); // this set of options uses the concat merge operator (we use this to append to history entries in the db)

        using DBInfoTup = std::tuple<QString, std::unique_ptr<rocksdb::DB> &, const rocksdb::Options &>;
        const std::list<DBInfoTup> dbs2open = {
            { "meta", p->db.meta, opts },
            { "headers", p->db.headers, opts },
            { "blkinfo" , p->db.blkinfo , opts },
            { "utxoset", p->db.utxoset, opts },
            { "scripthash_history", p->db.shist, shistOpts },
        };
        const auto OpenDB = [this](const DBInfoTup &tup) {
            auto & [name, uptr, opts] = tup;
            rocksdb::DB *db = nullptr;
            rocksdb::Status s;
            // try and open database
            const QString path = options->datadir + QDir::separator() + name;
            s = rocksdb::DB::Open( opts, path.toStdString(), &db);
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
    loadCheckTxNumsFileAndBlkInfo();

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
    auto & mop = p->db.shistOpts.merge_operator;
    ConcatOperator *c = mop ? dynamic_cast<ConcatOperator *>(mop.get()) : nullptr;
    QVariantMap ret;
    ret["merge calls"] = c ? c->merges.load() : QVariant();
    return ret;
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
    if (auto stat = batch.Put(ToSlice(uint32_t(height)), ToSlice(h)); !stat.ok())
        throw DatabaseError(QString("Error writing header %1: %2").arg(height).arg(QString::fromStdString(stat.ToString())));
    if (auto stat = batch.Put(kNumHeaders, ToSlice<true>(uint32_t(height+1))); !stat.ok())
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
                    p->db.headers.get(), uint32_t(height), errMsg, false, p->db.defReadOpts));
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
                const auto bytes = GenericDBGetFailIfMissing<QByteArray>(db, uint32_t(i), errMsg, false, p->db.defReadOpts);
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

void Storage::loadCheckTxNumsFileAndBlkInfo()
{
    // may throw.
    p->txNumsFile = std::make_unique<RecordFile>(options->datadir + QDir::separator() + "txnum2txhash", HashLen, 0x000012e2);
    p->txNumNext = p->txNumsFile->numRecords();
    Debug() << "Read TxNumNext from file: " << p->txNumNext.load();
    TxNum ct = 0;
    if (const int height = latestTip().first; height >= 0)
    {
        Log() << "Checking tx counts ...";
        for (int i = 0; i <= height; ++i) {
            static const QString errMsg("Failed to read a blkInfo from db, the database may be corrupted");
            const auto blkInfo = GenericDBGetFailIfMissing<BlkInfo>(p->db.blkinfo.get(), uint32_t(i), errMsg, false, p->db.defReadOpts);
            if (blkInfo.txNum0 != ct)
                throw DatabaseFormatError(QString("BlkInfo for height %1 does not match computed txNum of %2."
                                                  "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                          .arg(i).arg(ct));
            ct += blkInfo.nTx;
        }
        Log() << ct << " total transactions";
    }
    if (ct != p->txNumNext) {
        throw DatabaseFormatError(QString("BlkInfo txNums do not add up to expected value of %1 != %2."
                                          "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                  .arg(ct).arg(p->txNumNext.load()));
    }
}


/// Thread-safe. Immediately save a UTXO to the db. May throw on database error.
void Storage::utxoAddToDB(const TXO &txo, const TXOInfo &info)
{
    assert(bool(p->db.utxoset));
    if (txo.isValid()) {
        static const QString errMsgPrefix("Failed to add a utxo to the utxo db");
        GenericDBPut(p->db.utxoset.get(), txo, info, errMsgPrefix, p->db.defWriteOpts); // may throw on failure
        ++p->utxoCt;
    }
}
/// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
std::optional<TXOInfo> Storage::utxoGetFromDB(const TXO &txo, bool throwIfMissing)
{
    assert(bool(p->db.utxoset));
    static const QString errMsgPrefix("Failed to read a utxo to the utxo db");
    return GenericDBGet<TXOInfo>(p->db.utxoset.get(), txo, !throwIfMissing, errMsgPrefix, false, p->db.defReadOpts);
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
        const auto blockTxNum0 = p->txNumNext.load();

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

        {  // add txnum -> txhash association to the TxNumsFile...
            auto batch = p->txNumsFile->beginBatchAppend(); // may throw if io error in c'tor here.
            QString errStr;
            for (const auto & txInfo : ppb->txInfos) {
                if (!batch.append(txInfo.hash, &errStr)) // does not throw here, but we do.
                    throw InternalError(QString("Batch append for txNums failed: %1.\n\n"
                                                "Database is now likely corrupted. Please delete the datadir and resynch.\n")
                                        .arg(errStr));
            }
            // <-- The batch d'tor may close the app on error here with Fatal() if a low-level file error occurs now
            //     on header update (see: RecordFile.cpp, ~BatchAppendContext()).
        }

        p->txNumNext += ppb->txInfos.size(); // update internal counter

        if (p->txNumNext != p->txNumsFile->numRecords())
            throw InternalError("TxNum file and internal txNumNext counter disagree! FIXME!");


        constexpr bool debugPrt = false;

        // update utxoSet
        {
            // add outputs

            for (const auto & [hashX, ag] : ppb->hashXAggregated) {
                for (const auto oidx : ag.outs) {
                    const auto & out = ppb->outputs[oidx];
                    if (out.spentInInputIndex.has_value()) {
                        if constexpr (debugPrt)
                            Debug() << "Skipping output #: " << oidx << " for " << ppb->txInfos[out.txIdx].hash.toHex() << " (was spent in same block tx: " << ppb->txInfos[ppb->inputs[out.spentInInputIndex.value()].txIdx].hash.toHex() << ")";
                        continue;
                    }
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
                        auto & ag = ppb->hashXAggregated[info.hashX];
                        ag.ins.emplace_back(inum);
                        newHashXInputsResolved.insert(info.hashX);
                        // mark its txidx
                        if (auto & vec = ag.txNumsTouchedByHashX; vec.empty() || vec.back() != in.txIdx)
                            vec.emplace_back(in.txIdx);

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
                std::sort(ag.txNumsTouchedByHashX.begin(), ag.txNumsTouchedByHashX.end());
                auto last = std::unique(ag.txNumsTouchedByHashX.begin(), ag.txNumsTouchedByHashX.end());
                ag.txNumsTouchedByHashX.erase(last, ag.txNumsTouchedByHashX.end());
                ag.ins.shrink_to_fit();
                ag.txNumsTouchedByHashX.shrink_to_fit();
            }

            if constexpr (debugPrt)
                Debug() << "utxoset size: " << utxoSetSize() << " block: " << ppb->height;
        }

        {
            // now.. update the txNumsTouchedByHashX to be offset from txNum0 for this block, and save history to db table
            // history is hashX -> TxNumVec (serialized) as a serities of 6-bytes txNums in blockchain order as they appeared.
            constexpr bool debugSh = false;
            qint64 t0 = 0;
            if constexpr (debugSh) t0 = Util::getTimeNS();
            size_t ctr = 0;
            rocksdb::WriteBatch batch;
            for (auto & [hashX, ag] : ppb->hashXAggregated) {
                for (auto & txNum : ag.txNumsTouchedByHashX) {
                    txNum += blockTxNum0; // transform local txIdx to -> txNum (global mapping)
                }
                if (debugSh) ctr += ag.txNumsTouchedByHashX.size();
                // save scripthash history for this hashX, by appending to existing history. Note that this uses
                // the 'ConcatOperator' class we defined in this file, which requires rocksdb be compiled with RTTI.
                if (auto st = batch.Merge(ToSlice(hashX), ToSlice(Serialize(ag.txNumsTouchedByHashX))); !st.ok())
                    throw DatabaseError(QString("batch merge fail for hashX %1, block height %2: %3")
                                        .arg(QString(hashX.toHex())).arg(ppb->height).arg(QString::fromStdString(st.ToString())));
            }
            if (auto st = p->db.shist->Write(p->db.defWriteOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("batch merge fail for block height %1: %2")
                                    .arg(ppb->height).arg(QString::fromStdString(st.ToString())));
            if constexpr (debugSh) {
                auto elapsed = Util::getTimeNS() - t0;
                Debug() << "Wrote " << ctr << " history entries in " << QString::number(elapsed/1e6, 'f', 3) << " msec";
            }
        }


        // save BlkInfo
        static const QString blkInfoErrMsg("Error writing BlkInfo to db");
        GenericDBPut(p->db.blkinfo.get(), uint32_t(ppb->height), BlkInfo{
                blockTxNum0, // .txNum0
                unsigned(ppb->txInfos.size()), // .nTx
            }, blkInfoErrMsg, p->db.defWriteOpts);

        /*
        if (nReserve) {
            if (const auto size = p->blkInfos.size(); size + nReserve < p->blkInfos.capacity())
                p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
        }

        p->blkInfos.emplace_back(BlkInfo{
            blockTxNum0, // .txNum0
            unsigned(ppb->txInfos.size()),
            unsigned(ppb->inputs.size()),
            unsigned(ppb->outputs.size())
        });
        */

        appendHeader(rawHeader, ppb->height);

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

    static const QString kErrMsg ("Error reading TxHash for TxNum %1: %2");
    QString errStr;
    const auto bytes = p->txNumsFile->readRecord(n, &errStr);
    if (bytes.isEmpty()) {
        errStr = kErrMsg.arg(n).arg(errStr);
        if (throwIfMissing)
            throw DatabaseError(errStr);
        Warning() << errStr;
    } else {
        ret.emplace(bytes);
    }
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

    // deep copy, raw bytes
    template <> QByteArray Serialize(const BlkInfo &b) { return QByteArray(reinterpret_cast<const char *>(&b), int(sizeof(b))); }
    template <> BlkInfo Deserialize(const QByteArray &ba, bool *ok) {
        BlkInfo ret;
        if (ba.length() != sizeof(ret)) {
            if (ok) *ok = false;
        } else {
            if (ok) *ok = true;
            ret = *reinterpret_cast<const BlkInfo *>(ba.constData());
        }
        return ret;
    }

    template <> QByteArray Serialize(const TxNumVec &v)
    {
        // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
        QByteArray ret(int(v.size()*6), Qt::Uninitialized);
        uint8_t *cur = reinterpret_cast<uint8_t *>(ret.data());
        for (const auto num : v) {
            cur[0] = (num >> 0) & 0xff;
            cur[1] = (num >> 8) & 0xff;
            cur[2] = (num >> 16) & 0xff;
            cur[3] = (num >> 24) & 0xff;
            cur[4] = (num >> 32) & 0xff;
            cur[5] = (num >> 40) & 0xff;
            cur += 6;
        }
        return ret;
    }
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize [[maybe_unused]] (const QByteArray &ba, bool *ok)
    {
        const size_t blen = size_t(ba.length());
        const size_t N = blen / 6;
        TxNumVec ret;
        if (N * 6 != blen) {
            // wrong size, not multiple of 6; bail
            if (ok) *ok = false;
            return ret;
        }
        if (ok) *ok = true;
        const uint8_t *cur = reinterpret_cast<const uint8_t *>(ba.begin()), *end = reinterpret_cast<const uint8_t *>(ba.end());
        ret.reserve(N);
        for ( ; cur < end; cur += 6) {
            ret.emplace_back(
                (TxNum(cur[0]) << 0)
              | (TxNum(cur[1]) << 8)
              | (TxNum(cur[2]) << 16)
              | (TxNum(cur[3]) << 24)
              | (TxNum(cur[4]) << 32)
              | (TxNum(cur[5]) << 40)
            );
        }
        return ret;
    }

}
