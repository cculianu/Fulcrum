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
#include <utility>
#include <vector>

DatabaseError::~DatabaseError(){} // weak vtable warning suppression
DatabaseSerializationError::~DatabaseSerializationError() {} // weak vtable warning suppression
DatabaseFormatError::~DatabaseFormatError() {} // weak vtable warning suppression
DatabaseKeyNotFound::~DatabaseKeyNotFound() {} // weak vtable warning suppression
HeaderVerificationFailure::~HeaderVerificationFailure() {} // weak vtable warning suppression
UndoInfoMissing::~UndoInfoMissing() {} // weak vtable warning suppression

namespace {
    /// Encapsulates the 'meta' db table
    struct Meta {
        uint32_t magic = 0xf33db33f, version = 0x1;
        QString chain; ///< "test", "main", etc
        uint16_t platformBits = sizeof(long)*8U; ///< we save the platform wordsize to the db
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

    /// Return a shallow, temporary copy of the memory of an object as a QByteArray. This reduces typing of
    /// the boilerplate: "QByteArray::FromRawData(reinterpret_cast...." etc everywhere in this file.
    /// Note: It is unsafe to use this function for anything other than obtaining a weak reference to the memory of an
    /// object as a QByteArray for temporary purposes. The original object must live at least as long as this returned
    /// QByteArray.  Note that even copy-constructing a new QByteArray from this returned QByteArray will lead to
    /// dangling pointers. See: https://doc.qt.io/qt-5/qbytearray.html#fromRawData.
    template <typename Object,
              std::enable_if_t<!std::is_pointer_v<std::remove_cv_t<Object>>, int> = 0>
    QByteArray ShallowTmp(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(mem), int(size));
    }

    /// Construct a QByteArray from a deep copy of any object's memory area. Slower than ShallowTmp above but 100% safe
    /// to use after the original object expires since the returned QByteArray takes ownership of its private copy of
    /// the memory it allocated.
    template <typename Object,
              std::enable_if_t<!std::is_pointer_v<std::remove_cv_t<Object>>, int> = 0>
    QByteArray DeepCpy(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray(reinterpret_cast<const char *>(mem), int(size));
    }

    /// Serialize a simple value such as an int directly, without using the space overhead that QDataStream imposes.
    /// This is less safe but is more compact since the bytes of the passed-in value are written directly to the
    /// returned QByteArray, without any encapsulation.  Note that use of this mechanism makes all data in the database
    /// no longer platform-neutral, which is ok. The presumption is users can re-synch their DB if switching
    /// architectures.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    [[maybe_unused]] QByteArray SerializeScalar (const Scalar & s) { return DeepCpy(&s); }
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalarNoCopy (const Scalar &s) { return ShallowTmp(&s);  }
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
    // TxNumVec
    using TxNumVec = std::vector<TxNum>;
    // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
    template <> QByteArray Serialize(const TxNumVec &);
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize(const QByteArray &, bool *);

    // CompactTXO -- not currently used since we prefer toBytes() directly (TODO: remove if we end up never using this)
    template <> QByteArray Serialize(const CompactTXO &);
    template <> CompactTXO Deserialize(const QByteArray &, bool *);


    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return ShallowTmp(s.data(), s.size()); }

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

    /// Helper to get db name (basename of path)
    QString DBName(const rocksdb::DB *db) { return QFileInfo(QString::fromStdString(db->GetName())).baseName(); }
    /// Helper to just get the status error string as a QString
    QString StatusString(const rocksdb::Status & status) { return QString::fromStdString(status.ToString()); }

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
                                      .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Key not found in db %1").arg(DBName(db)))
                                      .arg(StatusString(status)));
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error reading a key from db %1").arg(DBName(db)))
                                .arg(StatusString(status)));
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
                                              .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Database format error in db %1").arg(DBName(db))));
                }
                bool ok;
                ret.emplace( DeserializeScalar<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized as a scalar '%2'")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing a scalar from db %1").arg(DBName(db)))
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
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing an object from db %1").arg(DBName(db))));
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
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error writing to db %1").arg(DBName(db)))
                                .arg(StatusString(st)));
    }
    /// Throws on all errors. Otherwise enqueues a write to the batch.
    template <bool safeScalar = false, typename KeyType, typename ValueType>
    void GenericBatchPut
                (rocksdb::WriteBatch & batch, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Put(ToSlice<safeScalar>(key), ToSlice<safeScalar>(value));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Put")
                                .arg(StatusString(st)));
    }
    /// Throws on all errors. Otherwise enqueues a delete to the batch.
    template <bool safeScalar = false, typename KeyType>
    void GenericBatchDelete
                (rocksdb::WriteBatch & batch, const KeyType & key,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Delete(ToSlice<safeScalar>(key));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Delete")
                                .arg(StatusString(st)));
    }
    /// A convenient wrapper to db->Write(batch...) which throws on all errors.
    void GenericBatchWrite(rocksdb::DB *db, rocksdb::WriteBatch & batch,
                        const QString & errorMsgPrefix = QString(),
                        const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Write(opts, &batch);
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error writing batch to db %1").arg(DBName(db)))
                                .arg(StatusString(st)));
    }
    /// Throws on all errors. Otherwise deletes a key from db. It is not an error to delete a non-existing key.
    template <bool safeScalar = false, typename KeyType>
    void GenericDBDelete
                (rocksdb::DB *db, const KeyType & key,
                 const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                 const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Delete(opts, ToSlice<safeScalar>(key));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deleting a key from db %1").arg(DBName(db)))
                                .arg(StatusString(st)));
    }

    //// A helper data structs -- written to the blkinfo table. This helps localize a txnum to a specific position in
    /// a block.  The table is keyed off of block_height(uint32_t) -> serialized BlkInfo (raw bytes)
    struct BlkInfo {
        TxNum txNum0 = 0;
        unsigned nTx = 0;
        BlkInfo() = default;
        BlkInfo(const BlkInfo &) = default;
        [[maybe_unused]] BlkInfo (TxNum txn, unsigned ntx) : txNum0(txn), nTx(ntx) {}
        bool operator==(const BlkInfo &o) const { return txNum0 == o.txNum0 && nTx == o.nTx; }
        bool operator!=(const BlkInfo &o) const { return !(*this == o); }
        [[maybe_unused]] bool operator<(const BlkInfo &o) const { return txNum0 == o.txNum0 ? nTx < o.nTx : txNum0 < o.txNum0; }
        BlkInfo &operator=(const BlkInfo &) = default;
    };
    // serializes as raw bytes from struct
    template <> QByteArray Serialize(const BlkInfo &);
    // deserializes as raw bytes from struct
    template <> BlkInfo Deserialize(const QByteArray &, bool *);

    /// Block rewind/undo information. One of these is kept around in the db for the last 10 blocks.
    /// It basically stores a record of all the UTXO's added and removed, as well as the set of
    /// scripthashes.
    struct UndoInfo {
        using ScriptHashSet = std::unordered_set<HashX, HashHasher>;
        using UTXOAddUndo = std::tuple<TXO, HashX, CompactTXO>;
        using UTXODelUndo = std::tuple<TXO, TXOInfo>;

        BlockHeight height = 0; ///< we save a copy of this infomation as a sanity check
        BlockHash hash; ///< we save a copy of this information as a sanity check. (bytes are in "reversed", bitcoind ToHex()-style memory order)
        BlkInfo blkInfo; ///< we save a copy of this from the global value for convenience and as a sanity check.

        // below is the actual critical undo information
        ScriptHashSet scriptHashes;
        std::vector<UTXOAddUndo> addUndos;
        std::vector<UTXODelUndo> delUndos;

        [[maybe_unused]] QString toDebugString() const;

        [[maybe_unused]] bool operator==(const UndoInfo &) const; // for debug ser/deser

        bool isValid() const { return hash.size() == HashLen; } ///< cheap, imperfect check for validity
        void clear() { height = 0; hash.clear(); blkInfo = BlkInfo(); scriptHashes.clear(); addUndos.clear(); delUndos.clear(); }
    };

    QString UndoInfo::toDebugString() const {
        QString ret;
        QTextStream ts(&ret);
        ts  << "<Undo info for height: " << height << " addUndos: " << addUndos.size() << " delUndos: " << delUndos.size()
            << " scriptHashes: " << scriptHashes.size() << " nTx: " << blkInfo.nTx << " txNum0: " << blkInfo.txNum0
            << " hash: " << hash.toHex() << ">";
        return ret;
    }

    bool UndoInfo::operator==(const UndoInfo &o) const {
        return height == o.height && hash == o.hash && blkInfo == o.blkInfo && scriptHashes == o.scriptHashes
                && addUndos == o.addUndos && delUndos == o.delUndos;
    }

    // serialize as raw bytes mostly (no QDataStream)
    template <> QByteArray Serialize(const UndoInfo &);
    // serialize from raw bytes mostly (no QDataStream)
    template <> UndoInfo Deserialize(const QByteArray &, bool *);


    /// Associative merge operator used for scripthash history concatenation
    /// TODO: this needs to be made more efficient by implementing the real MergeOperator interface and combining
    /// appends efficiently to reduce allocations.  Right now it's called for each append.
    class ConcatOperator : public rocksdb::AssociativeMergeOperator {
    public:
        ~ConcatOperator() override;

        mutable std::atomic<unsigned> merges = 0;

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

}


struct Storage::Pvt
{
    /* NOTE: If taking multiple locks, all locks should be taken in the order they are declared, to avoid deadlocks. */

    const int blockHeaderSize = BTC::GetBlockHeaderSize();

    Meta meta;
    Lock metaLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBs {
        const rocksdb::ReadOptions defReadOpts; ///< avoid creating this each time
        const rocksdb::WriteOptions defWriteOpts; ///< avoid creating this each time

        rocksdb::Options opts, shistOpts;

        std::shared_ptr<ConcatOperator> concatOperator;

        std::unique_ptr<rocksdb::DB> meta, headers, blkinfo, utxoset,
                                     shist, shunspent, // scripthash_history and scripthash_unspent
                                     undo; // undo (reorg rewind)
    } db;

    std::unique_ptr<RecordFile> txNumsFile;

    /// Big lock used for block/history updates. Public methods that read the history such as getHistory and listUnspent
    /// take this as read-only (shared), and addBlock and undoLatestBlock take this as read/write (exclusively).
    /// This is intended to be a coarse lock.  Currently the update code takes this along with headerVerifierLock and
    /// blkInfoLock at the same time, so it's (as of now) equivalent to either of those two locks.
    /// TODO: See about removing all the other locks and keeping one general RWLock for all updates?
    mutable RWLock blocksLock;

    BTC::HeaderVerifier headerVerifier;
    mutable RWLock headerVerifierLock;

    std::atomic<TxNum> txNumNext{0};

    std::vector<BlkInfo> blkInfos;
    std::map<TxNum, unsigned> blkInfosByTxNum; ///< ordered map of TxNum0 for a block -> index into above blkInfo array
    RWLock blkInfoLock; ///< locks blkInfos and blkInfosByTxNum

    std::atomic<int64_t> utxoCt = 0;

    std::atomic<uint32_t> earliestUndoHeight = UINT32_MAX; ///< the purpose of this is to control when we issue "delete" commands to the db for deleting expired undo infos from the undo db

    /// TODO: Tune the cahce size. With the below settings it is approx. 50MB-60MB when totally filled
    /// (each entry is ~40 bytes + overhead).  This cache is anticipated to see heavy use for get_history, so we may
    /// wish to make it larger.
    static constexpr size_t nCacheMax = 1000000, nCacheElasticity = 250000;
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
        shistOpts.merge_operator = p->db.concatOperator = std::make_shared<ConcatOperator>(); // this set of options uses the concat merge operator (we use this to append to history entries in the db)

        using DBInfoTup = std::tuple<QString, std::unique_ptr<rocksdb::DB> &, const rocksdb::Options &>;
        const std::list<DBInfoTup> dbs2open = {
            { "meta", p->db.meta, opts },
            { "headers", p->db.headers, opts },
            { "blkinfo" , p->db.blkinfo , opts },
            { "utxoset", p->db.utxoset, opts },
            { "scripthash_history", p->db.shist, shistOpts },
            { "scripthash_unspent", p->db.shunspent, opts },
            { "undo", p->db.undo, opts },
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
                                    .arg(name).arg(StatusString(s)).arg(path));
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
            if (m_db.magic != p->meta.magic || m_db.version != p->meta.version || m_db.platformBits != p->meta.platformBits) {
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
    // check txnums
    loadCheckTxNumsFileAndBlkInfo();
    // count utxos -- note this depends on "blkInfos" being filled in so it much be called after loadCheckTxNumsFileAndBlkInfo()
    loadCheckUTXOsInDB();
    // load check earliest undo to populate earliestUndoHeight
    loadCheckEarliestUndo();

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
    QVariantMap ret;
    auto & c = p->db.concatOperator;
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

auto Storage::latestTip(Header *hdrOut) const -> std::pair<int, HeaderHash> {
    std::pair<int, HeaderHash> ret = headerVerifier().first.lastHeaderProcessed(); // ok; lock stays locked until statement end.
    if (hdrOut) *hdrOut = ret.second; // this is not a hash but the actual block header
    if (ret.second.isEmpty() || ret.first < 0) {
        ret.first = -1;
        ret.second.clear();
        if (hdrOut) hdrOut->clear();
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

void Storage::appendHeader(const Header &h, BlockHeight height)
{
    const auto targetHeight = GenericDBGet<uint32_t, true>(p->db.headers.get(), kNumHeaders, true, // missing ok
                                                           "Error reading header count from database").value_or(0);
    if (UNLIKELY(height != targetHeight))
        throw InternalError(QString("Bad use of appendHeader -- expected height %1, got height %2").arg(targetHeight).arg(height));
    rocksdb::WriteBatch batch;
    if (auto stat = batch.Put(ToSlice(uint32_t(height)), ToSlice(h)); !stat.ok())
        throw DatabaseError(QString("Error writing header %1: %2").arg(height).arg(StatusString(stat)));
    if (auto stat = batch.Put(kNumHeaders, ToSlice<true>(uint32_t(height+1))); !stat.ok())
        throw DatabaseError(QString("Error writing header size key: %1").arg(StatusString(stat)));
    if (auto stat = p->db.headers->Write(p->db.defWriteOpts, &batch); !stat.ok())
        throw DatabaseError(QString("Error writing header %1: %2").arg(height).arg(StatusString(stat)));
}

void Storage::deleteHeadersPastHeight(BlockHeight height)
{
    auto numHdrs = GenericDBGetFailIfMissing<uint32_t, true>(p->db.headers.get(), kNumHeaders, "Error reading header count from database");
    rocksdb::WriteBatch batch;
    while (--numHdrs > height) {
        if (auto stat = batch.Delete(ToSlice(uint32_t(numHdrs))); !stat.ok())
            throw DatabaseError(QString("batch.Delete failed for %1 when deleting headers to height %2: %3")
                                .arg(numHdrs).arg(height).arg(StatusString(stat)));
    }
    numHdrs = height + 1;
    if (auto stat = batch.Put(kNumHeaders, ToSlice<true>(uint32_t(numHdrs))); !stat.ok())
        throw DatabaseError(QString("batch.Put failed when for numHdrs %1: %2").arg(numHdrs).arg(StatusString(stat)));
    if (auto stat = p->db.headers->Write(p->db.defWriteOpts, &batch); !stat.ok())
        throw DatabaseError(QString("Write failed when deleting headers to height %1: %2").arg(height).arg(StatusString(stat)));
}

auto Storage::headerForHeight(BlockHeight height, QString *err) -> std::optional<Header>
{
    std::optional<Header> ret;
    if (int(height) <= latestTip().first && int(height) >= 0) {
        ret = headerForHeight_nolock(height, err);
    } else if (err) { *err = QString("Height %1 is out of range").arg(height); }
    return ret;
}

auto Storage::headerForHeight_nolock(BlockHeight height, QString *err) -> std::optional<Header>
{
    std::optional<Header> ret;
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
    return ret;
}

/// Convenient batched alias for above. Returns a set of headers starting at height. May return < count if not
/// all headers were found. Thead safe.
auto Storage::headersFromHeight(BlockHeight height, unsigned count, QString *err) -> std::vector<Header>
{
    std::vector<Header> ret;
    SharedLockGuard g(p->blocksLock); // to ensure clients get a consistent view
    int num = std::min(1 + latestTip().first - int(height), int(count)); // note this also takes a lock briefly so we need to do this after the lockguard above
    if (num > 0) {
        if (err) *err = "";
        ret.reserve(unsigned(num));
        for (int i = 0; i < num; ++i) {
            auto opt = headerForHeight_nolock(height + unsigned(i), err);
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

void Storage::loadCheckTxNumsFileAndBlkInfo()
{
    // may throw.
    p->txNumsFile = std::make_unique<RecordFile>(options->datadir + QDir::separator() + "txnum2txhash", HashLen, 0x000012e2);
    p->txNumNext = p->txNumsFile->numRecords();
    Debug() << "Read TxNumNext from file: " << p->txNumNext.load();
    TxNum ct = 0;
    if (const int height = latestTip().first; height >= 0)
    {
        p->blkInfos.reserve(std::min(size_t(height+1), MAX_HEADERS));
        Log() << "Checking tx counts ...";
        for (int i = 0; i <= height; ++i) {
            static const QString errMsg("Failed to read a blkInfo from db, the database may be corrupted");
            const auto blkInfo = GenericDBGetFailIfMissing<BlkInfo>(p->db.blkinfo.get(), uint32_t(i), errMsg, false, p->db.defReadOpts);
            if (blkInfo.txNum0 != ct)
                throw DatabaseFormatError(QString("BlkInfo for height %1 does not match computed txNum of %2."
                                                  "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                          .arg(i).arg(ct));
            ct += blkInfo.nTx;
            p->blkInfos.emplace_back(blkInfo);
            p->blkInfosByTxNum[blkInfo.txNum0] = unsigned(p->blkInfos.size()-1);
        }
        Log() << ct << " total transactions";
    }
    if (ct != p->txNumNext) {
        throw DatabaseFormatError(QString("BlkInfo txNums do not add up to expected value of %1 != %2."
                                          "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                  .arg(ct).arg(p->txNumNext.load()));
    }
}

// NOTE: this must be called *after* loadCheckTxNumsFileAndBlkInfo(), because it needs a valid p->txNumNext
void Storage::loadCheckUTXOsInDB()
{
    FatalAssert(!!p->db.utxoset) << __FUNCTION__ << ": Utxo set db is not open";

    Log() << "Verifying utxo set ...";

    const auto t0 = Util::getTimeNS();
    {
        const int currentHeight = latestTip().first;

        std::unique_ptr<rocksdb::Iterator> iter(p->db.utxoset->NewIterator(p->db.defReadOpts));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the utxo set db");
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
            // uncomment this to do a deep test: TODO: Make this configurable from the CLI -- this last check is very slow.
            //const CompactTXO ctxo = CompactTXO(info.txNum, txo.prevoutN);
            //const QByteArray shuKey = info.hashX + ctxo.toBytes();
            //static const QString errPrefix("Error reading scripthash_unspent");
            if (bool fail1 = false, fail2 = false/*, fail3 = false*/;
                    (fail1 = (info.confirmedHeight.has_value() && int(info.confirmedHeight.value()) > currentHeight))
                    || (fail2 = info.txNum >= p->txNumNext)
                    /*|| (fail3 = !GenericDBGet<QByteArray>(p->db.shunspent.get(), shuKey, true, errPrefix, false, p->db.defReadOpts).has_value())*/) {
                // TODO: reorg? Inconsisent db?  FIXME
                QString msg;
                {
                    QTextStream ts(&msg);
                    ts << "Inconsistent database: txo " << txo.toString() << " at height: "
                       << info.confirmedHeight.value();
                    if (fail1) {
                        ts << " > current height: " << currentHeight << ".";
                    } else if (fail2) {
                        ts << ". TxNum: " << info.txNum << " >= " << p->txNumNext << ".";
                    } /*else if (fail3) {
                        ts << ". Failed to find ctxo " << ctxo.toString() << " in scripthash_unspent db.";
                    }*/
                    ts << "\n\nThe database has been corrupted. Please delete the datadir and resynch to bitcoind.\n";
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

void Storage::loadCheckEarliestUndo()
{
    FatalAssert(!!p->db.undo) << __FUNCTION__ << ": Undo db is not open";

    const auto t0 = Util::getTimeNS();
    int ctr = 0;
    {
        std::unique_ptr<rocksdb::Iterator> iter(p->db.undo->NewIterator(p->db.defReadOpts));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the undo db");
        for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
            const auto keySlice = iter->key();
            if (keySlice.size() != sizeof(uint32_t))
                throw DatabaseFormatError("Unexpected key in undo database. We expect only 32-bit unsigned ints!");
            const uint32_t height = DeserializeScalar<uint32_t>(FromSlice(keySlice));
            if (height < p->earliestUndoHeight) p->earliestUndoHeight = height;
            ++ctr;
        }
    }
    if (ctr) {
        Debug() << "Undo db contains " << ctr << " entries, earliest is " << p->earliestUndoHeight.load() << ", "
                << QString::number((Util::getTimeNS() - t0)/1e6, 'f', 2) << " msec elapsed.";
    }
}

struct Storage::UTXOBatch::P {
    rocksdb::WriteBatch utxosetBatch; ///< batch writes/deletes end up in the utxoset db (keyed off TXO)
    rocksdb::WriteBatch shunspentBatch; ///< batch writes/deletes end up in the shunspent db (keyed off HashX+CompactTXO)
    int addCt = 0, rmCt = 0;
    bool defunct = false;
};

Storage::UTXOBatch::UTXOBatch() : p(new P) {}
Storage::UTXOBatch::UTXOBatch(UTXOBatch &&o) { p.swap(o.p); }

void Storage::issueUpdates(UTXOBatch &b)
{
    static const QString errMsg1("Error issuing batch write to utxoset db for a utxo update"),
                         errMsg2("Error issuing batch write to scripthash_unspent db for a utxo update");
    if (UNLIKELY(b.p->defunct))
        throw InternalError("Misuse of Storage::issueUpdates. Cannot issue the same updates using the same context more than once. FIXME!");
    assert(bool(p->db.utxoset) && bool(p->db.shunspent));
    GenericBatchWrite(p->db.utxoset.get(), b.p->utxosetBatch, errMsg1, p->db.defWriteOpts); // may throw
    GenericBatchWrite(p->db.shunspent.get(), b.p->shunspentBatch, errMsg2, p->db.defWriteOpts); // may throw
    p->utxoCt += b.p->addCt - b.p->rmCt; // tally up adds and deletes
    b.p->defunct = true;
}

namespace {
    inline QByteArray mkShunspentKey(const QByteArray & hashX, const CompactTXO &ctxo) {
        // we do it this way for performance:
        const int hxlen = hashX.length();
        assert(hxLen == HashLen);
        QByteArray key(hxlen + int(ctxo.serSize()), Qt::Uninitialized);
        std::memcpy(key.data(), hashX.constData(), size_t(hxlen));
        ctxo.toBytesInPlace(key.data()+hxlen, ctxo.serSize());
        return key;
    }
}

void Storage::UTXOBatch::add(const TXO &txo, const TXOInfo &info, const CompactTXO &ctxo)
{
    {
        // Update db utxoset, keyed off txo -> txoinfo
        static const QString errMsgPrefix("Failed to add a utxo to the utxo batch");
        GenericBatchPut(p->utxosetBatch, txo, info, errMsgPrefix); // may throw on failure
    }

    {
        // Update the scripthash unspent. This is a very simple table which we scan by hashX prefix using
        // an iterator in listUnspent.  Each entry's key is prefixed with the HashX bytes (32) but suffixed with the
        // serialized CompactTXO bytes (8). Each entry's data is a 8-byte int64_t of the amount of the utxo to save
        // on lookup cost for getBalance().
        static const QString errMsgPrefix("Failed to add an entry to the scripthash_unspent batch");

        GenericBatchPut(p->shunspentBatch, mkShunspentKey(info.hashX, ctxo), int64_t(info.amount / info.amount.satoshi()),
                        errMsgPrefix); // may throw, which is what we want
    }
    ++p->addCt;
}

void Storage::UTXOBatch::remove(const TXO &txo, const HashX &hashX, const CompactTXO &ctxo)
{
    {
        // enqueue delete from utxoset db -- may throw.
        static const QString errMsgPrefix("Failed to issue a batch delete for a utxo");
        GenericBatchDelete(p->utxosetBatch, txo, errMsgPrefix);
    }
    {
        // enqueue delete from scripthash_unspent db
        static const QString errMsgPrefix("Failed to issue a batch delete for a utxo to the scripthash_unspent db");
        GenericBatchDelete(p->shunspentBatch, mkShunspentKey(hashX, ctxo), errMsgPrefix);
    }
    ++p->rmCt;
}

/// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
std::optional<TXOInfo> Storage::utxoGetFromDB(const TXO &txo, bool throwIfMissing)
{
    assert(bool(p->db.utxoset));
    static const QString errMsgPrefix("Failed to read a utxo from the utxo db");
    return GenericDBGet<TXOInfo>(p->db.utxoset.get(), txo, !throwIfMissing, errMsgPrefix, false, p->db.defReadOpts);
}

int64_t Storage::utxoSetSize() const { return p->utxoCt; }
double Storage::utxoSetSizeMiB() const {
    constexpr int64_t elemSize = TXO::serSize() + TXOInfo::serSize();
    return (utxoSetSize()*elemSize) / 1e6;
}

void Storage::addBlock(PreProcessedBlockPtr ppb, bool saveUndo, unsigned nReserve)
{
    assert(bool(ppb) && bool(p));

    std::unique_ptr<UndoInfo> undo;

    if (saveUndo) {
        undo.reset(new UndoInfo);
        undo->height = ppb->height;
    }

    // take all locks now.. since this is a Big Deal. TODO: add more locks here?
    std::scoped_lock guard(p->blocksLock, p->headerVerifierLock, p->blkInfoLock);

    const auto verifUndo = p->headerVerifier; // keep a copy of verifier state for undo purposes in case this fails
    // This object ensures that if an exception is thrown while we are in the below code, we undo the header verifier
    // and return it to its previous state.  Note the defer'd functor is called with the above scoped_lock held.
    Defer undoVerifierOnScopeEnd([&verifUndo, this] { p->headerVerifier = verifUndo; });

    // code in the below block may throw -- exceptions are propagated out to caller.
    {
        const auto blockTxNum0 = p->txNumNext.load();

        // Verify header chain makes sense (by checking hashes, using the shared header verifier)
        QByteArray rawHeader;
        {
            QString errMsg;
            if (!p->headerVerifier(ppb->header, &errMsg) ) {
                // XXX possible reorg point. Caller will/should roll back the db state via issuing calls to undoLatestBlock()
                throw HeaderVerificationFailure(errMsg);
            }
            // save raw header back to our buffer -- this will be used at the end of this function to add it to the db
            // after everything completes successfully.
            rawHeader = p->headerVerifier.lastHeaderProcessed().second;
        }

        {  // add txnum -> txhash association to the TxNumsFile...
            auto batch = p->txNumsFile->beginBatchAppend(); // may throw if io error in c'tor here.
            QString errStr;
            for (const auto & txInfo : ppb->txInfos) {
                if (!batch.append(txInfo.hash, &errStr)) // does not throw here, but we do.
                    throw InternalError(QString("Batch append for txNums failed: %1.").arg(errStr));
            }
            // <-- The batch d'tor may close the app on error here with Fatal() if a low-level file error occurs now
            //     on header update (see: RecordFile.cpp, ~BatchAppendContext()).
        }

        p->txNumNext += ppb->txInfos.size(); // update internal counter

        if (p->txNumNext != p->txNumsFile->numRecords())
            throw InternalError("TxNum file and internal txNumNext counter disagree! FIXME!");


        constexpr bool debugPrt = false;

        // update utxoSet & scritphash history
        {
            std::unordered_set<HashX, HashHasher> newHashXInputsResolved;

            {
                // utxo batch block (updtes utxoset & scripthash_unspent tables)
                UTXOBatch utxoBatch;

                // reserve space in undo, if in saveUndo mode
                if (undo) {
                    undo->addUndos.reserve(ppb->outputs.size());
                    undo->delUndos.reserve(ppb->inputs.size());
                }

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
                        info.txNum = blockTxNum0 + out.txIdx;
                        const TXO txo{ hash, out.outN };
                        const CompactTXO ctxo(info.txNum, txo.prevoutN);
                        utxoBatch.add(txo, info, ctxo); // add to db
                        if (undo) { // save undo info if we are in saveUndo mode
                            undo->addUndos.emplace_back(txo, info.hashX, ctxo);
                        }
                        if constexpr (debugPrt)
                            Debug() << "Added txo: " << txo.toString()
                                    << " (txid: " << hash.toHex() << " height: " << ppb->height << ") "
                                    << " amount: " << info.amount.ToString() << " for HashX: " << info.hashX.toHex();
                    }
                }

                // add spends (process inputs)
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
                            // was a prevout from a previos block.. so the ppb didn't have it in the 'involving hashx' set..
                            // mark the spend as having involved this hashX for this ppb now.
                            auto & ag = ppb->hashXAggregated[info.hashX];
                            ag.ins.emplace_back(inum);
                            newHashXInputsResolved.insert(info.hashX);
                            // mark its txidx
                            if (auto & vec = ag.txNumsInvolvingHashX; vec.empty() || vec.back() != in.txIdx)
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
                        utxoBatch.remove(txo, info.hashX, CompactTXO(info.txNum, txo.prevoutN)); // delete from db
                        if (undo) { // save undo info, if we are in saveUndo mode
                            undo->delUndos.emplace_back(txo, info);
                        }
                    } else {
                        QString s;
                        {
                            const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                            QTextStream ts(&s);
                            ts << "Failed to spend: " << in.prevoutHash.toHex() << ":" << in.prevoutN << " (spending txid: " << dbgTxIdHex << ")";
                        }
                        throw InternalError(s);
                    }
                    ++inum;
                }

                // commit the utxoset updates now.. this issues the writes to the db and also updates
                // p->utxoCt. This may throw.
                issueUpdates(utxoBatch);
            }

            // sort and shrink_to_fit new hashX inputs added
            for (const auto & hashX : newHashXInputsResolved) {
                auto & ag = ppb->hashXAggregated[hashX];
                std::sort(ag.ins.begin(), ag.ins.end()); // make sure they are sorted
                std::sort(ag.txNumsInvolvingHashX.begin(), ag.txNumsInvolvingHashX.end());
                auto last = std::unique(ag.txNumsInvolvingHashX.begin(), ag.txNumsInvolvingHashX.end());
                ag.txNumsInvolvingHashX.erase(last, ag.txNumsInvolvingHashX.end());
                ag.ins.shrink_to_fit();
                ag.txNumsInvolvingHashX.shrink_to_fit();
            }

            if constexpr (debugPrt)
                Debug() << "utxoset size: " << utxoSetSize() << " block: " << ppb->height;
        }

        {
            // now.. update the txNumsInvolvingHashX to be offset from txNum0 for this block, and save history to db table
            // history is hashX -> TxNumVec (serialized) as a serities of 6-bytes txNums in blockchain order as they appeared.
            rocksdb::WriteBatch batch;
            for (auto & [hashX, ag] : ppb->hashXAggregated) {
                for (auto & txNum : ag.txNumsInvolvingHashX) {
                    txNum += blockTxNum0; // transform local txIdx to -> txNum (global mapping)
                }
                // save scripthash history for this hashX, by appending to existing history. Note that this uses
                // the 'ConcatOperator' class we defined in this file, which requires rocksdb be compiled with RTTI.
                if (auto st = batch.Merge(ToSlice(hashX), ToSlice(Serialize(ag.txNumsInvolvingHashX))); !st.ok())
                    throw DatabaseError(QString("batch merge fail for hashX %1, block height %2: %3")
                                        .arg(QString(hashX.toHex())).arg(ppb->height).arg(StatusString(st)));
            }
            if (auto st = p->db.shist->Write(p->db.defWriteOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("batch merge fail for block height %1: %2")
                                    .arg(ppb->height).arg(StatusString(st)));
        }


        {
            // update BlkInfo
            if (nReserve) {
                if (const auto size = p->blkInfos.size(); size + 1 > p->blkInfos.capacity())
                    p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
            }

            p->blkInfos.emplace_back(
                blockTxNum0, // .txNum0
                unsigned(ppb->txInfos.size())
            );

            const auto & blkInfo = p->blkInfos.back();

            p->blkInfosByTxNum[blkInfo.txNum0] = unsigned(p->blkInfos.size()-1);

            // save BlkInfo to db
            static const QString blkInfoErrMsg("Error writing BlkInfo to db");
            GenericDBPut(p->db.blkinfo.get(), uint32_t(ppb->height), blkInfo, blkInfoErrMsg, p->db.defWriteOpts);

            if (undo) {
                // save blkInfo to undo information, if in saveUndo mode
                undo->blkInfo = p->blkInfos.back();
            }
        }

        // save the last of the undo info, if in saveUndo mode
        if (undo) {
            const auto t0 = Util::getTimeNS();
            undo->hash = BTC::HashRev(rawHeader);
            undo->scriptHashes = Util::keySet<decltype (undo->scriptHashes)>(ppb->hashXAggregated);
            static const QString errPrefix("Error saving undo info to undo db");

            GenericDBPut(p->db.undo.get(), uint32_t(ppb->height), *undo, errPrefix, p->db.defWriteOpts); // save undo to db
            if (ppb->height < p->earliestUndoHeight) {
                // remember earliest for delete clause below...
                p->earliestUndoHeight = ppb->height;
            }

            if constexpr (debugPrt) {
                // testing undo ser/deser
                Debug() << "Undo info 1: " << undo->toDebugString();
                QByteArray ba = Serialize(*undo);
                Debug() << "Undo info 1 serSize: " << ba.length();
                bool ok;
                auto undo2 = Deserialize<UndoInfo>(ba, &ok);
                ba.fill('z'); // ensure no shallow copies of buffer exist in deserialized object. if they do below tests will fail
                FatalAssert(ok && undo2.isValid()) << "Deser of undo info failed!";
                Debug() << "Undo info 2: " << undo2.toDebugString();
                Debug() << "Undo info 1 == undo info 2: " << (*undo == undo2);
            } else {
                const auto elapsedms = (Util::getTimeNS() - t0)/1e6;
                const size_t nTx = undo->blkInfo.nTx, nSH = undo->scriptHashes.size();
                Debug() << "Saved undo for block " << undo->height << ", "
                        << nTx << " " << Util::Pluralize("transaction", nTx)
                        << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
                        << ", in " << QString::number(elapsedms, 'f', 2) << " msec.";
            }
        }
        // Expire old undos >10 blocks ago to keep the db tidy.  We only do this if we know there is an old
        // undo for said height in db.
        if (const auto expireUndoHeight = int(ppb->height) - int(BTC::maxReorgDepth);
                expireUndoHeight >= 0 && unsigned(expireUndoHeight) >= p->earliestUndoHeight) {
            // FIXME -- this runs for every block in between the last undo save and current tip.
            // If the node was off for a while then restarted this just hits the db with useless deletes for non-existant
            // keys as we catch up.  It's not the end of the world, as each call here is on the order of microseconds..
            // but perhaps we need to see about fixing this to not do that.
            static const QString errPrefix("Error deleting old/stale undo info from undo db");
            GenericDBDelete(p->db.undo.get(), uint32_t(expireUndoHeight), errPrefix, p->db.defWriteOpts);
            p->earliestUndoHeight = unsigned(expireUndoHeight + 1);
            if constexpr (debugPrt) Debug() << "Deleted undo for block " << expireUndoHeight << ", earliest now " << p->earliestUndoHeight.load();
        }

        appendHeader(rawHeader, ppb->height);

        undoVerifierOnScopeEnd.disable(); // indicate to the "Defer" object declared at the top of this function that it shouldn't undo anything anymore as we are happy now with the db state now.
    }
}

BlockHeight Storage::undoLatestBlock()
{
    // take all locks now.. since this is a Big Deal. TODO: add more locks here?
    std::scoped_lock guard(p->blocksLock, p->headerVerifierLock, p->blkInfoLock);

    const auto t0 = Util::getTimeNS();

    const auto [tip, header] = p->headerVerifier.lastHeaderProcessed();
    if (tip <= 0 || header.length() != p->blockHeaderSize) throw UndoInfoMissing("No header to undo");
    const BlockHeight prevHeight = unsigned(tip-1);
    Header prevHeader;
    {
        // grab previous header now
        QString err;
        auto opt = headerForHeight_nolock(prevHeight, &err);
        if (!opt.has_value()) throw UndoInfoMissing(err);
        prevHeader = opt.value();
    }
    const QString errMsg1 = QString("Unable to retrieve undo info for %1").arg(tip);
    const auto undoOpt = GenericDBGet<UndoInfo>(p->db.undo.get(), uint32_t(tip), true, errMsg1, false, p->db.defReadOpts);
    if (!undoOpt.has_value())
        throw UndoInfoMissing(errMsg1);
    const auto & undo = undoOpt.value();

    // ensure undo info sanity
    if (!undo.isValid() || undo.height != unsigned(tip) || undo.hash != BTC::HashRev(header)
        || prevHeight+1 >= p->blkInfos.size() || p->blkInfos.empty() || p->blkInfos.back() != undo.blkInfo)
        throw DatabaseFormatError(QString("The undo information for height %1 was successfully retrieved from the "
                                          "database, but it failed an internal consistency check.").arg(tip));
    {
        // all sanity check passed. Now, undo things in reverse order of what we did in addBlock above, rougly speaking

        // first, undo the header
        p->headerVerifier.reset(prevHeight+1, prevHeader);
        deleteHeadersPastHeight(prevHeight); // commit change to db

        // undo the blkInfo from the back
        p->blkInfos.pop_back();
        p->blkInfosByTxNum.erase(undo.blkInfo.txNum0);
        GenericDBDelete(p->db.blkinfo.get(), uint32_t(undo.height), "Failed to delete blkInfo in undoLatestBlock");
        // clear num2hash cache
        p->lruNum2Hash.clear();

        const auto txNum0 = undo.blkInfo.txNum0;

        // undo the scripthash histories
        for (const auto & sh : undo.scriptHashes) {
            const QString shHex = Util::ToHexFast(sh);
            const auto vec = GenericDBGetFailIfMissing<TxNumVec>(p->db.shist.get(), sh, QString("Undo failed because we failed to retrieve the scripthash history for %1").arg(shHex), false, p->db.defReadOpts);
            TxNumVec newVec;
            newVec.reserve(vec.size());
            for (const auto txNum : vec) {
                if (txNum < txNum0) {
                    // accept only stuff in history that's before txNum0 for this block, filter out everything else
                    newVec.push_back(txNum);
                }
            }
            const QString errMsg = QString("Undo failed because we failed to write the new scripthash history for %1").arg(shHex);
            if (!newVec.empty()) {
                // The below is entirely unnecessary as the txnums should be already sorted and unique in the db data.
                // We are doing this here to illustrate that this invariant in the data is very important.
                // Block undo is intended to be an infrequent process (and thus not especially performance-critical),
                // so this does no harm.
                std::sort(newVec.begin(), newVec.end());
                auto last = std::unique(newVec.begin(), newVec.end());
                newVec.erase(last, newVec.end());
            }
            if (!newVec.empty()) {
                // the sh still has some history, write it to db
                GenericDBPut(p->db.shist.get(), sh, newVec, errMsg, p->db.defWriteOpts);
            } else {
                // the sh in question lost all its history as a result of undo, just delete it from db to save space
                GenericDBDelete(p->db.shist.get(), sh, errMsg, p->db.defWriteOpts);
            }
        }

        {
            // UTXO set update
            UTXOBatch utxoBatch;

            // now, undo the utxo deletions by re-adding them
            for (const auto & [txo, info] : undo.delUndos) {
                // note that deletions may have an info with a txnum before this block, for obvious reasons
                utxoBatch.add(txo, info, CompactTXO(info.txNum, txo.prevoutN)); // may throw
            }

            // now, undo the utxo additions by deleting them
            for (const auto & [txo, hashx, ctxo] : undo.addUndos) {
                assert(ctxo.txNum() >= txNum0); // all of the additions must have been in this block or newer
                utxoBatch.remove(txo, hashx, ctxo); // may throw
            }

            issueUpdates(utxoBatch); // may throw, updates p->utxoCt and issues write to db.
        }

        if (p->earliestUndoHeight >= undo.height)
            // oops, we're out of undos now!
            p->earliestUndoHeight = UINT_MAX;
        GenericDBDelete(p->db.undo.get(), uint32_t(undo.height)); // make sure to delete this undo info since it was just applied.

        // lastly, truncate the tx num file and re-set txNumNext to point to this block's txNum0 (thereby recycling it)
        assert(long(p->txNumNext) - long(txNum0) == long(undo.blkInfo.nTx));
        p->txNumNext = txNum0;
        if (QString err; p->txNumsFile->truncate(txNum0, &err) != txNum0 || !err.isEmpty()) {
            throw InternalError(QString("Failed to truncate txNumsFile to %1: %2").arg(txNum0).arg(err));
        }
    }

    const size_t nTx = undo.blkInfo.nTx, nSH = undo.scriptHashes.size();
    const auto elapsedms = (Util::getTimeNS() - t0) / 1e6;
    Log() << "Applied undo for block " << undo.height << ", " << nTx << " " << Util::Pluralize("transaction", nTx)
          << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
          << ", in " << QString::number(elapsedms, 'f', 2) << " msec, new height now: " << prevHeight;

    return prevHeight;
}

std::optional<TxHash> Storage::hashForTxNum(TxNum n, bool throwIfMissing, bool *wasCached, bool skipCache) const
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

std::optional<unsigned> Storage::heightForTxNum(TxNum n) const
{
    SharedLockGuard g(p->blkInfoLock);
    std::optional<unsigned> ret;
    auto it = p->blkInfosByTxNum.upper_bound(n);  // O(logN) search; find the block *AFTER* n, then go backw on to find the block in range
    if (it != p->blkInfosByTxNum.begin()) {
        --it;
        const auto & bi = p->blkInfos[it->second];
        if (n >= bi.txNum0 && n < bi.txNum0+bi.nTx)
            ret = it->second;
    }
    return ret;
}

std::optional<TxHash> Storage::hashForHeightAndPos(BlockHeight height, unsigned posInBlock) const
{
    std::optional<TxHash> ret;
    TxNum txNum = 0;
    SharedLockGuard(p->blocksLock); // guarantee a consistent view (so that data doesn't mutate from underneath us)
    {
        SharedLockGuard g(p->blkInfoLock);
        if (height >= p->blkInfos.size())
            return ret;
        const BlkInfo & bi = p->blkInfos[height];
        if (posInBlock >= bi.nTx)
            return ret;
        txNum = bi.txNum0 + posInBlock;
    }
    ret = hashForTxNum(txNum);
    return ret;
}

auto Storage::getHistory(const HashX & hashX) const -> History
{
    History ret;
    if (hashX.length() != HashLen)
        return ret;
    try {
        SharedLockGuard g(p->blocksLock);  // makes sure history doesn't mutate from underneath our feet
        static const QString err("Error retrieving history for a script hash");
        auto nums_opt = GenericDBGet<TxNumVec>(p->db.shist.get(), hashX, true, err, false, p->db.defReadOpts);
        if (nums_opt.has_value()) {
            auto & nums = nums_opt.value();
            ret.reserve(nums.size());
            for (auto num : nums) {
                auto hash = hashForTxNum(num).value(); // may throw, but that indicates some database inconsistency. we catch below
                auto height = heightForTxNum(num).value(); // may throw, same deal
                ret.emplace_back(HistoryItem{hash, height});
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

auto Storage::listUnspent(const HashX & hashX) const -> UnspentItems
{
    UnspentItems ret;
    if (hashX.length() != HashLen)
        return ret;
    try {
        constexpr size_t iota = 10; // we initially reserve this many items in the returned array in order to prevent redundant allocations in the common case.
        {
            // take shared lock (ensure history doesn't mutate from underneath our feet)
            SharedLockGuard g(p->blocksLock);
            std::unique_ptr<rocksdb::Iterator> iter(p->db.shunspent->NewIterator(p->db.defReadOpts));
            const rocksdb::Slice prefix = ToSlice(hashX); // points to data in hashX

            // Search table for all keys that start with hashx's bytes. Note: the loop end-condition is strange.
            // See: https://github.com/facebook/rocksdb/wiki/Prefix-Seek-API-Changes#transition-to-the-new-usage
            rocksdb::Slice key;
            bool didReserveIota = false;
            for (iter->Seek(prefix); iter->Valid() && (key = iter->key()).starts_with(prefix); iter->Next()) {
                if (key.size() != HashLen + CompactTXO::serSize())
                    // should never happen, indicates db corruption
                    throw InternalError("Key size for hashx is invalid");
                const CompactTXO ctxo = CompactTXO::fromBytes(key.data() + HashLen, CompactTXO::serSize());
                if (!ctxo.isValid())
                    // should never happen, indicates db corruption
                    throw InternalError("Deserialized CompactTXO is invalid");
                static const QString err("Error retrieving the utxo for an unspent item");
                auto hash = hashForTxNum(ctxo.txNum()).value(); // may throw, but that indicates some database inconsistency. we catch below
                auto height = heightForTxNum(ctxo.txNum()).value(); // may throw, same deal
                auto info = GenericDBGetFailIfMissing<TXOInfo>(p->db.utxoset.get(), TXO{ hash, ctxo.N()}, err, false, p->db.defReadOpts); // may throw -- indicates db inconsistency
                if (!didReserveIota) {
                    // small performance tweak -- reserve iota (10) initially since most unspent lists are <10 in db.
                    didReserveIota = true;
                    ret.reserve(iota);
                }
                ret.emplace_back(UnspentItem{
                    { hash, height }, // base HistoryItem
                    ctxo.N(),  // .tx_pos
                    info.amount, // .value
                    info.txNum, // .txNum
                });
            }
        } // release lock
        std::sort(ret.begin(), ret.end());
        if (const auto sz = ret.size(), cap = ret.capacity(); cap - sz > iota && double(cap)/double(sz) > 1.20)
            // we only do this if we're wasting enough space (at least iota, and at least 20% space wasted),
            // otherwise we don't bother since this returned object is fairly ephemeral and for smallish disparities
            // between capacity and size, it's fine.
            ret.shrink_to_fit();
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

bitcoin::Amount Storage::getBalance(const HashX &hashX) const
{
    bitcoin::Amount ret;
    if (hashX.length() != HashLen)
        return ret;
    try {
        // take shared lock (ensure history doesn't mutate from underneath our feet)
        SharedLockGuard g(p->blocksLock);
        std::unique_ptr<rocksdb::Iterator> iter(p->db.shunspent->NewIterator(p->db.defReadOpts));
        const rocksdb::Slice prefix = ToSlice(hashX); // points to data in hashX

        // Search table for all keys that start with hashx's bytes. Note: the loop end-condition is strange.
        // See: https://github.com/facebook/rocksdb/wiki/Prefix-Seek-API-Changes#transition-to-the-new-usage
        rocksdb::Slice key;
        for (iter->Seek(prefix); iter->Valid() && (key = iter->key()).starts_with(prefix); iter->Next()) {
            if (key.size() != HashLen + CompactTXO::serSize())
                // should never happen, indicates db corruption
                throw InternalError(QString("Key size for scripthash %1 is invalid").arg(QString(hashX.toHex())));
            const CompactTXO ctxo = CompactTXO::fromBytes(key.data() + HashLen, CompactTXO::serSize());
            if (!ctxo.isValid())
                // should never happen, indicates db corruption
                throw InternalError(QString("Deserialized CompactTXO is invalid for scripthash %1").arg(QString(hashX.toHex())));
            bool ok;
            const auto amt = DeserializeScalar<int64_t>(FromSlice(iter->value()), &ok);
            if (UNLIKELY(!ok))
                throw InternalError(QString("Bad amount in db for ctxo %1 (%2)").arg(ctxo.toString()).arg(QString(hashX.toHex())));
            const bitcoin::Amount amount = amt * bitcoin::Amount::satoshi();
            if (UNLIKELY(!bitcoin::MoneyRange(amount)))
                throw InternalError(QString("Out-of-range amount in db for ctxo %1: %2").arg(ctxo.toString()).arg(amt));
            ret += amount; // tally the result
        }
        if (UNLIKELY(!bitcoin::MoneyRange(ret))) {
            ret = ret.zero();
            throw InternalError(QString("Out-of-range total in db for getBalance on scripthash: %1").arg(QString(hashX.toHex())));
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

// HistoryItem & UnspentItem -- operator< and operator== -- for sort.
bool Storage::HistoryItem::operator<(const HistoryItem &o) const noexcept {
    return height == o.height ? hash < o.hash : height < o.height;
}
bool Storage::HistoryItem::operator==(const HistoryItem &o) const noexcept {
    return height == o.height && hash == o.hash;
}
bool Storage::UnspentItem::operator<(const UnspentItem &o) const noexcept {
    if (txNum == o.txNum) { // order by txNum
        if (tx_pos == o.tx_pos) { // then by tx_pos
            // next by tx_hash, height (this branch shouldn't normally be reached with real blockchain data since
            // txNum:tx_pos defines an UnspentItem completed...
            if (HistoryItem::operator<(o))
                return true;
            else if (HistoryItem::operator==(o))
                return value < o.value;
            return false;
        }
        return tx_pos < o.tx_pos;
    }
    return txNum < o.txNum;
}
bool Storage::UnspentItem::operator==(const UnspentItem &o) const noexcept {
    return txNum == o.txNum && tx_pos == o.tx_pos && value == o.value && HistoryItem::operator==(o);
}

namespace {
    // specializations of Serialize/Deserialize
    template <> QByteArray Serialize(const Meta &m)
    {
        QByteArray ba;
        {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            // we serialize the 'magic' value as a simple scalar as a sort of endian check for the DB
            ds << SerializeScalarNoCopy(m.magic) << m.version << m.chain << m.platformBits;
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
                    if (!ds.atEnd()) {
                        // TODO: make this field non-optional. For now we tolerate it missing since we added this field
                        // later and we want to be able to still test on our existing db's.
                        ds >> m.platformBits;
                    }
                    ok = ds.status() == QDataStream::Status::Ok;
                }
            }
        }
        return m;
    }

    template <> QByteArray Serialize (const TXO &txo) { return txo.toBytes(); }
    template <> TXO Deserialize(const QByteArray &ba, bool *ok) {
        TXO ret = TXO::fromBytes(ba); // requires exact size, fails if extra bytes at the end
        if (ok) *ok = ret.isValid();
        return ret;
    }

    template <> QByteArray Serialize(const TXOInfo &inf) { return inf.toBytes(); }
    template <> TXOInfo Deserialize(const QByteArray &ba, bool *ok)
    {
        TXOInfo ret = TXOInfo::fromBytes(ba); // will fail if extra bytes at the end
        if (ok) *ok = ret.isValid();
        return ret;
    }

    // deep copy, raw bytes
    template <> QByteArray Serialize(const BlkInfo &b) { return DeepCpy(&b); }
    // will fail if extra bytes at the end
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

    struct UndoInfoSerHeader {
        static constexpr uint16_t defMagic = 0xf12c, defVer = 0x1;
        uint16_t magic = defMagic; ///< sanity check
        uint16_t ver = defVer; ///< sanity check
        uint32_t len = 0; ///< the length of the entire buffer, including this struct and all data to follow. A sanity check.
        uint32_t nScriptHashes = 0, nAddUndos = 0, nDelUndos = 0; ///< the number of elements in each of the 3 arrays in question.

        static constexpr size_t addUndoItemSerSize = TXO::serSize() + HashLen + CompactTXO::serSize();
        static constexpr size_t delUndoItemSerSize = TXO::serSize() + TXOInfo::serSize();

        /// computes the total size given the ser size of the blkInfo struct. Requires that nScriptHashes, nAddUndos, and nDelUndos be already filled-in.
        size_t computeTotalSize() const {
            const auto shSize = nScriptHashes * HashLen;
            const auto addsSize = nAddUndos * addUndoItemSerSize;
            const auto delsSize = nDelUndos * delUndoItemSerSize;
            return sizeof(*this) + sizeof(UndoInfo::height) + HashLen + sizeof(BlkInfo) + shSize + addsSize + delsSize;
        }
        bool isLenSane() const { return size_t(len) == computeTotalSize(); }
    };

    // UndoInfo
    template <> QByteArray Serialize(const UndoInfo &u) {
        UndoInfoSerHeader hdr;
        // fill these in now so that hdr.computeTotalSize works
        hdr.nScriptHashes = uint32_t(u.scriptHashes.size());
        hdr.nAddUndos = uint32_t(u.addUndos.size());
        hdr.nDelUndos = uint32_t(u.delUndos.size());
        hdr.len = uint32_t(hdr.computeTotalSize());
        QByteArray ret;
        ret.reserve(int(hdr.len));
        // 1. header
        ret.append(ShallowTmp(&hdr));
        // 2. .height
        ret.append(SerializeScalarNoCopy(u.height));
        // 3. .hash
        const auto chkHashLen = [&ret](const QByteArray & hash) -> bool {
            if (hash.length() != HashLen) {
                Warning() << "hash is not " << HashLen << " bytes. Serialize UndoInfo fail. FIXME!";
                ret.clear();
                return false;
            }
            return true;
        };
        if (!chkHashLen(u.hash)) return ret;
        ret.append(u.hash);
        // 4. .blkInfo
        const QByteArray blkInfoBytes = Serialize(u.blkInfo);
        ret.append(blkInfoBytes);
        // 5. .scriptHashes, 32 bytes each, for all in set
        for (const auto & sh : u.scriptHashes) {
            if (UNLIKELY(!chkHashLen(sh))) return ret;
            ret.append(sh);
        }
        // 6. .addUndos, 64 bytes each * nAddUndos
        for (const auto & [txo, hashX, ctxo] : u.addUndos) {
            if (UNLIKELY(!chkHashLen(hashX))) return ret;
            ret.append(Serialize(txo));
            ret.append(hashX);
            ret.append(Serialize(ctxo));
        }
        // 7. .delUndos, 50 bytes each * nDelUndos
        for (const auto & [txo, txoInfo] : u.delUndos) {
            ret.append(Serialize(txo));
            if (UNLIKELY(!chkHashLen(txoInfo.hashX))) return ret;
            ret.append(Serialize(txoInfo));
        }
        assert(ret.length() == int(hdr.len));
        return ret;
    }

    // UndoInfo -- note this will fail if the byte array has extra bytes at the end
    template <> UndoInfo Deserialize(const QByteArray &ba, bool *ok) {
        UndoInfo ret;
        const auto setOk = [&ok, &ret] (bool b) { if (ok) *ok = b; if (!b) ret.clear(); };
        const auto chkAssertion = [&setOk] (bool assertion, const char *extra = "") {
            if (UNLIKELY(!assertion)) {
                Warning() << "Deserialize UndoInfo called with an invalid byte array! FIXME! " << extra;
                setOk(false);
            }
            return assertion;
        };
        if (!chkAssertion(ba.size() > int(sizeof(UndoInfoSerHeader)), "Short byte count"))
            return ret;

        // 1. .header
        const UndoInfoSerHeader *hdr = reinterpret_cast<decltype (hdr)>(ba.data());
        if (!chkAssertion(int(hdr->len) == ba.size() && hdr->magic == hdr->defMagic && hdr->ver == hdr->defVer
                          && hdr->isLenSane(), "Header sanity check fail"))
            return ret;

        const char *cur = ba.data() + sizeof(*hdr), *const end = ba.data() + ba.length();
        bool myok = false;
        // 2. .height
        ret.height = DeserializeScalar<decltype(ret.height)>(ShallowTmp(cur, sizeof(ret.height)), &myok);
        if (!chkAssertion(myok && cur < end))
            return ret;
        cur += sizeof(ret.height);
        // 3. .hash
        ret.hash = DeepCpy(cur, HashLen); // deep copy
        if (!chkAssertion(ret.hash.length() == HashLen && cur < end))
            return ret;
        cur += HashLen;
        // 4. .blkInfo
        ret.blkInfo = Deserialize<BlkInfo>(ShallowTmp(cur, sizeof(BlkInfo)), &myok);
        if (!chkAssertion(myok && cur <= end))
            return ret;
        cur += sizeof(BlkInfo);
        // 5. .scriptHashes, 32 bytes each * hdr->nScriptHashes
        ret.scriptHashes.reserve(hdr->nScriptHashes);
        for (unsigned i = 0; i < hdr->nScriptHashes; ++i) {
            if (!chkAssertion(cur+HashLen <= end)) return ret;
            ret.scriptHashes.insert(DeepCpy(cur, HashLen)); // deep copy
            cur += HashLen;
        }
        // 6. .addUndos, 64 bytes each * nAddUndos
        ret.addUndos.reserve(hdr->nAddUndos);
        for (unsigned i = 0; i < hdr->nAddUndos; ++i) {
            if (!chkAssertion(cur+TXO::serSize() <= end)) return ret;
            TXO txo = Deserialize<TXO>(ShallowTmp(cur, TXO::serSize()), &myok);
            cur += TXO::serSize();
            if (!chkAssertion(myok && cur+HashLen <= end)) return ret;
            QByteArray hashX = DeepCpy(cur, HashLen); // deep copy
            cur += HashLen;
            if (!chkAssertion(cur+CompactTXO::serSize() <= end)) return ret;
            CompactTXO ctxo = Deserialize<CompactTXO>(ShallowTmp(cur, CompactTXO::serSize()), &myok);
            cur += CompactTXO::serSize();
            if (!chkAssertion(myok)) return ret;
            ret.addUndos.emplace_back(std::move(txo), std::move(hashX), std::move(ctxo));
        }
        // 7. .delUndos, 50 bytes each * nDelUndos
        ret.delUndos.reserve(hdr->nDelUndos);
        for (unsigned i = 0; i < hdr->nDelUndos; ++i) {
            if (!chkAssertion(cur+TXO::serSize() <= end)) return ret;
            TXO txo = Deserialize<TXO>(ShallowTmp(cur, TXO::serSize()), &myok);
            cur += TXO::serSize();
            if (!chkAssertion(myok && cur+TXOInfo::serSize() <= end)) return ret;
            TXOInfo info = Deserialize<TXOInfo>(ShallowTmp(cur, TXOInfo::serSize()), &myok);
            cur += TXOInfo::serSize();
            if (!chkAssertion(myok)) return ret;
            ret.delUndos.emplace_back(std::move(txo), std::move(info));
        }
        chkAssertion(cur == end, "cur != end");
        setOk(true);
        return ret;
    }

    template <> QByteArray Serialize(const TxNumVec &v)
    {
        // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
        QByteArray ret(int(v.size()*6), Qt::Uninitialized);
        uint8_t *cur = reinterpret_cast<uint8_t *>(ret.data());
        for (const auto num : v) {
            CompactTXO::txNumToCompactBytes(cur, num);
            cur += 6;
        }
        return ret;
    }
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize (const QByteArray &ba, bool *ok)
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
            ret.emplace_back( CompactTXO::txNumFromCompactBytes(cur) );
        }
        return ret;
    }

    template <> QByteArray Serialize(const CompactTXO &c) { return c.toBytes(); }
    template <> CompactTXO Deserialize(const QByteArray &b, bool *ok) {
        CompactTXO ret = CompactTXO::fromBytes(b);
        if (ok) *ok = ret.isValid();
        return ret;
    }
} // end anon namespace
