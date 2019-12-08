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

namespace {
    /// Encapsulates the 'meta' db table
    struct Meta {
        uint32_t magic = 0xf33db33f, version = 0x1;
        QString chain; ///< "test", "main", etc
    };

    // some database keys we use -- todo: if this grows large, move it elsewhere
    static const rocksdb::Slice kMeta{"meta"}, kNumHeaders{"num_headers"};
    static constexpr size_t MAX_HEADERS = 100000000; // 100 mln max headers for now.

    /// NOTE: the byte array should live as long as the slice does. slice is just a weak ref into the byte array
    inline rocksdb::Slice ToSlice(const QByteArray &ba) { return rocksdb::Slice(ba.constData(), size_t(ba.size())); }
    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return QByteArray::fromRawData(s.data(), int(s.size())); }

    // serialize/deser -- for basic types we use QDataStream, but we also have specializations at the end of this file
    template <typename Type>
    QByteArray Serialize(const Type & n) {
        QByteArray ba;
        QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
        ds << n;
        return ba;
    }
    template <typename Type>
    Type Deserialize(const QByteArray &ba, bool *ok = nullptr) {
        QDataStream ds(ba);
        Type ret{};
        ds >> ret;
        if (ok)
            *ok = ds.status() == QDataStream::Status::Ok;
        return ret;
    }
    /// Serialize a simple value such as an int directly, without using the space overhead that QDataStream imposes.
    /// This is less safe but is more compact since the bytes of the passed-in value are written directly to the
    /// returned QByteArray, without any encapsulation.  Note that use of this mechanism makes all data in the database
    /// no longer platform-neutral, which is ok. The presumption is users can re-synch their DB if switching
    /// architectures.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalar(const Scalar & s) {
        return QByteArray(reinterpret_cast<const char *>(&s), sizeof(s));
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
    template <> QByteArray Serialize(const CompactTXO &);
    template <> CompactTXO Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXOInfo &);
    template <> TXOInfo Deserialize(const QByteArray &, bool *);

    /// DB read/write helpers
    /// NOTE: these may throw DatabaseError
    /// If missingOk=false, then the returned optional is guaranteed to have a value if this function returns without throwing.
    /// If missingOk=true, then if there was no other database error and the key was not found, the returned optional !has_value()
    ///
    /// Template arg "safeScalar", if true, will deserialize even scalar int, float, etc data using the Deserialize<>
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
        if (missingOk && status.IsNotFound()) {
            return ret; // optional will not has_value() to indicate missing key
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error reading a key from the db")
                                .arg(status.ToString().c_str()));
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

    // some helper data structs
    struct BlkInfo {
        TxNum txNum0 = 0;
        unsigned nTx = 0, nIns = 0, nOuts = 0;
    };
}

struct Storage::Pvt
{
    Meta meta;
    Lock metaLock;

    Headers headers;
    std::pair<unsigned, QByteArray> lastHeaderSaved; ///< remember the last header saved to disk, so subsequent saves leave off from this index
    RWLock headersLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBs {
        std::unique_ptr<rocksdb::DB> meta, headers, txnums, blkinfo, utxoset, shist;
    } db;

    BTC::HeaderVerifier headerVerifier;
    Lock headerVerifierLock;

    std::atomic<TxNum> txNumNext{0};

    UTXOSet utxoSet;
    RWLock utxoSetLock;
    std::unordered_set<TXO> utxoSetAdditionsUnsaved, utxoSetDeletionsUnsaved;

    std::vector<BlkInfo> blkInfos;

    std::atomic<unsigned> unsavedCt = 0;

    static constexpr size_t nCacheMax = 1000000, nCacheElasticity = 5000000;
    LRU::Cache<true, TxNum, TxHash> lruNum2Hash{nCacheMax, nCacheElasticity};
    LRU::Cache<true, TxHash, TxNum, HashHasher> lruHash2Num{nCacheMax, nCacheElasticity};
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
    loadHeadersFromDB();
    loadUTXOSetFromDB();

    start(); // starts our thread
}

void Storage::cleanup()
{
    stop(); // joins our thread

    // if there is an unsavedCt, flag these as unsaved to check and save. Won't do much if they aren't really unsaved.
    SaveSpec override = p->unsavedCt ? SaveItem::Hdrs|SaveItem::UtxoSet : SaveItem::None;
    save_impl(override);
}

auto Storage::stats() const -> Stats
{
    // TODO ...
    return Stats();
}

auto Storage::mutableHeaders() -> std::pair<Headers &, ExclusiveLockGuard>
{
    return std::pair<Headers &, ExclusiveLockGuard>{ p->headers, p->headersLock };
}

auto Storage::headers() const -> std::pair<const Headers &, SharedLockGuard>
{
    return std::pair<const Headers &, SharedLockGuard>{ p->headers, p->headersLock };
}

// Keep returned LockGuard in scope while you use the HeaderVerifier
auto Storage::headerVerifier() -> std::pair<BTC::HeaderVerifier &, LockGuard>
{
    return std::pair<BTC::HeaderVerifier &, LockGuard>( p->headerVerifier, p->headerVerifierLock );
}

auto Storage::mutableUtxoSet() -> std::pair<UTXOSet &, ExclusiveLockGuard>
{
    return std::pair<UTXOSet &, ExclusiveLockGuard>{ p->utxoSet, p->utxoSetLock };
}

auto Storage::utxoSet() const -> std::pair<const UTXOSet &, SharedLockGuard>
{
    return std::pair<const UTXOSet &, SharedLockGuard>{ p->utxoSet, p->utxoSetLock };
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


// should this come from headersVerifier() instead?
std::pair<int, QByteArray> Storage::latestTip() const {
    std::pair<int, QByteArray> ret;
    {
        auto [hdrs, lock] = headers();
        ret.first = int(hdrs.size())-1; // -1 if no headers
        if (!hdrs.empty())
            ret.second = BTC::HashRev(hdrs.back());
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
            if (flags & SaveItem::UtxoSet) { // utxo set
                using Set = decltype (p->utxoSetAdditionsUnsaved);
                Set unsavedAdditions, unsavedDeletions;
                UTXOSet copy;
                bool doSave = false;
                {
                    ExclusiveLockGuard g(p->utxoSetLock);
                    unsavedAdditions.swap(p->utxoSetAdditionsUnsaved);
                    unsavedDeletions.swap(p->utxoSetDeletionsUnsaved);
                    p->unsavedCt = 0;
                    if ((doSave = unsavedAdditions.size() || unsavedDeletions.size())) {
                        const auto t0 = Util::getTimeNS(); // DEBUG REMOVE ME
                        copy = p->utxoSet; // <-- this copy is inefficient (takes on the order of 1 second -- but it is preferable to holding the lock for potentially many seconds)
                        // DEBUG REMOVE ME
                        const auto elapsed = Util::getTimeNS() - t0;
                        Debug() << "utxo copy took: " << QString::number(elapsed/1e6, 'f', 3) << " msec size: " << copy.size();
                    }
                }
                if (doSave)
                    saveUtxoUnsaved_impl(copy, unsavedAdditions, unsavedDeletions);
            }
            if (flags & SaveItem::Hdrs) { // headers
                // TODO: See if this copy is inefficient. So far it seems preferable to the alternative.
                // We would rather do this here than hold the lock for the duration of the db save.
                const Headers copy = headers().first;
                saveHeaders_impl(copy);
            }
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
    if (auto status = p->db.meta->Put(rocksdb::WriteOptions(), kMeta, ToSlice(Serialize(p->meta))); !status.ok()) {
        throw DatabaseError("Failed to write meta to db");
    }

    Debug() << "Wrote new metadata to db";
}

void Storage::saveHeaders_impl(const Headers &h)
{
    if (!p->db.headers) return;
    //Debug() << "Saving headers ...";
    size_t start = 0;
    const auto t0 = Util::getTimeNS();
    {
        // figure out where to resume from
        if (size_t idx = p->lastHeaderSaved.first; idx && idx < h.size() && p->lastHeaderSaved.second == h[idx]) {
            start = idx + 1;
        }
        if (start < h.size()) {
            Debug() << "Saving from height " << start;
            rocksdb::WriteBatch batch;
            for (size_t i = start; i < h.size(); ++i) {
                // headers are keyed off of uint32_t index (height) -- note we save the raw int value here without any QDataStream encapsulation
                if (auto stat = batch.Put(ToSlice(SerializeScalar(uint32_t(i))), ToSlice(h[i])); !stat.ok())
                    throw DatabaseError(QString("Error writing header %1: %2").arg(i).arg(stat.ToString().c_str()));
            }
            // save height to db *after* we successfully wrote all the headers
            if (auto stat = batch.Put(kNumHeaders, ToSlice(Serialize(uint32_t(h.size())))); !stat.ok())
                throw DatabaseError(QString("Error writing header size key: %1").arg(stat.ToString().c_str()));
            auto opts = rocksdb::WriteOptions();
            // uncomment all this stuff if we want to do fsync and other paranoia. turned off for now.
            //opts.sync = true;
            //opts.low_pri = true;
            if (auto stat = p->db.headers->Write(opts, &batch); !stat.ok())
                throw DatabaseError(QString("Error writing headers: %1").arg(stat.ToString().c_str()));
            //auto fopts = rocksdb::FlushOptions();
            //fopts.wait = true; fopts.allow_write_stall = true;
            //if (auto stat = p->db.headers->Flush(fopts); !stat.ok())
            //    throw DatabaseError(QString("Flush error while writing headers: %1").arg(stat.ToString().c_str()));
            p->lastHeaderSaved = { h.size()-1, h.back() }; // remember last
        }
    }
    const auto elapsed = Util::getTimeNS() - t0;
    const auto ct = (h.size()-start);
    if (ct)
        Debug() << "Wrote " << ct << " " << Util::Pluralize("header", ct) << " to db in " << QString::number(elapsed/1e6, 'f', 3) << " msec";
}

void Storage::saveUtxoUnsaved_impl(const UTXOSet &set, const std::unordered_set<TXO> &adds, const std::unordered_set<TXO> &dels)
{
    if (!p->db.utxoset || !(adds.size()+dels.size())) return;
    //Debug() << "Saving utxo set ...";
    const auto t0 = Util::getTimeNS();
    rocksdb::DB *db = p->db.utxoset.get();
    const auto wopts = rocksdb::WriteOptions();
    // process deletions
    for (const auto & txo : dels) {
        const auto txNum = txNumForHash(txo.prevoutHash, true).value(); // may throw
        CompactTXO ctxo(txNum, txo.prevoutN);
        if (const auto st = db->Delete(wopts, ToSlice(ctxo.toBytesCpy()));
                !st.ok() /*&& !st.IsNotFound()*/)
            throw DatabaseError(QString("Error deleting a utxo from the db: %1").arg(QString::fromStdString(st.ToString())));
    }
    // process additions
    {
        rocksdb::WriteBatch batch;
        for (const auto & txo : adds) {
            const auto txNum = txNumForHash(txo.prevoutHash, true).value(); // may throw
            CompactTXO ctxo(txNum, txo.prevoutN);
            const auto it = set.find(txo);
            if (it == set.end())
                throw InternalError(QString("Missing txo %1 from utxo set .. cannot save!").arg(txo.toString()));
            const auto & info = it->second;
            if (const auto st = batch.Put(ToSlice(ctxo.toBytesCpy()), ToSlice(Serialize(info))); !st.ok())
                throw DatabaseError(QString("Error in writeBatch for txo %1: %2").arg(txo.toString()).arg(QString::fromStdString(st.ToString())));
        }
        if (const auto st = db->Write(wopts, &batch); !st.ok())
            throw DatabaseError(QString("Error writing batch txo additions: %1").arg(QString::fromStdString(st.ToString())));
    }
    const auto elapsed = Util::getTimeNS() - t0;
    Debug() << "Wrote utxo set " << adds.size() << " adds, " << dels.size() << " dels to db in " << QString::number(elapsed/1e6, 'f', 3) << " msec";
}

void Storage::loadHeadersFromDB()
{
    FatalAssert(!!p->db.headers) << __FUNCTION__ << ": Headers db is not open";

    Debug() << "Loading headers ...";
    uint32_t num = 0;
    const auto t0 = Util::getTimeNS();
    {
        auto * const db = p->db.headers.get();

        num = GenericDBGet<uint32_t, true>(db, kNumHeaders, true, "Error reading header count from database").value_or(0); // missing ok
        if (num > MAX_HEADERS)
            throw DatabaseFormatError(QString("Header count (%1) in database exceeds MAX_HEADERS! This is likely due to"
                                              " a database format mistmatch. Delete the datadir and resynch it.")
                                      .arg(num));

        Headers h;
        h.reserve(num);
        const QString errMsg("Error retrieving header from db");
        const int hsz = BTC::GetBlockHeaderSize();
        // read db
        for (uint32_t i = 0; i < num; ++i) {
            // guaranteed to return a value or throw
            auto bytes = GenericDBGetFailIfMissing<QByteArray>(db, ToSlice(SerializeScalar(uint32_t(i))), errMsg);
            if (UNLIKELY(bytes.size() != hsz))
                throw DatabaseFormatError(QString("Error reading header %1, wrong size: %2").arg(i).arg(bytes.size()));
            h.emplace_back(std::move(bytes));
        }
        // verify headers: hashPrevBlock must match what we actually read from db
        if (num) {
            Debug() << "Verifying " << num << " " << Util::Pluralize("header", num) << " ...";
            auto [verif, lock] = headerVerifier();
            QString err;
            for (unsigned i = 0; i < num; ++i) {
                // verify headers hash chains match by checking hashPrevBlock versus actual previous hash.
                // we use the helper functor HeaderVerifier for this.
                if (!verif(h[i], &err))
                    throw DatabaseError(QString("%1. Possible databaase corruption. Delete the datadir and resynch.").arg(err));
            }
            p->lastHeaderSaved = verif.lastHeaderProcessed(); // remember last
        }
        // locked until scope end...
        auto [headers, lock] = mutableHeaders();
        headers.swap(h);
    }
    if (num) {
        const auto elapsed = Util::getTimeNS();

        Debug() << "Read & verified " << num << " " << Util::Pluralize("header", num) << " from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
    }
}

void Storage::loadUTXOSetFromDB()
    {
        FatalAssert(!!p->db.utxoset) << __FUNCTION__ << ": Utxo set db is not open";

        Debug() << "Loading utxo set ...";

        const auto t0 = Util::getTimeNS();
        {
            // the purpose of this map is to ensure that all txid's in app memory share the same implicitly shared QByteArray
            std::unordered_set<HashX, HashHasher> hashXSeen;
            //robin_hood::unordered_flat_map<TxNum, TxHash> num2hash; // this also acts as a cache as well as ensuring all txhashes share the same QByteArray

            const int currentHeight = latestTip().first;

            std::unique_ptr<rocksdb::Iterator> iter(p->db.utxoset->NewIterator(rocksdb::ReadOptions()));
            if (!iter) throw DatabaseError("Unable to obtain an iterator to the utxo set db");
            iter->SeekToFirst();
            unsigned ctr = 0;
            size_t savings = 0, cost = 0;
            for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
                const auto ctxo = CompactTXO::fromBytes(FromSlice(iter->key()));
                if (!ctxo.isValid()) {
                    throw DatabaseSerializationError("Read an invalid txo from the utxo set database."
                                                     " This may be due to a database format mismatch."
                                                     " Delete the datadir and resynch it.");
                }
                TxHash hash;
                //if (auto it = num2hash.find(ctxo.txNum()); it != num2hash.end()) {
                //    hash = it->second; // ensure implicitly shared
                //    savings += size_t(hash.length());
                /*} else*/ {
                    bool wasCached = false;
                    const auto ohash = hashForTxNum(ctxo.txNum(), false, &wasCached); // reads from db. db uses some caching hopefully
                    if (!ohash.has_value())
                        throw DatabaseFormatError("A txo is missing its txhash metadata in the db."
                                                  " This may be due to a database format mismatch."
                                                  " Delete the datadir and resynch it.");
                    //num2hash[ctxo.txNum()] = hash = ohash.value();
                    hash = ohash.value();
                    if (wasCached) savings += size_t(hash.length());
                    else cost += size_t(hash.length());
                }
                if (hash.length() != HashLen)
                    throw DatabaseFormatError("A txo is missing has corrupted txhash metadata in the db."
                                              " Delete the datadir and resynch it.");
                auto info = TXOInfo::fromBytes(FromSlice(iter->value()));
                if (!info.isValid())
                    throw DatabaseSerializationError(QString("Txo %1:%2 has invalid metadata in the db."
                                                            " This may be due to a database format mismatch."
                                                            " Delete the datadir and resynch it.")
                                                     .arg(QString(hash.toHex()))
                                                     .arg(ctxo.N()));
                if (info.confirmedHeight.has_value() && int(info.confirmedHeight.value()) > currentHeight) {
                    // TODO: reorg? Inconsisent db?  FIXME
                    Debug() << "Ignoring txo " << hash << ":" << ctxo.N() << " at height: "
                            << info.confirmedHeight.value() << " > current height: " << currentHeight;
                    continue;
                }
                if (auto it = hashXSeen.find(info.hashX); it != hashXSeen.end()) {
                    info.hashX = *it; // make sure they all implicitly share the same hashx
                    savings += size_t(info.hashX.length());
                } else {
                    hashXSeen.insert(info.hashX);
                    cost += size_t(info.hashX.length());
                }
                p->utxoSet[TXO{hash, ctxo.N()}] = info;
                cost += sizeof(TXO) + sizeof(TXOInfo);
                if (0 == ++ctr % 100000) {
                    *(0 == ctr % 2500000 ? std::make_unique<Log>() : std::make_unique<Debug>()) << "Read " << ctr << " utxos ...";
                }
            }
            Log() << "UTXO set " << QString::number(cost/1e6, 'f', 3) << " MiB in " << p->utxoSet.size() << " txos";
            Debug() << "Mem savings: " << QString::number(savings/1e6, 'f', 3) << " MiB (" << /*num2hash: " << num2hash.size() << " " << */"hashXSeen: " << hashXSeen.size() << ")";
            const size_t nShrink1 = p->lruHash2Num.shrink(), nShrink2 = p->lruNum2Hash.shrink();
            Debug() << "Purged cache: " << std::max(nShrink1, nShrink2) << " tx hashes, cache size now: " << std::max(p->lruHash2Num.size(), p->lruNum2Hash.size()) << " tx hashes";
        }
        const auto num = p->utxoSet.size();
        if (num) {
            const auto elapsed = Util::getTimeNS();

            Debug() << "Read " << num << " " << Util::Pluralize("utxo", num) << " from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
        }
    }


QString Storage::addBlock(PreProcessedBlockPtr ppb, unsigned nReserve)
{
    assert(bool(ppb) && bool(p));

    QString errRet;

    std::scoped_lock guard(p->headerVerifierLock, p->headersLock, p->utxoSetLock); // take all locks now.. todo: add more locks here
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
        {
            rocksdb::WriteBatch batch;
            const TxNum txNum0 = p->txNumNext;
            for (size_t i = 0; i < ppb->txInfos.size(); ++i) {
                const TxNum txnum = txNum0 + i;
                const TxHash & hash = ppb->txInfos[i].hash;
                const auto hashSlice = ToSlice(hash);
                const auto txNumBytes = SerializeScalar(txnum);
                // txnums are keyed off of uint64_t txNum -- note we save the raw uint64 value here without any QDataStream encapsulation
                if (auto stat = batch.Put(ToSlice(txNumBytes), hashSlice); !stat.ok())
                    throw DatabaseError(QString("Error writing txNum -> txHash for txNum %1: %2").arg(txNum0 + i).arg(QString::fromStdString(stat.ToString())));
                if (auto stat = batch.Put(hashSlice, ToSlice(txNumBytes)); !stat.ok())
                    throw DatabaseError(QString("Error writing txHash -> txNum for txNum %1: %2").arg(txNum0 + i).arg(QString::fromStdString(stat.ToString())));

                // add to lru cache since these may be used immediately below..
                p->lruHash2Num.insert(hash, txnum);
                p->lruNum2Hash.insert(txnum, hash);
            }
            if (auto stat = p->db.txnums->Write(rocksdb::WriteOptions(), &batch); !stat.ok())
                throw DatabaseError(QString("Error writing txNums batch: %1").arg(QString::fromStdString(stat.ToString())));

        }
        //auto elapsed = Util::getTimeNS() - t0;
        //Debug() << "Wrote " << ppb->txInfos.size() << " new TxNums to db in " << QString::number(elapsed/1e6, 'f', 3) << " msec";

        static constexpr bool debugPrt = false;

        // update utxoSet
        {
            // add outputs

            for (const auto & [hashX, ag] : ppb->hashXAggregated) {
                for (const auto oidx : ag.outs) {
                    const auto & out = ppb->outputs[oidx];
                    const TxHash & hash = ppb->txInfos[out.txIdx].hash;
                    TXOInfo info;
                    info.hashX = hashX;
                    info.amount = out.amount;
                    info.confirmedHeight = ppb->height;
                    const TXO txo{ hash, out.outN };
                    p->utxoSet[txo] = info;
                    p->utxoSetAdditionsUnsaved.insert(txo);
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
                if (!inum) {
                    // coinbase.. skip
                } else if (const auto it = p->utxoSet.find(TXO{in.prevoutHash, in.prevoutN}); it != p->utxoSet.end()) {
                    const auto & info = it->second;
                    if (info.confirmedHeight.has_value() && info.confirmedHeight.value() != ppb->height) {
                        // was a prevout from a previos block.. so the ppb didn't have it in the touched set..
                        // mark the spend as having touched this hashX for this ppb now.
                        ppb->hashXAggregated[info.hashX].ins.emplace_back(inum);
                        in.prevoutHash = it->first.prevoutHash; // ensure shallow/shared copy of QByteArray in inputs
                        newHashXInputsResolved.insert(info.hashX);
                    }
                    if constexpr (debugPrt) {
                        const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                        Debug() << "Spent " << it->first.toString() << " amount: " << it->second.amount.ToString()
                                << " in txid: "  << dbgTxIdHex << " height: " << ppb->height
                                << " input number: " << ppb->numForInputIdx(inum).value_or(0xffff)
                                << " HashX: " << it->second.hashX.toHex();
                    }
                    if (auto it2 = p->utxoSetAdditionsUnsaved.find(it->first); it2 != p->utxoSetAdditionsUnsaved.end()) {
                        // was in unsaved additions, no need to add it to deletions
                        p->utxoSetAdditionsUnsaved.erase(it2);
                    } else {
                        // was not in unsaved additions.. add it to deletions
                        p->utxoSetDeletionsUnsaved.insert(it->first);
                    }
                    p->utxoSet.erase(it); // invalidate txo  (spend it) by removing from map
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
                Debug() << "utxoset size: " << p->utxoSet.size() << " block: " << ppb->height;
        }

        if (nReserve) {
            if (const auto size = p->headers.size(); size + nReserve < p->headers.capacity())
                p->headers.reserve(size + nReserve); // reserve space for new headers in 1 go to save on copying
            if (const auto size = p->blkInfos.size(); size + nReserve < p->blkInfos.capacity())
                p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
        }

        // save blkInfos
        p->blkInfos.emplace_back(BlkInfo{
            p->txNumNext, // .txNum0
            unsigned(ppb->txInfos.size()),
            unsigned(ppb->inputs.size()),
            unsigned(ppb->outputs.size())
        });

        // append header (todo: see about reserving suitable chunks)
        p->headers.emplace_back(rawHeader);
        // update txNum after everything checks out
        p->txNumNext += ppb->txInfos.size();

        ++p->unsavedCt;

    } catch (const std::exception & e) {
        errRet = e.what();
        p->headerVerifier = verifUndo; // undo header verifier state
    }

    // enqueue a save every 10000 blocks
    if (errRet.isEmpty() && p->unsavedCt > 10000) {
        p->unsavedCt = 0;
        save(SaveItem::Hdrs|SaveItem::UtxoSet);
    }

    return errRet;
}

// some helpers for TxNum -- these may throw DatabaseError
std::optional<TxNum> Storage::txNumForHash(const TxHash &h, bool throwIfMissing, bool *wasCached)
{
    std::optional<TxNum> ret = p->lruHash2Num.tryGet(h);
    if (ret.has_value()) {
        // save was cached flat
        if (wasCached) *wasCached = true;
        return ret; // cached, return it
    } else if (wasCached) *wasCached = false; // save flag if caller is interested

    static const QString kErrMsg ("Error reading txNumForHash from db");

    ret = GenericDBGet<TxNum, false>(p->db.txnums.get(), ToSlice(h), !throwIfMissing, kErrMsg);
    if (ret.has_value())
        // save in cache
        p->lruHash2Num.insert(h, ret.value());
    return ret;
}

std::optional<TxHash> Storage::hashForTxNum(TxNum n, bool throwIfMissing, bool *wasCached)
{
    std::optional<TxHash> ret = p->lruNum2Hash.tryGet(n);
    if (ret.has_value()) {
        if (wasCached) *wasCached = true;
        return ret;
    } else if (wasCached) *wasCached = false;

    static const QString kErrMsg ("Error reading hashForTxNum from db");
    ret = GenericDBGet<TxHash, false>(p->db.txnums.get(), ToSlice(SerializeScalar(n)), !throwIfMissing, kErrMsg);
    if (ret.has_value())
        // save in cache
        p->lruNum2Hash.insert(n, ret.value());
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
            ds << SerializeScalar(m.magic) << m.version << m.chain;
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

    template <> QByteArray Serialize [[maybe_unused]] (const CompactTXO &ctxo) { return ctxo.toBytesCpy(); }
    template <> CompactTXO Deserialize [[maybe_unused]] (const QByteArray &ba, bool *ok) {
        CompactTXO ret = CompactTXO::fromBytes(ba);
        if (ok) *ok = ret.isValid();
        return ret;
    }

    template <> QByteArray Serialize(const TXOInfo &inf) { return inf.toBytes(); }
    template <> TXOInfo Deserialize [[maybe_unused]] (const QByteArray &ba, bool *ok)
    {
        TXOInfo ret = TXOInfo::fromBytes(ba);
        if (ok) *ok = ret.isValid();
        return ret;
    }
}
