#include "BTC.h"
#include "Storage.h"

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"

#include <QByteArray>
#include <QDir>

#include <atomic>
#include <optional>
#include <shared_mutex>
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
                                        bool acceptExtraBytesAtEndOfData = false) ///< if true, we are ok with extra unparsed bytes in data. otherwise we throw. (this check is only done for !safeScalar mode)
    {
        rocksdb::PinnableSlice datum;
        std::optional<RetType> ret;
        if (UNLIKELY(!db)) throw InternalError("GenericDBGet was passed a null pointer!");
        const auto status = db->Get(rocksdb::ReadOptions(), db->DefaultColumnFamily(), key, &datum);
        if (missingOk && status.IsNotFound()) {
            return ret; // optional will not has_value() to indicate missing key
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error reading a key from the db")
                                .arg(status.ToString().c_str()));
        } else {
            // ok status
            if constexpr (std::is_base_of_v<QByteArray, std::remove_cv_t<RetType> >) {
                // special compile-time case for QByteArray subclasses -- return a deep copy of the data bytes directly.
                // TODO: figure out a way to do this without the 1 extra copy! (PinnableSlice -> ret).
                ret.emplace(reinterpret_cast<const char *>(datum.data()), QByteArray::size_type(datum.size()));
            } else if constexpr (!safeScalar && std::is_scalar_v<RetType> && !std::is_pointer_v<RetType>) {
                if (!acceptExtraBytesAtEndOfData && datum.size() > sizeof(RetType)) {
                    // reject extra stuff at end of data stream
                    throw DatabaseFormatError(QString("%1: Extra bytes at the end of data")
                                              .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Database format error"));
                }
                bool ok;
                ret = DeserializeScalar<RetType>(FromSlice(datum), &ok);
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized as a scalar '%2'")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error deserializing a scalar from db")
                                .arg(typeid (RetType).name()));
                }
            } else {
                bool ok;
                ret = Deserialize<RetType>(FromSlice(datum), &ok);
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
    RetType GenericDBGetFailIfMissing(rocksdb::DB * db, const rocksdb::Slice &k, const QString &errMsgPrefix = QString(), bool extraDataOk = false)
    {
        return GenericDBGet<RetType, safeScalar>(db, k, false, errMsgPrefix, extraDataOk).value();
    }
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
        std::unique_ptr<rocksdb::DB> meta, headers;
    } db;

    BTC::HeaderVerifier headerVerifier;
    Lock headerVerifierLock;
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
    rocksdb::Options opts;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    opts.IncreaseParallelism();
    opts.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present
    opts.create_if_missing = true;
    opts.error_if_exists = false;
    opts.compression = rocksdb::CompressionType::kNoCompression; // for now we test without compression. TODO: characterize what is fastest and best..

    QString metaPath = options->datadir + QDir::separator() + "meta",
            headersPath = options->datadir + QDir::separator() + "headers";

    rocksdb::DB *db = nullptr;
    rocksdb::Status s;
    // meta database
    s = rocksdb::DB::Open(opts, metaPath.toStdString(), &db);
    if (!s.ok() || !db)
        throw DatabaseError(QString("Error opening meta database: %1 (path: %2)").arg(s.ToString().c_str()).arg(metaPath));
    p->db.meta.reset(db); db = nullptr;
    // headers database
    s = rocksdb::DB::Open(opts, headersPath.toStdString(), &db);
    if (!s.ok() || !db)
        throw DatabaseError(QString("Error opening headers database: %1 (path: %2)").arg(s.ToString().c_str()).arg(headersPath));
    p->db.headers.reset(db); db = nullptr;

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

    start(); // starts our thread
}

void Storage::cleanup()
{
    stop(); // joins our thread

    save_impl(); // writes all "dirty" data immediately to disk
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

void Storage::save(SaveSpec typed_spec)
{
    using IntType = decltype(p->pendingSaves.load());
    // enqueue save on event loop if not previously enqueued (we know it was previously enqueued if the p->pendingSaves
    // atomic variable is not 0).
    if (const auto spec = IntType(typed_spec); ! p->pendingSaves.fetch_or(spec))
    {
        QTimer::singleShot(0, this, &Storage::save_impl);
    }
}

void Storage::save_impl()
{
    if (const auto flags = SaveSpec(p->pendingSaves.exchange(0)); flags) { // atomic clear of flags, grab prev val
        try {
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
    Debug() << "Saving headers ...";
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
            opts.sync = true;
            opts.low_pri = true;
            if (auto stat = p->db.headers->Write(opts, &batch); !stat.ok())
                throw DatabaseError(QString("Error writing headers: %1").arg(stat.ToString().c_str()));
            auto fopts = rocksdb::FlushOptions();
            fopts.wait = true; fopts.allow_write_stall = true;
            if (auto stat = p->db.headers->Flush(fopts); !stat.ok())
                throw DatabaseError(QString("Flush error while writing headers: %1").arg(stat.ToString().c_str()));
            p->lastHeaderSaved = { h.size()-1, h.back() }; // remember last
        }
    }
    const auto elapsed = Util::getTimeNS();
    const auto ct = (h.size()-start);
    Debug() << "Wrote " << ct << " " << Util::Pluralize("header", ct) << " to db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
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
        // read db
        for (uint32_t i = 0; i < num; ++i) {
            // guaranteed to return a value
            const auto bytes = GenericDBGetFailIfMissing<QByteArray>(db, ToSlice(SerializeScalar<uint32_t>(i)),
                                                                     QString("Error retrieving header %1").arg(i));
            if (bytes.size() != int(BTC::GetBlockHeaderSize()))
                throw DatabaseFormatError(QString("Error reading header %1, wrong size: %2").arg(i).arg(bytes.size()));
            h.emplace_back(bytes);
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
}
