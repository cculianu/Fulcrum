#include "BTC.h"
#include "Storage.h"

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"

#include <QByteArray>
#include <QDir>

#include <atomic>
#include <shared_mutex>
#include <type_traits>
#include <vector>

DatabaseError::~DatabaseError(){} // vtable

namespace {
    /// Encapsulates the 'meta' db table
    struct Meta {
        uint32_t magic = 0xf33db33f, version = 0x1;
        QString chain; ///< "test", "main", etc
    };

    // some database keys we use -- todo: if this grows large, move it elsewhere
    static const rocksdb::Slice kMeta{"meta"}, kNumHeaders{"num_headers"};
    static constexpr size_t MAX_HEADERS = 100000000; // 100 mln max headers for now.

    /// the byte array should live as long as the slice does. slice is just a weak ref into the byte array
    inline rocksdb::Slice ToSlice(const QByteArray &ba) { return rocksdb::Slice(ba.constData(), size_t(ba.size())); }
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
        std::string data;
        if (auto status = p->db.meta->Get(rocksdb::ReadOptions(), p->db.meta->DefaultColumnFamily(), kMeta, &data);
                !status.ok() && !status.IsNotFound()) {
            throw DatabaseError("Cannot read meta from db");
        } else if (status.IsNotFound()) {
            // ok, did not exist .. write a new one to db
            saveMeta_impl();
        } else {
            bool ok;
            m_db = Deserialize<Meta>(FromSlice(data), &ok);
            if (!ok || m_db.magic != p->meta.magic || m_db.version != p->meta.version) {
                throw DatabaseError("Incompatible database format -- delete the datadir and resynch");
            }
            p->meta = m_db;
            Debug () << "Read meta from db ok";
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
        auto & db = *(p->db.headers);
        rocksdb::PinnableSlice datum;
        bool ok;
        if (auto s = db.Get(rocksdb::ReadOptions(), db.DefaultColumnFamily(), kNumHeaders, &datum);
                s.IsNotFound()) { /* ignore .. */ }
        else if (!s.ok())
            throw DatabaseError(QString("Error reading %1: %2").arg(kNumHeaders.ToString().c_str()).arg(s.ToString().c_str()));
        else if (num = Deserialize<uint32_t>(FromSlice(datum), &ok); !ok)
            throw DatabaseError("Error reading header count from database");
        else if (num > MAX_HEADERS)
            throw DatabaseError("Header count in database exceeds MAX_HEADERS! FIXME!");

        datum.Reset();
        Headers h;
        h.reserve(num);
        // read db
        for (uint32_t i = 0; i < num; ++i, datum.Reset()) {
            if (auto s = db.Get(rocksdb::ReadOptions(), db.DefaultColumnFamily(), ToSlice(SerializeScalar(uint32_t(i))), &datum); !s.ok())
                throw DatabaseError(QString("Error reading header %1: %2").arg(i).arg(s.ToString().c_str()));
            else if (datum.size() != BTC::GetBlockHeaderSize())
                throw DatabaseError(QString("Error reading header %1, wrong size: %2").arg(i).arg(datum.size()));
            h.emplace_back(datum.data(), int(datum.size()));
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
