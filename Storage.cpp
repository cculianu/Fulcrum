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
    };

    // some database keys we use -- todo: if this grows large, move it elsewhere
    static const rocksdb::Slice kMeta{"meta"}, kNumHeaders{"num_headers"};
    static constexpr size_t MAX_HEADERS = 100000000; // 100 mln max headers for now.

    /// the byte array should live as long as the slice does. slice is just a weak ref into the byte array
    inline rocksdb::Slice ToSlice(const QByteArray &ba) { return rocksdb::Slice(ba.constData(), size_t(ba.size())); }
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return QByteArray::fromRawData(s.data(), int(s.size())); }
    // transform a struct or other class into a serialized byte stream suitable for giving to ToSlice
    // specializations for supported types at the end of this file
    template <typename Thing, std::enable_if_t<!std::is_arithmetic_v<Thing>, int> = 0>
    QByteArray Serialize(const Thing &);
    template <typename Thing, std::enable_if_t<!std::is_arithmetic_v<Thing>, int> = 0>
    Thing Deserialize(const QByteArray &, bool *ok = nullptr);


    // numeric serialize/deser
    template <typename Num, std::enable_if_t<std::is_arithmetic_v<Num>, int> = 0>
    QByteArray Serialize(Num n) {
        QByteArray ba;
        QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
        ds << n;
        return ba;
    }
    template <typename Num, std::enable_if_t<std::is_arithmetic_v<Num>, int> = 0>
    Num Deserialize(const QByteArray &ba, bool *ok = nullptr) {
        QDataStream ds(ba);
        Num ret = {};
        ds >> ret;
        if (ok)
            *ok = ds.status() == QDataStream::Status::Ok;
        return ret;
    }

    // specializations
    template <> QByteArray Serialize(const Meta &);
    template <> Meta Deserialize(const QByteArray &, bool *);
}

struct Storage::Pvt
{
    Headers headers;
    RWLock headersLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBs {
        std::unique_ptr<rocksdb::DB> meta, headers;
    } db;
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
        Meta m_me, m_db;
        std::string data;
        if (auto status = p->db.meta->Get(rocksdb::ReadOptions(), p->db.meta->DefaultColumnFamily(), kMeta, &data);
                !status.ok() && !status.IsNotFound()) {
            throw DatabaseError("Cannot read meta from db");
        } else if (status.IsNotFound()) {
            // ok, did not exist write to db
            status = p->db.meta->Put(rocksdb::WriteOptions(), kMeta, ToSlice(Serialize(m_me)));
            Debug() << "Wrote new metadata to db";
        } else {
            bool ok;
            m_db = Deserialize<Meta>(FromSlice(data), &ok);
            if (!ok || m_db.magic != m_me.magic || m_db.version > m_me.version) {
                throw DatabaseError("Incompatible database format -- delete the datadir and resynch");
            }
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
        if (flags & SaveItem::Hdrs) {
            // headers
            auto [hdrs, guard] = headers();
            saveHeaders_impl(hdrs);
        }
        //if (flags & SaveItem:Whatever) { // ... etc ...
    }
}

void Storage::saveHeaders_impl(const Headers &h)
{
    if (!p->db.headers) return;
    Debug() << "Saving headers ...";
    const auto t0 = Util::getTimeNS();
    {
        rocksdb::WriteBatch batch;
        batch.Put(kNumHeaders, ToSlice(Serialize(unsigned(h.size()))));
        for (size_t i = 0; i < h.size(); ++i) {
            batch.Put(ToSlice(Serialize(unsigned(i))), ToSlice(h[i]));
        }
        p->db.headers->Write(rocksdb::WriteOptions(), &batch);
    }
    const auto elapsed = Util::getTimeNS();
    Debug() << "Wrote " << h.size() << " headers to db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
}

void Storage::loadHeadersFromDB()
{
    FatalAssert(!!p->db.headers) << __FUNCTION__ << ": Headers db is not opene";

    Debug() << "Loading headers ...";
    unsigned num = 0;
    const auto t0 = Util::getTimeNS();
    {
        auto & db = *(p->db.headers);
        std::string datum;
        bool ok;
        if (auto s = db.Get(rocksdb::ReadOptions(), kNumHeaders, &datum);
                s.IsNotFound()) { /* ignore .. */ }
        else if (!s.ok())
            throw DatabaseError(QString("Error reading %1: %2").arg(kNumHeaders.ToString().c_str()).arg(s.ToString().c_str()));
        else if (num = Deserialize<unsigned>(FromSlice(datum), &ok); !ok)
            throw DatabaseError("Error reading header count from database");
        else if (num > MAX_HEADERS)
            throw DatabaseError("Header count in database exceeds MAX_HEADERS! FIXME!");

        Headers h;
        h.reserve(num);
        for (size_t i = 0; i < num; ++i) {
            datum.clear();
            if (auto s = db.Get(rocksdb::ReadOptions(), ToSlice(Serialize(unsigned(i))), &datum); !s.ok())
                throw DatabaseError(QString("Error reading header %1: ").arg(i).arg(s.ToString().c_str()));
            else if (datum.size() != BTC::GetBlockHeaderSize())
                throw DatabaseError(QString("Error reading header %1, wrong size: %2").arg(i).arg(datum.size()));
            h.emplace_back(&datum[0], int(datum.size()));
        }
        // locked until scope end...
        auto [headers, lock] = mutableHeaders();
        headers.swap(h);
    }
    const auto elapsed = Util::getTimeNS();
    Debug() << "Read " << num << " headers from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
}

namespace {
    // specializations of this are later in this file...
    template <> QByteArray Serialize(const Meta &m)
    {
        QByteArray ba;
        {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            ds << m.magic << m.version;
        }
        return ba;
    }
    template <> Meta Deserialize(const QByteArray &ba, bool *ok_ptr)
    {
        bool dummy;
        bool &ok (ok_ptr ? *ok_ptr : dummy);
        ok = false;
        Meta m;
        {
            QDataStream ds(ba);
            ds >> m.magic >> m.version;
            ok = ds.status() == QDataStream::Status::Ok;
        }
        return m;
    }
}
