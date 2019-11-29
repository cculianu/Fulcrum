#include "BTC.h"
#include "Storage.h"

#include "bitcoin/block.h"
#include "bitcoin/streams.h"
#include "bitcoin/version.h"

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

    // specializations
    template <> QByteArray Serialize(const Meta &);
    template <> Meta Deserialize(const QByteArray &, bool *);
}

struct Storage::Pvt
{
    Headers headers;
    std::pair<size_t, QByteArray> lastHeaderSaved; ///< remember the last header saved to disk, so subsequent saves leave off from this index
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
        try {
            if (flags & SaveItem::Hdrs) { // headers
                // TODO: See if this copy is inefficient. So far it seems preferable to the alternative.
                // We would rather do this here than hold the lock for the duration of the db save.
                const Headers copy = headers().first;
                saveHeaders_impl(copy);
            }
            //if (flags & SaveItem:Whatever) { // ... etc ...
        } catch (const std::exception & e) {
            Fatal() << e.what(); // will abort app...
        }
    }
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
                if (auto stat = batch.Put(ToSlice(Serialize(unsigned(i))), ToSlice(h[i])); !stat.ok())
                    throw DatabaseError(QString("Error writing header %1: %2").arg(i).arg(stat.ToString().c_str()));
            }
            if (auto stat = batch.Put(kNumHeaders, ToSlice(Serialize(unsigned(h.size())))); !stat.ok())
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
    unsigned num = 0;
    const auto t0 = Util::getTimeNS();
    {
        auto & db = *(p->db.headers);
        rocksdb::PinnableSlice datum;
        bool ok;
        if (auto s = db.Get(rocksdb::ReadOptions(), db.DefaultColumnFamily(), kNumHeaders, &datum);
                s.IsNotFound()) { /* ignore .. */ }
        else if (!s.ok())
            throw DatabaseError(QString("Error reading %1: %2").arg(kNumHeaders.ToString().c_str()).arg(s.ToString().c_str()));
        else if (num = Deserialize<unsigned>(FromSlice(datum), &ok); !ok)
            throw DatabaseError("Error reading header count from database");
        else if (num > MAX_HEADERS)
            throw DatabaseError("Header count in database exceeds MAX_HEADERS! FIXME!");

        datum.Reset();
        Headers h;
        h.reserve(num);
        // read db
        for (unsigned i = 0; i < num; ++i, datum.Reset()) {
            if (auto s = db.Get(rocksdb::ReadOptions(), db.DefaultColumnFamily(), ToSlice(Serialize(unsigned(i))), &datum); !s.ok())
                throw DatabaseError(QString("Error reading header %1: ").arg(i).arg(s.ToString().c_str()));
            else if (datum.size() != BTC::GetBlockHeaderSize())
                throw DatabaseError(QString("Error reading header %1, wrong size: %2").arg(i).arg(datum.size()));
            h.emplace_back(datum.data(), int(datum.size()));
        }
        // verify headers: hashPrevBlock must match what we actually read from db
        if (num) {
            Debug() << "Verifying " << num << " " << Util::Pluralize("header", num) << " ...";
            bitcoin::CBlockHeader prevHdr, curHdr;
            for (unsigned i = 0; i < num; ++i) {
                bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, h[i], 0);
                curHdr.Unserialize(vr);
                // verify headers hash chains match by checking hashPrevBlock versus actual previous hash.
                if (i > 0 && curHdr.hashPrevBlock != prevHdr.GetHash())
                    throw DatabaseError(QString("Header %1 'hashPrevBlock' does not match the previous block read from db. "
                                                "Possible databaase corruption. Delete the datadir and resynch.")
                                        .arg(i));
                prevHdr = curHdr;
            }
            p->lastHeaderSaved = { h.size()-1, h.back() }; // remember last
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
