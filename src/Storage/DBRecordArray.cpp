//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#include "DBRecordArray.h"

#include "ByteView.h"
#include "ConcatOperator.h"
#include "Util.h"

#include "bitcoin/serialize.h"
#include "bitcoin/streams.h"

#include <QFileInfo>

#include <bit>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace {

const std::string kMetaDataKey; // the metadata row is a single empty string. It must be the first row!

} // end namespace

struct DBRecordArray::MetaData {
    uint32_t magic{};
    uint64_t recSz{};
    uint64_t bucketNRecs{};
    uint64_t nRecs{};

    MetaData() = default;
    explicit MetaData(const DBRecordArray &d)
        : magic{d.magicBytes()}, recSz{d.recordSize()}, bucketNRecs{d.bucketNumRecords()}, nRecs{d.numRecords()} {}

    SERIALIZE_METHODS(MetaData, obj) {
        READWRITE(obj.magic, obj.recSz, obj.bucketNRecs, obj.nRecs);
    }

    template<typename Ret = std::string>
    Ret toBytes() const {
        using VT = typename Ret::value_type;
        static_assert(sizeof(VT) == 1);
        Ret ret;
        ret.reserve(sizeof(*this));
        bitcoin::GenericVectorWriter(0, 0, ret, 0, *this);
        return ret;
    }

    bool fromBytes(const ByteView &bytes, std::string *errStr = nullptr) {
        try {
            bitcoin::GenericVectorReader(0, 0, bytes, 0, *this);
        } catch (const std::ios_base::failure &e) {
            if (errStr) *errStr = e.what();
            return false;
        }
        return true;
    }
};

DBRecordArray::Error::~Error() {} // for vtable

DBRecordArray::DBRecordArray(rocksdb::DB &db_, rocksdb::ColumnFamilyHandle &cf_, uint32_t recSz_,
                             const uint32_t bucketNRecsPOT, uint32_t magic_) noexcept(false)
    : db{db_}, cf{cf_}, recSz{recSz_}, magic{magic_}, bucketNRecs{std:: bit_floor(bucketNRecsPOT)},
      bucketShiftAmt{static_cast<uint8_t>(std::popcount(bucketNRecs - 1u))}
{
    // bucketNRecsPOT must be a power of 2
    if (!std::has_single_bit(bucketNRecsPOT))
        throw Error(QString("%1: specified bucketNRecs size of `%2` is not a power of 2!").arg(__func__).arg(bucketNRecsPOT));
    // recSz cannot be 0 and buckets cannot exceed 2GiB (for rocksdb safety)
    if (recSz == 0 || static_cast<uint64_t>(recSz) * static_cast<uint64_t>(bucketNRecs) > 1ull << 31u)
        throw Error(QString("%1: invalid record size and/or bucket size combination (recSz * bucketNRecs = %2)")
                        .arg(__func__).arg(recSz * bucketNRecs));
    // Ensure basic sanity of the column family in question
    rocksdb::ColumnFamilyDescriptor desc;
    if (auto s = cf.GetDescriptor(&desc); ! s.ok())
        throw Error(QString("%1: failed to retrieve ColumnFamilyDescriptor, error: %2").arg(__func__, QString::fromStdString(s.ToString())));
    // merge operator must be our ConcatOperator class
    else if ( ! desc.options.merge_operator || ! dynamic_cast<StorageDetail::ConcatOperator *>(desc.options.merge_operator.get()))
        throw Error(QString("%1: DB column %2 lacks a merge operator of the proper type (merge operator found: %3)")
                        .arg(__func__, QString::fromStdString(desc.name), QString::fromStdString(desc.options.merge_operator
                                                                                                     ? desc.options.merge_operator->Name()
                                                                                                     : "NONE")));
    // comparator must be the default bytewise comparator
    else if (desc.options.comparator != rocksdb::ColumnFamilyOptions{}.comparator)
        throw Error(QString("%1: DB column %2 has an unexpected comparator: %3")
                        .arg(__func__, QString::fromStdString(desc.name), QString::fromStdString(desc.options.comparator
                                                                                                     ? desc.options.comparator->Name()
                                                                                                     : "NONE")));

    readOrInitMeta();
}

QString DBRecordArray::name() const
{
    return QFileInfo(QString::fromStdString(db.GetName())).fileName() + "/" + QString::fromStdString(cf.GetName());
}

void DBRecordArray::readOrInitMeta()
{
    const QString dbName = name();
    // read the "meta" row (first row)
    std::unique_ptr<rocksdb::Iterator> iter{db.NewIterator(ropts, &cf)};
    if (!iter) throw Error(QString("%1: INTERNAL ERROR for DB %1 -- got a null iterator from db.NewIterator()!").arg(__func__, dbName));
    iter->SeekToFirst();
    MetaData meta;
    bool isNew = false;
    nRecs = 0;
    if (iter->Valid()) {
        // non-empty DB first record *must* be the metadata entry
        if (iter->key().compare(kMetaDataKey) != 0) {
            throw Error(QString("%1: Unrecognized DB format for %2 -- first row must be the metadata entry!").arg(__func__, dbName));
        }
        meta.fromBytes(iter->value());
        if (meta.magic != magic)
            throw Error(QString("%1: Magic bytes mismatch for DB %2, expected: %3, got: %4").arg(__func__, dbName)
                            .arg(magic, 8, 16, QChar{'0'}).arg(meta.magic, 8, 16, QChar{'0'}));
        if (meta.recSz != recSz)
            throw Error(QString("%1: Record size mismatch for DB %2, expected: %3, got: %4").arg(__func__, dbName)
                            .arg(recSz).arg(meta.recSz));
        if (meta.bucketNRecs != bucketNRecs) {
            if (!std::has_single_bit(meta.bucketNRecs))
                throw Error(QString("%1: bucketNRecs mismatch for DB %2, expected: %3, got: %4; DB value is not a power of 2!")
                                .arg(__func__, dbName).arg(bucketNRecs).arg(meta.bucketNRecs));
            if (static_cast<uint64_t>(recSz) * static_cast<uint64_t>(meta.bucketNRecs) > 1ull << 31u)
                throw Error(QString("%1: excessive bucket size read from metadata in DB (recSz * bucketNRecs = %2)")
                                .arg(__func__).arg(recSz * meta.bucketNRecs));
            Warning() << __func__ << ": bucketNRecs mismatch for DB " << dbName << ", expected: " << bucketNRecs
                      <<  " got: " << meta.bucketNRecs << ", will proceed with DB value instead";
            bucketNRecs = meta.bucketNRecs;
            bucketShiftAmt = static_cast<uint8_t>(std::popcount(bucketNRecs - 1u));
        }

        // See if nRecs is sane
        iter->SeekToLast();
        if (!iter->Valid())
            throw Error(QString("%1: INTERNAL ERROR for DB %2 -- unable to seek to last row!").arg(__func__, dbName));
        if (meta.nRecs > 0u) {
            // we have records, check the last row is what we expect
            const uint64_t lastRecNum = meta.nRecs - 1u;
            const VarIntBE lastKeyVarInt = makeKey(recordNumToBucketNum(lastRecNum));
            const rocksdb::Slice lastKey = lastKeyVarInt.byteView().toStringView();
            if (const auto &k = iter->key(); k.compare(lastKey) != 0)
                throw Error(QString("%1: Database corruption possible for DB %2 -- last row's key is not as expected. Expected: %3, got: %4").arg(__func__, dbName)
                                .arg(QString::fromLatin1(QByteArray(lastKey.data(), lastKey.size()).toHex()))
                                .arg(QString::fromLatin1(QByteArray(k.data(), k.size()).toHex())));

            const auto bucketData = iter->value();
            if (bucketData.size() % recSz)
                throw Error(QString("%1: Database corruption possible for DB %2 -- last row's data blob is not sized correctly. Expected a multiple of %3, got: %4").arg(__func__, dbName)
                                .arg(recSz).arg(bucketData.size()));
            const size_t bucketNItems = bucketData.size() / recSz;
            const uint64_t recNumBucketBase = recordNumBucketBase(lastRecNum);

            if (recNumBucketBase + bucketNItems != meta.nRecs)
                throw Error(QString("%1: Database corruption possible for DB %2 -- number of records in column family seems to mistmatch metadata. Expected: %3, got: %4").arg(__func__, dbName)
                                .arg(meta.nRecs).arg(recNumBucketBase + bucketNItems));
        } else {
            // we have no records, we expect the last row to be the first row (the metadata entry)
            if (iter->key().compare(rocksdb::Slice(kMetaDataKey)) != 0)
                throw Error(QString("%1: Unrecognized DB format for %2 -- when nRecs==0, the only row must be the metadata entry!").arg(__func__, dbName));
        }

        // It is sane, set nRecs
        nRecs = meta.nRecs;
    } else {
        // New DB, write meta
        isNew = true;
        rocksdb::WriteBatch batch;
        writeMeta(batch, &meta);
        db.Write(wopts, &batch);
    }
    Debug() << (isNew ? "Wrote" : "Read") << " metadata " << (isNew ? "to" : "from") << " DB " << dbName
            << ", magic: " << meta.magic << ", recordSize: " << meta.recSz << ", bucketNRecs: " << meta.bucketNRecs;
}

void DBRecordArray::writeMeta(rocksdb::WriteBatch &batch, MetaData *metaOut) const
{
    MetaData meta(*this);
    if (auto s = batch.Put(&cf, kMetaDataKey, meta.toBytes()); !s.ok()) {
        throw Error(QString("%1: failed to write metadata for DB %2, error: %3").arg(__func__, name(), QString::fromStdString(s.ToString())));
    }
    if (metaOut) *metaOut = meta;
}

bool DBRecordArray::BatchWriteContext::append(const ByteView &data, QString *errStr)
{
    if (data.size() != d.recSz) [[unlikely]] {
        if (errStr) *errStr = QString("Usage error for %1. Bad write: %2 != %3!").arg(d.name()).arg(data.size()).arg(d.recSz);
        return false;
    }
    const uint64_t recNum = d.nRecs++;
    const uint64_t bucketNum = d.recordNumToBucketNum(recNum);
    if (!lastWrite || lastWrite->bucketNum != bucketNum) {
        lastWrite.emplace(bucketNum, std::string{makeKey(bucketNum).byteView().toStringView()});
    }
    const auto st = batch.Merge(&d.cf, lastWrite->bucketKey, data.toStringView());
    if (!st.ok()) [[unlikely]] {
        if (errStr) *errStr = QString("DB error for %1. batch.Merge() error: %2").arg(d.name(), QString::fromStdString(st.ToString()));
        return false;
    }
    dirty = true;
    return true;
}

uint64_t DBRecordArray::BatchWriteContext::truncate(uint64_t newNumRecords, QString *errStr)
{
    if (newNumRecords < d.nRecs) {
        uint64_t firstBucketNum = d.recordNumToBucketNum(newNumRecords);
        bool hadError = false;
        if (const uint64_t endOffset = d.recordNumOffsetFromBucketBase(newNumRecords); endOffset > 0u) {
            // We read-modify-write because newNumRecords fell inside a bucket
            std::string val;
            const VarIntBE varIntKey = d.makeKey(firstBucketNum);
            const rocksdb::Slice key{varIntKey.byteView().toStringView()};
            if (auto st = d.db.Get(d.ropts, &d.cf, key, &val); !st.ok()) { // read in the current bucket
                if (errStr) *errStr = QString("DB error for %1. Get returned error: %2").arg(d.name(), QString::fromStdString(st.ToString()));
                hadError = true;
            } else if (val.size() <= endOffset) {
                if (errStr) *errStr = QString("DB error for %1. Possible corruption because value's size (%2) for bucketNum %3 is less tha expected (%4)")
                                          .arg(d.name()).arg(val.size()).arg(firstBucketNum).arg(endOffset);
                hadError = true;
            } else {
                // no errors, truncate the bucket, and write it back
                val.resize(endOffset);
                st = batch.Put(&d.cf, key, val);
                if (!st.ok()) {
                    if (errStr) *errStr = QString("DB error for %1. Get returned error: %2").arg(d.name(), QString::fromStdString(st.ToString()));
                    hadError = true;
                } else {
                    dirty = true;
                }
            }

            ++firstBucketNum; // we delete everything forward of the *NEXT* bucket.
        }
        if (!hadError) {
            const VarIntBE firstVarIntKey = d.makeKey(firstBucketNum);
            const rocksdb::Slice firstBucketKey{firstVarIntKey.byteView().toStringView()};
            const std::string pastTheEndKey = std::string(sizeof(uint64_t) + 2u, '\xff'); // 10 * 0xff should be larger than any key in the DB
            const auto st = batch.DeleteRange(&d.cf, firstBucketKey, pastTheEndKey);
            if (!st.ok()) {
                if (errStr) *errStr = QString("DB error for %1. batch.DeleteRange() error: %2").arg(d.name(), QString::fromStdString(st.ToString()));
            } else {
                d.nRecs = newNumRecords;
                dirty = true;
            }
        }
    }
    return d.nRecs;
}

DBRecordArray::BatchWriteContext::~BatchWriteContext()
{
    if (dirty) {
        d.writeMeta(batch);
    }
}

QByteArray DBRecordArray::readRandomCommon(const uint64_t recNum, std::optional<LastRead> *lastRead, QString *errStr) const
{
    QByteArray ret;
    if (auto nr = nRecs.load(); recNum < nr) {
        const uint64_t bucketNum = recordNumToBucketNum(recNum);
        const size_t offset = recordNumOffsetFromBucketBase(recNum);
        const bool useCached = lastRead && *lastRead && (*lastRead)->bucketNum == bucketNum;
        if (!useCached) {
            // no cached value, read bucket from db
            const VarIntBE varIntKey = makeKey(bucketNum);
            const std::string_view key{varIntKey.byteView().toStringView()};
            std::string value;
            const auto st = db.Get(ropts, &cf, key, &value);
            if (st.ok()) {
                if (offset + recSz <= value.size()) {
                    // read ok, set ret
                    ret = QByteArray(value.data() + offset, static_cast<QByteArray::size_type>(recSz));
                    // cache DB read for subsequent calls to the same bucket
                    if (lastRead)  lastRead->emplace(bucketNum, std::string{key}, std::move(value));
                } else if (errStr)
                    *errStr = QString("DB error for %1. Record number %2 is missing from the DB data blob!").arg(name()).arg(recNum);
            } else if (errStr)
                *errStr = QString("DB error for %1. %2").arg(name(), QString::fromStdString(st.ToString()));
        } else {
            // read cached
            const std::string &value = (*lastRead)->bucketValue;
            if (offset + recSz <= value.size()) {
                // read ok, set ret
                ret = QByteArray(value.data() + offset, static_cast<QByteArray::size_type>(recSz));
            } else if (errStr)
                *errStr = QString("DB error for %1. Record number %2 is missing from the cached DB data blob!").arg(name()).arg(recNum);
        }
    } else if (errStr)
        *errStr = QString("DB error for %1. Record number %2 out of range (nRecs = %3)").arg(name()).arg(recNum).arg(nr);
    return ret;
}

QByteArray DBRecordArray::readRecord(const uint64_t recNum, QString *errStr) const
{
    std::shared_lock g(rwlock);
    return readRandomCommon(recNum, nullptr, errStr);
}

std::vector<QByteArray> DBRecordArray::readRecords(const uint64_t recNumStart, size_t count, QString *errStr) const
{
    std::shared_lock g(rwlock);
    std::vector<QByteArray> ret;
    const uint64_t nR = nRecs.load();
    count = nR > recNumStart ? std::min(count, static_cast<size_t>(nR-recNumStart)) : 0u;
    if (!count) {
        if (errStr) *errStr = "readRecords specification is out of range";
        return ret;
    }
    ret.reserve(count);
    std::optional<LastRead> cachedLastRead;
    for (uint64_t recNum = recNumStart; recNum < nR && count; --count, ++recNum) {
        ret.emplace_back(readRandomCommon(recNum, &cachedLastRead, errStr));
        if (static_cast<size_t>(ret.back().size()) != recSz) {
            if (errStr)
                *errStr = QString("Unable to read record %1 from DB %2 (error was: '%3')")
                              .arg(recNum).arg(name(), *errStr);
            ret.pop_back();
            break;
        }
    }
    return ret;
}

std::vector<QByteArray> DBRecordArray::readRandomRecords(const std::vector<uint64_t> & recNums, QString *errStr, bool continueOnError) const
{
    std::multimap<uint64_t, size_t> recNumIndices; // maps recNum -> index in `recNums`
    // create sorted map -- we do this to use readRandomCommon() in order for a hopeful performance boost
    for (size_t i = 0, rsz = recNums.size(); i < rsz; ++i)
        recNumIndices.emplace(recNums[i], i);
    std::vector<QByteArray> ret(recNums.size(), QByteArray{}); // pre-sized

    std::optional<LastRead> cachedLastRead;
    struct Last {
        uint64_t recNum;
        QByteArray data;
        Last(uint64_t r, const QByteArray &d) : recNum{r}, data{d} {}
    };
    std::optional<Last> lastRecNum;
    bool doErrorCleanup = false;

    // take a lock only after allocating all of the above
    std::shared_lock g(rwlock);
    for (const auto & [recNum, index] : recNumIndices) {
        if (lastRecNum && lastRecNum->recNum == recNum) {
            // dupe recNum in caller array, just use Last value
            ret[index] = std::as_const(lastRecNum->data);
            continue;
        }
        // do read, leveraging that we are reading records in order and that we are using cachedLastRead for speed
        const QByteArray &data = ret[index] = readRandomCommon(recNum, &cachedLastRead, errStr);

        // oops, we got an error.. mark the doErrorCleanup flag .. but we cannot break out of loop yet because
        // we must continue the request since some items at beginning of `ret` array may end up with valid results in
        // them. Instead, we truncate `ret` in the !continueOnError case at the end of this function.. :/
        if (data.isEmpty() && !continueOnError) [[unlikely]] {
            doErrorCleanup = true;
        }

        // cache last recNum to extra speed boost on duplicated recNums
        if (!lastRecNum)
            lastRecNum.emplace(recNum, data);
        else if (lastRecNum->recNum != recNum) {
            lastRecNum->recNum = recNum;
            lastRecNum->data = data;
        }
    }
    if (doErrorCleanup) [[unlikely]] {
        // !continueOnError -> figure out where the first blank spot is in the return and truncate, then return
        for (size_t i = 0; i < ret.size(); ++i) {
            if (ret[i].isEmpty()) {
                ret.resize(i);
                break;
            }
        }
    }
    return ret;
}

std::unique_ptr<rocksdb::Iterator> DBRecordArray::seekToFirstBucket() const
{
    std::unique_ptr<rocksdb::Iterator> iter(db.NewIterator(ropts, &cf));
    if (!iter) [[unlikely]] throw Error(QString("%1: rocksdb returned a nullptr iterator").arg(__func__));
    iter->Seek(makeKey(0).byteView().toStringView());
    return iter;
}

/* static */
uint64_t DBRecordArray::bucketNumFromDbKey(const ByteView &key)
{
    try {
        const VarIntBE v = VarIntBE::fromBytes(key);
        return v.value<uint64_t>();
    } catch (const std::exception &e) {
        throw Error(QString("%1: error in parsing db key (%2): %3")
                        .arg(__func__, QString::fromLatin1(ByteView{key}.toByteArray(false).toHex()), e.what()));
    }
}

#ifdef ENABLE_TESTS
#include "tests/Tests.h"
#include <QTemporaryDir>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <type_traits>
#include <vector>

TEST_SUITE(dbrecordarray)

QTemporaryDir tmpDir(APPNAME "_XXXXXX.tmp");
tmpDir.setAutoRemove(true);
std::vector<QByteArray> hashes;
constexpr size_t HashLen = 32;
constexpr size_t N = 100'000; // 100k items
constexpr size_t BUCKET_SIZE = 16;
auto DbDeleter = [](rocksdb::DB *db) { if (db) { db->Close(); delete db; } };
std::unique_ptr<rocksdb::DB, decltype(DbDeleter)> db;
rocksdb::ColumnFamilyHandle *cf{}; // points into db above
std::optional<DBRecordArray> dba;
Tic t0;

TEST_CASE(gen_hashes) {
    Log() << "Testing DBRecordArray in dir \"" << tmpDir.path() << "\" with " << N << " " << HashLen << "-byte random records ...";

    hashes.assign(N, QByteArray(HashLen, Qt::Uninitialized));
    // randomize hashes
    QByteArray *lastH = nullptr;
    for (auto & h : hashes) {
        GetRandBytes(h.data(), h.size());
        TEST_CHECK_MESSAGE(!lastH || *lastH != h, "Something went wrong generating random hashes.. previous hash and this hash match!");
        lastH = &h;
    }
};

TEST_CASE(open_db) {
    TEST_CHECK(tmpDir.isValid());
    rocksdb::DB *dbptr{};
    rocksdb::Options opts;
    opts.create_if_missing = true;
    opts.merge_operator.reset(new StorageDetail::ConcatOperator);
    auto st = rocksdb::DB::Open(opts, tmpDir.path().toStdString(), &dbptr);
    TEST_CHECK_MESSAGE(st.ok(), st.ToString());
    db.reset(dbptr);
    TEST_CHECK(db != nullptr);
    if (!db) throw Exception("DB pointer is null! Cannot proceed!");
    cf = db->DefaultColumnFamily();
};

TEST_CASE(batch_append) {
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE);
    rocksdb::WriteBatch batch;
    {
        auto ctx = dba->beginBatchWrite(batch);
        QString err;
        for (const auto & h : hashes)
            TEST_CHECK_MESSAGE(ctx.append(h, &err),
                               QString("Failed to append a record using batch append to DBRecordArray: %1").arg(err).toStdString());
    }
    auto st = db->Write({}, &batch);
    TEST_CHECK(st.ok());
    TEST_CHECK(db->FlushWAL(true).ok());
    TEST_CHECK(dba->numRecords() == N);
    Log() << "Wrote " << dba->numRecords() << " hahses";
};

// Read 1 record at a time randomly from 3 threads concurrently
TEST_CASE(threaded_read) {
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    std::vector<std::thread> thrds;
    TEST_CHECK(dba->numRecords() == N);
    std::atomic_size_t ctr{0};
    QString fail_shared;
    std::mutex fail_shared_mut;
    for (size_t i = 0; i < 3; ++i) {
        thrds.emplace_back([&]{
            QString fail;
            for (size_t i = 0; fail.isEmpty() && i < hashes.size() * 7 / 20; ++i) {
                size_t idx = InsecureRandRange(hashes.size());
                TEST_CHECK(dba->readRecord(idx, &fail) == hashes[idx]);
                ++ctr;
            }
            if (!fail.isEmpty()) {
                std::unique_lock l(fail_shared_mut);
                fail_shared = fail;
            }
        });
    }
    for (auto & t : thrds) t.join();
    if (!fail_shared.isEmpty()) throw Exception(fail_shared);
    Log() << "Read " << ctr.load() << " individual records randomly using " << thrds.size() << " concurrent threads";
};

// Read 1000 records at a time randomly from 3 threads concurrently
TEST_CASE(threaded_read_bulk) {
    std::vector<std::thread> thrds;
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    TEST_CHECK(dba->numRecords() == N);
    std::atomic_size_t ctr{0};
    QString fail_shared;
    std::mutex fail_shared_mut;
    for (size_t i = 0; i < 3; ++i) {
        thrds.emplace_back([&]{
            QString fail;
            constexpr size_t NBatch = 1000;
            for (size_t i = 0; fail.isEmpty() && i < hashes.size() * 2; i += NBatch) {
                std::vector<uint64_t> recNums(NBatch);
                for (size_t j = 0; fail.isEmpty() && j < NBatch; ++j) {
                    size_t idx = InsecureRandRange(N);
                    recNums[j] = idx;
                    ++ctr;
                }
                const auto results = dba->readRandomRecords(recNums, &fail, false);
                TEST_CHECK(results.size() == recNums.size());
                if (results.size() != recNums.size())
                    fail = QString("Failed to read random records: ") + fail;
                for (size_t i = 0; fail.isEmpty() && i < results.size(); ++i) {
                    TEST_CHECK(results[i]== hashes[recNums[i]]);
                    if (results[i] != hashes[recNums[i]])
                        fail = QString("Record #%1, index %2 failed to compare equal!").arg(i).arg(recNums[i]);
                }
            }
            if (!fail.isEmpty()) {
                std::unique_lock l(fail_shared_mut);
                fail_shared = fail;
            }
        });
    }
    for (auto & t : thrds) t.join();
    if (!fail_shared.isEmpty()) throw Exception(fail_shared);
    Log() << "Read " << ctr.load() << " batched records randomly using " << thrds.size() << " concurrent threads";
};

TEST_CASE(truncate_half) {
    // truncate to N / 2, and verify
    {
        rocksdb::WriteBatch batch;
        dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
        {
            auto ctx = dba->beginBatchWrite(batch);
            QString err;
            TEST_CHECK(ctx.truncate(hashes.size() / 2, &err) == hashes.size() / 2);
            if (!err.isEmpty()) throw Exception(err);
        }
        TEST_CHECK(db->Write({}, &batch).ok());
    }
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    TEST_CHECK(dba->numRecords() == hashes.size() / 2);
    QString fail;
    const auto results = dba->readRecords(0, hashes.size() / 2, &fail);
    if (!fail.isEmpty()) throw Exception(QString("Failed to verify truncated data: %1").arg(fail));
    TEST_CHECK(results.size() == hashes.size() / 2);
    for (size_t i = 0; i < results.size(); ++i)
        TEST_CHECK(results.at(i) == hashes.at(i));
    Log() << "Truncated file to size " << dba->numRecords() << " and verified";
};

// truncate the file to 0, then write N / 10 records using single-append calls and verify
TEST_CASE(truncate_tenth) {
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    {
        rocksdb::WriteBatch batch;
        {
            auto ctx = dba->beginBatchWrite(batch);
            QString err;
            TEST_CHECK(ctx.truncate(0, &err) == 0);
            if (!err.isEmpty()) throw Exception(err);
        }
        TEST_CHECK(db->Write({}, &batch).ok());
    }
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    TEST_CHECK(dba->numRecords() == 0);
    const auto NN = hashes.size() / 10;
    {
        rocksdb::WriteBatch batch;
        {
            auto ctx = dba->beginBatchWrite(batch);
            for (size_t i = 0; i < NN; ++i) {
                QString err;
                const auto res = ctx.append(hashes[i], &err);
                TEST_CHECK(res);
                TEST_CHECK(dba->numRecords() == i + 1);
                if (!err.isEmpty())
                    throw Exception(QString("Failed to append record %1: %2").arg(i).arg(err));
            }
        }
        TEST_CHECK(db->Write({}, &batch).ok());
    }
    dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); // re-open
    QString fail;
    const auto results = dba->readRecords(0, NN, &fail);
    TEST_CHECK(results.size() == NN);
    if (!fail.isEmpty()) throw Exception(QString("Failed to verify truncated data: %1").arg(fail));
    for (size_t i = 0; i < results.size(); ++i)
        TEST_CHECK(results.at(i) == hashes.at(i));
    Log() << "Truncated file to size 0, appended using single-append calls to size " << dba->numRecords() << ", and verified";
};

TEST_CASE(exceptions) {
    // try mismatch on recSz
    static_assert (!std::is_base_of_v<DBRecordArray::Error, Exception>); // to ensure below works.. this is obviously always the case
    dba.reset(); // close so below code runs.. to be paranoid in case invatiants change
    // re-open on scope end
    Defer d([&]{ dba.emplace(*db, *cf, HashLen, BUCKET_SIZE); });

    TEST_CHECK_NO_THROW(DBRecordArray(*db, *cf, HashLen /* good recsz */, BUCKET_SIZE));
    TEST_CHECK_THROW(DBRecordArray(*db, *cf, HashLen + 1 /* bad recsz */, BUCKET_SIZE), DBRecordArray::Error);
    TEST_CHECK_THROW(DBRecordArray(*db, *cf, HashLen, BUCKET_SIZE, 0x42 /* bad magic*/), DBRecordArray::Error);
    TEST_CHECK_THROW(DBRecordArray(*db, *cf, HashLen, BUCKET_SIZE + 1 /* non POT bucketSz */), DBRecordArray::Error);
    TEST_CHECK_THROW(DBRecordArray(*db, *cf, HashLen, BUCKET_SIZE*2 /* mismatched bucketSz */), DBRecordArray::Error);
    TEST_CHECK_THROW(DBRecordArray(*db, *cf, HashLen, BUCKET_SIZE/2 /* mismatched bucketSz */), DBRecordArray::Error);
};

TEST_SUITE_END()
#endif
