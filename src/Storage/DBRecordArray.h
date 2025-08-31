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
#pragma once

#include "ByteView.h"
#include "Common.h"

#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/write_batch.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>

class DBRecordArray
{
    mutable std::shared_mutex rwlock;
    rocksdb::DB &db;
    rocksdb::ColumnFamilyHandle &cf;
    const rocksdb::ReadOptions ropts; // to avoid re-creating these every time
    const rocksdb::WriteOptions wopts;

    const size_t recSz;
    const size_t bucketNRecs;
    const uint32_t magic;
    const uint8_t bucketShiftAmt;
    std::atomic_uint64_t nRecs{0u};

    struct MetaData;

    void readOrInitMeta();
    void writeMeta(rocksdb::WriteBatch &batch, MetaData *metaOut = nullptr) const;

    static std::string makeKey(uint64_t bucketNum);

    inline uint64_t recordNumToBucketNum(uint64_t recNum) const { return recNum >> bucketShiftAmt; }
    inline uint64_t recordNumBucketBase(uint64_t recNum) const { return recordNumToBucketNum(recNum) << bucketShiftAmt; }
    inline size_t recordNumOffsetFromBucketBase(uint64_t recNum) const {
        return recSz * (recNum - recordNumBucketBase(recNum));
    }

    struct LastRead {
        uint64_t bucketNum{};
        std::string bucketKey;
        std::string bucketValue;
        LastRead() = default;
        LastRead(uint64_t bn, std::string &&key, std::string &&value) : bucketNum{bn}, bucketKey{std::move(key)}, bucketValue{std::move(value)} {}
    };

    QByteArray readRandomCommon(uint64_t recNum, std::optional<LastRead> *lastRead = nullptr, QString *errStr = nullptr) const;

public:

    struct Error : Exception { using Exception::Exception; ~Error() override; };

    // Note: This may throw an "Error" subclass on sanity check failure. `db` and `cf` must outlive the lifetime of this instance.
    // Note 2: `bucketNRecsPOT` must be a non-zero power of 2 such as 2, 4, 16, 64, 256, etc, otherwise this throws.
    DBRecordArray(rocksdb::DB &db, rocksdb::ColumnFamilyHandle &cf, uint32_t recordSize, uint32_t bucketNRecsPOT,
                  uint32_t magicBytes = 0x002367f0) noexcept(false);

    // Prevent copy construct and copy-assign
    DBRecordArray(const DBRecordArray &) = delete;
    DBRecordArray & operator=(const DBRecordArray &) = delete;

    size_t recordSize() const { return recSz; }
    uint32_t magicBytes() const { return magic; }
    QString name() const;
    uint64_t numRecords() const { return nRecs.load(); }
    size_t bucketNumRecords() const { return bucketNRecs; }

    /// Thread-safe.  The first record is recNum = 0, the second is recNum = 1. Returns a QByteArray of size recsz or
    /// an empty QByteArray on error.
    QByteArray readRecord(uint64_t recNum, QString *errStr = nullptr) const;

    /// Thread-safe. Like the above but does a batch read of count records sequantially starting at recNumStart.
    /// If the returned vector is not 'count' sized, either not enough records exist in the file or an error occurred
    /// (and *errStr will contain the error message).
    std::vector<QByteArray> readRecords(uint64_t recNumStart, size_t count, QString *errStr = nullptr) const;


    /// Thread-safe. Under non-error circumstances, the returned array will be of the same size as the recNums array,
    /// with corresponding indices containing the data obtained per recNum. On error the returned array will be shorter
    /// than anticipated and *errStr (if specified) will be set appropriately. Note that the recNums array is not
    /// "de-duplicated".
    ///
    /// New: If `continueOnError` is true, the returned vector will always be sized exactly the same as recNums.
    /// Any errors encountered will simply have empty QByteArrays inserted into the resulting vector. *errStr
    /// will be the last error encountered if there are errors.
    std::vector<QByteArray> readRandomRecords(const std::vector<uint64_t> & recNums, QString *errStr = nullptr,
                                              bool continueOnError = false) const;

    class BatchWriteContext {
        DBRecordArray & d;
        rocksdb::WriteBatch & batch;
        std::unique_lock<std::shared_mutex> lock;
        // internal use. Used by DBRecordArray::beginBatchAppend
        BatchWriteContext(DBRecordArray &d, rocksdb::WriteBatch &batch) : d{d}, batch{batch}, lock{d.rwlock} {}
        friend class ::DBRecordArray;

        struct LastWrite {
            uint64_t bucketNum{};
            std::string bucketKey;
            LastWrite(uint64_t bn, std::string &&bk) : bucketNum{bn}, bucketKey{std::move(bk)} {}
        };
        std::optional<LastWrite> lastWrite;
        bool dirty = false;
    public:
        /// Updates this class and the metadata with the new nrecs count, does some checks (may quit app with Fatal() if checks fail), releases lock
        ~BatchWriteContext();
        /// Append a record to the end of the file. Does not write to the metadata until d'tor is called (at which
        /// point the record count is updated in the db by issuing a batch.Write()). Returns false on error.
        bool append(const ByteView &data, QString *errStr = nullptr);

        /// Truncate the DB array to contain std::min(numRecords(), newNumRecords). In other words, deletes every record
        /// with recNum >= newNumRecords. Returns the new numRecords() of the file (under non-error circumstances this
        /// should be identical to the supplied argument, newNumRecords).
        uint64_t truncate(uint64_t newNumRecords, QString *errStr = nullptr);
    };

    /// Returns a locking context. Use context.append() to write batches of records to the end of the DB.
    /// The locked context is released on BatchWriteContext destruction (at which time the metaData is also updated
    /// to reflect the new counts).
    BatchWriteContext beginBatchWrite(rocksdb::WriteBatch &batch) { return BatchWriteContext(*this, batch); }

    friend class DBRecordArray::BatchWriteContext;
};
