#pragma once

#include "Common.h"

#include <QByteArray>
#include <QFile>
#include <QString>

#include <atomic>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <memory>

/// A low-level class for reading/writing fixed-sized records indexed by an index number.  Basically, this is a
/// file-backed array.  We do it this way to save some space in the DB when the key is just a sequential index
/// and there is no sense in storing it.  Used by Storage for the TxNum -> TxHash map, for instance.
class RecordFile
{
public:
    struct FileError : public Exception { using Exception::Exception; ~FileError() override; };
    struct FileFormatError : public FileError { using FileError::FileError; ~FileFormatError() override; };
    struct FileOpenError : public FileError { using FileError::FileError; ~FileOpenError() override; };

    /// Throws Exception (typically one of the above Exceptions) if it cannot open fileName, or if filename was opened
    /// but doesn't seem cromulent (bad magic, bad size, etc).
    /// Note 'fileName' will be created if it does not already exist and initialized with the magicBytes and header.
    RecordFile(const QString &fileName, size_t recordSize, uint32_t magicBytes = 0x002367f0) noexcept(false);
    ~RecordFile();

    size_t recordSize() const { return recsz; }
    uint32_t magicBytes() const { return magic; }
    QString fileName() const { return file.fileName(); /* nb: assumption is file.fileName() is thread-safe */ }

    uint64_t numRecords() const { return nrecs; }

    /// Thread-safe.  Implicitly opens a private copy of the file and reads record number recNum from the file. The
    /// first record is recNum = 0, the second is recNum = 1. Each record is separated by recordSize() bytes in the
    /// file.
    /// Returns a QByteArray of size recsz or an empty QByteArray on error.
    QByteArray readRecord(uint64_t recNum, QString *errStr = nullptr) const;

    /// Thread-safe. Like the above but does a batch read of count records sequantially starting at recNumStart.
    /// If the returned vector is not 'count' sized, either not enough records exist in the file or an error occurred
    /// (and *errStr will contain the error message).
    std::vector<QByteArray> readRecords(uint64_t recNumStart, size_t count, QString *errStr = nullptr) const;

    /// Thread-safe.  Implicitly opens a private copy of the file and reads recNums from the file. Under non-error
    /// circumstances, the returned array will be of the same size as the recNums array, with corresponding indices
    /// containing the data obtained per recNum.  On error the returned array will be shorter than anticipated
    /// and *errStr (if specified) will be set appropriately.  Note that the recNums array is not "de-duplicated".
    std::vector<QByteArray> readRandomRecords(const std::vector<uint64_t> & recNums, QString *errStr = nullptr) const;

    /// Thread-safe, but it does take an exclusive lock.  Appends data to the file. The new record number is returned.
    /// Note that an error leads to an optional with no value being returned.  Data *must* be recordSize() bytes.
    /// Note: updateHeader is a performance optimization. If it's false, we don't write the new number of records
    /// to the header this call. Use this in a loop and specify updateHeader = true for the last iteration as a
    /// performance saving measaure.  For even better performance, consider using the beginBatchAppend() method
    /// which cuts down further on redundant checks (deferring them until the very end when the batch context ends).
    std::optional<uint64_t> appendRecord(const QByteArray &data, bool updateHeader = true, QString *errStr = nullptr);

    /// Deletes every record from the file starting with newNumRecords until the end of the file. Updates the header
    /// and internal counter to reflect the new count.  Returns the new numRecords() of the file (under non-error
    /// circumstances this should be identical to the supplied argument, newNumRecords).
    uint64_t truncate(uint64_t newNumRecords, QString *errStr = nullptr);

    class BatchAppendContext {
        RecordFile & rf;
        std::unique_lock<std::shared_mutex> lock;
        // internal use. Used by RecordFile::beginBatchAppend
        BatchAppendContext(RecordFile &);
        friend class ::RecordFile;
    public:
        /// updates the header with the new count, does some checks (may quit app with Fatal() if checks fail), releases lock
        ~BatchAppendContext();
        /// Append a record to the end of the file. Does not write to the file header until d'tor is called (at which
        /// point the file's record count is updated in the header).
        /// Note that it is imperative that the passed-in data be sized recordSize(). No checks are done as a
        /// performance shortcut!  If you pass in data that is not recsz bytes, the file may be corrupted or the app
        /// may quit with a fatal error.
        bool append(const QByteArray &data, QString *errStr = nullptr);
    };

    /// May throw Exception if the file is in an inconsistent state or if cannot seek (low-level IO error).
    /// Otherwise returnes a locking context. Use context.append() to write batches of records to the end of the file.
    /// The locked context is released on BatchAppendContext destruction (at which time the file's header is also updated
    /// to reflect the new counts).
    BatchAppendContext beginBatchAppend();

    /// Flushes pending writes. Thread-safe. Returns true if the flush succeeds, false otherwise.
    bool flush();

private:
    mutable std::shared_mutex rwlock;
    friend class RecordFile::BatchAppendContext;

    const size_t recsz;
    const uint32_t magic;
    QFile file; ///< this is kept open throughout the lifetime of this instance; and is the instance used to write to the file. readers open up a new QFile each time.
    std::atomic<uint64_t> nrecs = 0;
    std::atomic_bool ok = false;

    static constexpr size_t hdrsz = sizeof(magic) + sizeof(uint64_t);

    static constexpr qint64 offset0() { return hdrsz; }
    static constexpr qint64 offsetOfNRecs() { return sizeof(magic); }
    qint64 offsetOfRec(uint64_t recNum) const { return qint64(offset0() + recNum*recsz); }

    QByteArray readRandomCommon(QFile & f, uint64_t recNum, QString *errStr = nullptr) const;
    bool writeNewSizeToHeader(QString *errStr = nullptr, bool flush = false);
};

