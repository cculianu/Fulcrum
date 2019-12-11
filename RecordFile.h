#pragma once

#include "Common.h"

#include <QByteArray>
#include <QFile>
#include <QString>

#include <atomic>
#include <cstdint>
#include <optional>
#include <shared_mutex>

/// A low-level class for reading/writing fixed-sized records indexed by an index number.  Basically, this is a
/// file-backed array.  We do it this way to save some space in the DB when the key is just a sequential index
/// and there is no sense in storing it.  Used by Storage for the TxNum -> TxHash map, for instance.
class RecordFile
{
public:
    struct FileError : public Exception { using Exception::Exception; ~FileError() override; };
    struct FileFormatError : public FileError { using FileError::FileError; ~FileFormatError() override; };
    struct FileOpenError : public FileError { using FileError::FileError; ~FileOpenError() override; };

    /// Throws Exception if it cannot open fileName, or if filename was opened but doesn't seem cromulent (bad magic, bad size, etc).
    /// Note fileName will be created if it does not already exist and initialized with the magicBytes and header.
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
    QByteArray readRecord(uint64_t recNum) const;

    /// Thread-safe, but it does take an exclusive lock.  Appends data to the file. The new record number is returned.
    /// Note that an error leads to an optional with no value being returned.  Data *must* be recordSize() bytes.
    std::optional<uint64_t> appendRecord(const QByteArray &data, QString *errStr = nullptr);
private:
    mutable std::shared_mutex rwlock;

    const size_t recsz;
    const uint32_t magic;
    QFile file; ///< this is kept open throughout the lifetime of this instance; and is the instance used to write to the file. readers open up a new QFile each time.
    std::atomic<uint64_t> nrecs = 0;
    std::atomic_bool ok = false;

    static constexpr size_t hdrsz = sizeof(magic) + sizeof(uint64_t);

    static constexpr qint64 offset0() { return hdrsz; }
    static constexpr qint64 offsetOfNRecs() { return sizeof(magic); }
    qint64 offsetOfRec(uint64_t recNum) const { return qint64(offset0() + recNum*recsz); }
};

