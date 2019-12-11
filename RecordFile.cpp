#include "RecordFile.h"
#include "Util.h"

RecordFile::FileError::~FileError() {} // prevent weak vtable warning
RecordFile::FileFormatError::~FileFormatError() {} // prevent weak vtable warning
RecordFile::FileOpenError::~FileOpenError() {} // prevent weak vtable warning

RecordFile::RecordFile(const QString &fileName_, size_t recordSize_, uint32_t magicBytes_) noexcept(false)
    : recsz(recordSize_), magic(magicBytes_), file(fileName_)
{
    if (recsz == 0)
        throw BadArgs("Record size cannot be 0!");
    if (!file.open(QIODevice::ReadWrite)) {
        throw FileOpenError(QString("Cannot open file %1: %2").arg(fileName_).arg(file.errorString()));
    }
    if (file.size() < qint64(hdrsz)) {
        if (file.size() != 0) {
            throw FileFormatError("Bad file header");
        }
        // new file, write header
        file.seek(0);
        const uint64_t N = nrecs = 0;
        if (file.write(QByteArray::fromRawData(reinterpret_cast<const char *>(&magic), sizeof(magic))) != sizeof(magic)
                || file.write(QByteArray::fromRawData(reinterpret_cast<const char *>(&N), sizeof(N))) != sizeof(N)) {
            throw FileError(QString("Failed to write header: %1").arg(file.errorString()));
        }
    } else {
        // existing file, check header
        file.seek(0);
        uint32_t tmpMagic = 0;
        uint64_t tmpNRecs = 0;
        if (file.read(reinterpret_cast<char *>(&tmpMagic), sizeof(tmpMagic)) != sizeof(tmpMagic)
                || file.read(reinterpret_cast<char *>(&tmpNRecs), sizeof(tmpNRecs)) != sizeof(tmpNRecs)) {
            throw FileFormatError(QString("Failed to read header: %1").arg(file.errorString()));
        }
        if (tmpMagic != magic) {
            throw FileFormatError("Bad magic in header");
        }
        if (qint64(tmpNRecs*recsz + hdrsz) != file.size()) {
            throw FileFormatError("File size does is not a multiple of recordSize");
        }
        nrecs = tmpNRecs; // store num records since everything checks out.
    }
}

RecordFile::~RecordFile() {}

QByteArray RecordFile::readRandomCommon(QFile & f, uint64_t recNum, QString *errStr) const
{
    QByteArray ret;
    if (!f.seek(offsetOfRec(recNum)) || (ret = f.read(qint64(recsz))).length() != int(recsz)) {
        if (errStr)
            *errStr = QString("Unable to read record %1 from file %2 (error was: '%3')")
                             .arg(recNum).arg(f.fileName()).arg(f.errorString());
        ret.clear();
    }
    return ret;
}

QByteArray RecordFile::readRecord(uint64_t recNum, QString *errStr) const
{
    std::shared_lock g(rwlock);
    QByteArray ret;
    if (recNum < nrecs) {
        QFile f(fileName());
        if (!f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly)) {
            if (errStr) *errStr = QString("Unable to open file %1 (error was: '%2')")
                                         .arg(f.fileName()).arg(f.errorString());
        } else
            ret = readRandomCommon(f, recNum, errStr);
    }
    return ret;
}

std::vector<QByteArray> RecordFile::readRandomRecords(const std::vector<uint64_t> & recNums, QString *errStr) const
{
    std::shared_lock g(rwlock);
    std::vector<QByteArray> ret;
    ret.reserve(recNums.size());
    QFile f(fileName());
    if (!f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly)) {
        if (errStr) *errStr = QString("Unable to open file %1 (error was: '%2')").arg(fileName()).arg(f.errorString());
    } else {
        // good status
        for (const auto recNum : recNums) {
            if (recNum >= nrecs) {
                if (errStr) *errStr = QString("%1 is outside the record file, which only contains %2 records").arg(recNum).arg(nrecs);
                break;
            }
            ret.emplace_back(readRandomCommon(f, recNum, errStr));
            if (ret.back().isEmpty()) {
                ret.pop_back();
                break;
            }
        }
    }
    ret.shrink_to_fit();
    return ret;
}

std::vector<QByteArray> RecordFile::readRecords(uint64_t recNumStart, size_t count, QString *errStr) const
{
    std::shared_lock g(rwlock);
    std::vector<QByteArray> ret;
    count = nrecs > recNumStart ? std::min(count, size_t(nrecs-recNumStart)) : 0;
    if (!count) {
        if (errStr) *errStr = "Out of readRecords specification is out of range";
        return ret;
    }
    QFile f(fileName());
    if (!f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly) || !f.seek(offsetOfRec(recNumStart))) {
        if (errStr) *errStr = QString("Unable to open or seek in file %1 (error was: '%2')").arg(fileName()).arg(f.errorString());
        return ret;
    }
    ret.reserve(count);
    for (auto recNum = recNumStart; recNum < nrecs && count; --count, ++recNum) {
        ret.emplace_back(f.read(qint64(recsz)));
        if (size_t(ret.back().length()) != recsz) {
            if (errStr)
                *errStr = QString("Unable to read record %1 from file %2 (error was: '%3')")
                                 .arg(recNum).arg(f.fileName()).arg(f.errorString());
            ret.pop_back();
            break;
        }
    }
    ret.shrink_to_fit();
    return ret;
}

uint64_t RecordFile::truncate(uint64_t newNRecs, QString *errStr)
{
    if (newNRecs >= nrecs) {
        return nrecs;
    }
    std::lock_guard g(rwlock);
    if ( !file.resize(offsetOfRec(newNRecs)) ) {
        if (errStr) *errStr = QString("Failed to truncate file to %1: %2").arg(newNRecs).arg(file.errorString());
        return nrecs;
    }
    nrecs = newNRecs;
    if (!writeNewSizeToHeader(errStr))
        return 0;
    return nrecs;
}

std::optional<uint64_t> RecordFile::appendRecord(const QByteArray &data, bool updateHeader, QString *errStr)
{
    std::lock_guard g(rwlock);
    std::optional<uint64_t> ret;

    if (UNLIKELY(data.length() != int(recsz))) {
        if (errStr) *errStr = QString("Expected data of length %1, instead got data of length %2").arg(recsz).arg(data.length());
    } else if (const auto newNRecs = ++nrecs; !file.seek(offsetOfRec(newNRecs-1))) {
        if (errStr) *errStr = QString("Cannot seek to write record %1 (%2)").arg(newNRecs-1).arg(file.errorString());
    } else if (file.write(data) != data.length()) {
        if (errStr) *errStr = QString("Short write (%1)").arg(file.errorString());
    } else if (updateHeader && !writeNewSizeToHeader(errStr)) {
        // error string already populated properly by writeNewSizeToHeader
    } else {
        // everything ok
        ret.emplace(newNRecs-1);
    }
    return ret;
}

auto RecordFile::beginBatchAppend() -> BatchAppendContext
{
    return BatchAppendContext(*this);
}

RecordFile::BatchAppendContext::BatchAppendContext(RecordFile &rf_)
    : rf(rf_), lock(rf.rwlock)
{
    if (!rf.file.isOpen() || rf.file.size() != qint64(hdrsz + rf.nrecs.load()*rf.recsz)
            /* seek to end of file here with lock held */
            || !rf.file.seek(rf.file.size()))
        throw FileError(QString("Error in BatchAppendContext constructor, file is not open or seek failure (%1)").arg(rf.file.errorString()));
}

bool RecordFile::BatchAppendContext::append(const QByteArray &data, QString *errStr)
{
    if (qint64 dlen = data.length(); dlen != qint64(rf.recsz) || rf.file.write(data) != dlen) {
        if (errStr) *errStr = QString("Short write (%1)").arg(rf.file.errorString());
        return false;
    }
    ++rf.nrecs;
    return true;
}

bool RecordFile::writeNewSizeToHeader(QString *errStr)
{
    bool ret = false;
    if (UNLIKELY(!file.isOpen())) {
        if (errStr) *errStr = "File not open";
    } else if (!file.seek(offsetOfNRecs())) {
        if (errStr) *errStr = QString("Cannot seek to write header for %1").arg(file.fileName());
    } else if (const uint64_t newNRecs = nrecs.load();
                !file.write(QByteArray::fromRawData(reinterpret_cast<const char *>(&newNRecs), sizeof(newNRecs)))) {
        if (errStr) *errStr = QString("Cannot write header for %1: %2").arg(file.fileName()).arg(file.errorString());
    } else if (size_t(file.size()) != hdrsz + recsz*newNRecs) {
        if (errStr)
            *errStr = QString("File size mistmatch for %1, %2 is not a multiple of %3 (+ %4 header). File is now likely corrupted.")
                      .arg(file.fileName()).arg(file.size()).arg(recsz).arg(hdrsz);
    } else { ret = true; }
    return ret;
}

RecordFile::BatchAppendContext::~BatchAppendContext()
{
    // updates the header with the new count, does some checks, releases lock
    QString errStr;
    rf.writeNewSizeToHeader(&errStr);
    if (!errStr.isEmpty())
        Fatal() << errStr; // app will quit in main event loop after printing error.
}
