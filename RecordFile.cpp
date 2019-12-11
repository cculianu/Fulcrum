#include "RecordFile.h"
#include "Util.h"

RecordFile::FileError::~FileError() {} // prevent weak vtable warning
RecordFile::FileFormatError::~FileFormatError() {} // prevent weak vtable warning
RecordFile::FileOpenError::~FileOpenError() {} // prevent weak vtable warning

RecordFile::RecordFile(const QString &fileName_, size_t recordSize_, uint32_t magicBytes_) noexcept(false)
    : recsz(recordSize_), magic(magicBytes_), file(fileName_)
{
    if (!file.open(QIODevice::ReadWrite)) {
        throw FileOpenError(QString("Cannot open file %1: %2").arg(fileName_).arg(file.errorString()));
    }
    if (file.size() < qint64(hdrsz)) {
        if (file.size() != 0) {
            throw FileFormatError("Bad file header");
        }
        // new file, write header
        file.seek(0);
        const auto N = nrecs.load(); //
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


QByteArray RecordFile::readRecord(uint64_t recNum) const
{
    std::shared_lock g(rwlock);
    QByteArray ret;
    if (recNum < nrecs) {
        QFile f(fileName());
        if (QByteArray tmp; f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly)
                && f.seek(offsetOfRec(recNum)) && (tmp = f.read(qint64(recsz))).length() == int(recsz)) {
            ret = tmp;
        } else {
            Warning() << "Unable to open and/or read file " << fileName() << " for reading (error was: '" << f.errorString() << "') in " << __func__;
        }
    }
    return ret;
}

std::optional<uint64_t> RecordFile::appendRecord(const QByteArray &data, QString *errStr)
{
    std::lock_guard g(rwlock);
    std::optional<uint64_t> ret;
    if (UNLIKELY(data.length() != int(recsz))) {
        if (errStr) *errStr = QString("Expected data of length %1, instead got data of length %2").arg(recsz).arg(data.length());
    } else if (UNLIKELY(!file.isOpen())) {
        if (errStr) *errStr = "File not open";
    } else if (!file.seek(offsetOfNRecs())) {
        if (errStr) *errStr = "Cannot seek to write header";
    } else if (const auto newNRecs = ++nrecs;
               !file.write(QByteArray::fromRawData(reinterpret_cast<const char *>(&newNRecs), sizeof(newNRecs)))) {
        if (errStr) *errStr = file.errorString();
    } else if (!file.seek(offsetOfRec(newNRecs-1))) {
        if (errStr) *errStr = QString("Cannot seek to write record %1 (%2)").arg(newNRecs-1).arg(file.errorString());
    } else if (file.write(data) != data.length()) {
        if (errStr) *errStr = QString("Short write (%1)").arg(file.errorString());
    } else {
        // everything ok
        ret.emplace(newNRecs-1);
    }
    return ret;
}

