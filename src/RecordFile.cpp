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
#include "RecordFile.h"
#include "Util.h"

#include <cstdint>

namespace {
// Note we intentionally didn't include "bitcoin/crypto/endian.h" here in order to not depend on the bitcoin lib in
// this class.
    inline bool constexpr isBigEndian() noexcept {
#ifdef WORDS_BIGENDIAN
        return true;
#else
        return false;
#endif
    }
    [[maybe_unused]] [[nodiscard]] inline constexpr uint32_t bswap_32(uint32_t x) noexcept {
        return   ((x & uint32_t{0xff000000u}) >> 24u)
               | ((x & uint32_t{0x00ff0000u}) >>  8u)
               | ((x & uint32_t{0x0000ff00u}) <<  8u)
               | ((x & uint32_t{0x000000ffu}) << 24u);
    }
    [[maybe_unused]] [[nodiscard]] inline constexpr uint64_t bswap_64(uint64_t x) noexcept {
        return   ((x & uint64_t{0xff00000000000000ull}) >> 56ull)
               | ((x & uint64_t{0x00ff000000000000ull}) >> 40ull)
               | ((x & uint64_t{0x0000ff0000000000ull}) >> 24ull)
               | ((x & uint64_t{0x000000ff00000000ull}) >>  8ull)
               | ((x & uint64_t{0x00000000ff000000ull}) <<  8ull)
               | ((x & uint64_t{0x0000000000ff0000ull}) << 24ull)
               | ((x & uint64_t{0x000000000000ff00ull}) << 40ull)
               | ((x & uint64_t{0x00000000000000ffull}) << 56ull);
    }
    [[nodiscard]] inline constexpr uint32_t hToLe32(uint32_t x) noexcept { if constexpr (isBigEndian()) return bswap_32(x); else return x; }
    [[nodiscard]] inline constexpr uint32_t le32ToH(uint32_t x) noexcept { if constexpr (isBigEndian()) return bswap_32(x); else return x; }
    [[nodiscard]] inline constexpr uint64_t hToLe64(uint64_t x) noexcept { if constexpr (isBigEndian()) return bswap_64(x); else return x; }
    [[nodiscard]] inline constexpr uint64_t le64ToH(uint64_t x) noexcept { if constexpr (isBigEndian()) return bswap_64(x); else return x; }
} // namespace

RecordFile::FileError::~FileError() {} // prevent weak vtable warning
RecordFile::FileFormatError::~FileFormatError() {} // prevent weak vtable warning
RecordFile::FileOpenError::~FileOpenError() {} // prevent weak vtable warning

RecordFile::RecordFile(const QString &fileName_, size_t recordSize_, uint32_t magicBytes_) noexcept(false)
    : recsz(recordSize_), magic(magicBytes_), file(fileName_)
{
    if (recsz == 0)
        throw BadArgs("Record size cannot be 0!");
    if (!file.open(QIODevice::ReadWrite)) {
        throw FileOpenError(QString("Cannot open file %1: %2").arg(fileName_, file.errorString()));
    }
    if (file.size() < qint64(hdrsz)) {
        if (file.size() != 0) {
            throw FileFormatError("Bad file header");
        }
        // new file, write header, may throw on I/O error
        nrecs = 0;
        writeFullHeader(file, magic, nrecs.load());
    } else {
        // existing file, check header
        if (UNLIKELY(!file.seek(0))) throw FileError(QString("Failed to seek to position 0: %1").arg(file.errorString()));
        uint32_t tmpMagic = 0;
        uint64_t tmpNRecs = 0;
        if (file.read(reinterpret_cast<char *>(&tmpMagic), sizeof(tmpMagic)) != sizeof(tmpMagic)
                || file.read(reinterpret_cast<char *>(&tmpNRecs), sizeof(tmpNRecs)) != sizeof(tmpNRecs)) {
            throw FileFormatError(QString("Failed to read header: %1").arg(file.errorString()));
        }
        tmpMagic = le32ToH(tmpMagic); // swab from little-endian to host order
        tmpNRecs = le64ToH(tmpNRecs);
        if constexpr (isBigEndian()) {
            if (tmpMagic != magic) {
                // Big endian (compatibility with previous file format). Re-swab to detect and fix.
                const uint32_t beTmpMagic = bswap_32(tmpMagic);
                const uint64_t beTmpNRecs = bswap_64(tmpNRecs);
                if (beTmpMagic == magic && qint64(beTmpNRecs*recsz + hdrsz) == file.size()) {
                    // Header was encoded in big endian, convert it. This branch can happen if on a Big Endian system,
                    // where older code just encoded in host byte order, but now we impose little endian byte order on
                    // the header.
                    Warning() << "RecordFile \"" << fileName_ << "\" had a header which was encoded in big endian"
                                                                 " previously. It will be converted to little endian.";
                    writeFullHeader(file, tmpMagic = beTmpMagic, tmpNRecs = beTmpNRecs);
                }
            }
        }
        if (tmpMagic != magic)
            throw FileFormatError("Bad magic in header");
        if (qint64(tmpNRecs*recsz + hdrsz) != file.size())
            throw FileFormatError("File size is not a multiple of recordSize");
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
                             .arg(recNum).arg(f.fileName(), f.errorString());
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
                                         .arg(f.fileName(), f.errorString());
        } else
            ret = readRandomCommon(f, recNum, errStr);
    }
    return ret;
}

std::vector<QByteArray> RecordFile::readRandomRecords(const std::vector<uint64_t> & recNums, QString *errStr,
                                                      bool continueOnError) const
{
    std::shared_lock g(rwlock);
    std::vector<QByteArray> ret;
    ret.reserve(recNums.size());
    QFile f(fileName());
    if (!f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly)) {
        if (errStr) *errStr = QString("Unable to open file %1 (error was: '%2')").arg(fileName(), f.errorString());
    } else {
        // good status
        if (!continueOnError) {
            // in this branch, caller wants us to abort right away on error
            for (const auto recNum : recNums) {
                if (recNum >= nrecs) {
                    if (errStr) *errStr = QString("%1 is outside the record file, which only contains %2 records").arg(recNum).arg(nrecs.load());
                    break;
                }
                ret.emplace_back(readRandomCommon(f, recNum, errStr));
                if (ret.back().isEmpty()) {
                    ret.pop_back();
                    break;
                }
            }
        } else {
            // in this branch we simply keep values on error and insert them as empty QByteArrays
            for (const auto recNum : recNums) {
                if (recNum >= nrecs) {
                    if (errStr) *errStr = QString("%1 is outside the record file, which only contains %2 records").arg(recNum).arg(nrecs.load());
                    ret.emplace_back(); // empty QByteArray
                    continue;
                }
                ret.emplace_back(readRandomCommon(f, recNum, errStr));
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
        if (errStr) *errStr = "readRecords specification is out of range";
        return ret;
    }
    QFile f(fileName());
    if (!f.open(QIODevice::ReadOnly|QIODevice::ExistingOnly) || !f.seek(offsetOfRec(recNumStart))) {
        if (errStr) *errStr = QString("Unable to open or seek in file %1 (error was: '%2')").arg(fileName(), f.errorString());
        return ret;
    }
    ret.reserve(count);
    for (auto recNum = recNumStart; recNum < nrecs && count; --count, ++recNum) {
        ret.emplace_back(f.read(qint64(recsz)));
        if (size_t(ret.back().length()) != recsz) {
            if (errStr)
                *errStr = QString("Unable to read record %1 from file %2 (error was: '%3')")
                                 .arg(recNum).arg(f.fileName(), f.errorString());
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
    if (!writeNewSizeToHeader(errStr, true))
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

bool RecordFile::writeNewSizeToHeader(QString *errStr, bool flush)
{
    bool ret = false;
    if (UNLIKELY(!file.isOpen())) {
        if (errStr) *errStr = "File not open";
    } else if (!file.seek(offsetOfNRecs())) {
        if (errStr) *errStr = QString("Cannot seek to write header for %1").arg(file.fileName());
    } else if (const uint64_t leNewNRecs = hToLe64(nrecs.load());
                file.write(reinterpret_cast<const char *>(&leNewNRecs), sizeof(leNewNRecs)) != sizeof(leNewNRecs)) {
        if (errStr) *errStr = QString("Cannot write header for %1: %2").arg(file.fileName(), file.errorString());
    } else if (size_t(file.size()) != hdrsz + recsz*le64ToH(leNewNRecs)) {
        if (errStr)
            *errStr = QString("File size mistmatch for %1, %2 is not a multiple of %3 (+ %4 header). File is now likely corrupted.")
                      .arg(file.fileName()).arg(file.size()).arg(recsz).arg(hdrsz);
    } else {
        ret = true;
        if (flush)
            file.flush();
    }
    return ret;
}

/* static */
void RecordFile::writeFullHeader(QFile &f, const uint32_t magic, const uint64_t nRecs)
{
    if (UNLIKELY(!f.seek(0))) throw FileError(QString("Failed to seek to position 0: %1").arg(f.errorString()));
    const uint32_t leMagic = hToLe32(magic); // swab to le byte order
    const uint64_t leN = hToLe64(nRecs); // swab to le byte order
    if (f.write(reinterpret_cast<const char *>(&leMagic), sizeof(leMagic)) != sizeof(leMagic)
            || f.write(reinterpret_cast<const char *>(&leN), sizeof(leN)) != sizeof(leN)) {
        throw FileError(QString("Failed to write header: %1").arg(f.errorString()));
    }
}

bool RecordFile::flush()
{
    std::lock_guard g(rwlock);
    return file.flush();
}

RecordFile::BatchAppendContext::~BatchAppendContext()
{
    // updates the header with the new count, does some checks, releases lock
    QString errStr;
    rf.writeNewSizeToHeader(&errStr, true);
    if (!errStr.isEmpty())
        Fatal() << errStr; // app will quit in main event loop after printing error.
}

#ifdef ENABLE_TESTS
#include "App.h"
#include <QTemporaryFile>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <thread>
#include <type_traits>
#include <vector>

namespace {
    void testRecordFile() {
        size_t nChecksOK = 0;

        const auto fileName = []{
            QTemporaryFile tmp(APPNAME "_XXXXXX.tmp");
            tmp.open();
            auto ret = tmp.fileName();
            tmp.setAutoRemove(false); // keep file around so we can pass it to RecordFile instance
            return ret;
        }();
        constexpr size_t HashLen = 32;
        constexpr size_t N = 100'000; // 100k items
        Log() << "Testing Recordfile \"" << fileName << "\" with " << N << " " << HashLen << "-byte random records ...";
        // delete tmp file at scope end
        Defer d([&fileName] {
            QFile::remove(fileName);
            Log() << "Temporary file: \"" << fileName << "\" deleted";
        });

        Tic t0;
        std::vector<QByteArray> hashes(N, QByteArray(HashLen, Qt::Uninitialized));
        // randomize hashes
        QByteArray *lastH = nullptr;
        for (auto & h : hashes) {
            Util::getRandomBytes(h.data(), h.size());
            if (lastH && *lastH == h)
                throw Exception("Something went wrong generating random hashes.. previous hash and this hash match!");
            lastH = &h;
        }
        Log() << "Generated " << hashes.size() << " random hahses in " << t0.msecStr() << " msec";
        {
            t0 = Tic();
            RecordFile f(fileName, HashLen);
            auto batch = f.beginBatchAppend();
            QString err;
            for (const auto & h : hashes)
                if (!batch.append(h, &err))
                    throw Exception(QString("Failed to append a record using batch append to RecordFile: %1").arg(err));
            Log() << "Wrote " << f.numRecords() << " hahses in " << t0.msecStr() << " msec";
        }
        {
            t0 = Tic();
            // Read 1 record at a time randomly from 3 threads concurrently
            std::vector<std::thread> thrds;
            RecordFile f(fileName, HashLen);
            if (f.numRecords() != N) throw Exception("RecordFile has wrong number of records!");
            std::atomic_size_t ctr{0};
            QString fail_shared;
            std::mutex fail_shared_mut;
            for (size_t i = 0; i < 3; ++i) {
                thrds.emplace_back([&]{
                    QString fail;
                    for (size_t i = 0; fail.isEmpty() && i < hashes.size() * 7 / 20; ++i) {
                        size_t idx;
                        Util::getRandomBytes(reinterpret_cast<std::byte *>(&idx), sizeof(idx));
                        idx = idx % hashes.size();
                        if (f.readRecord(idx, &fail) != hashes[idx]) {
                            fail = QString("Failed to read an individual record at position %1 correctly: %2").arg(idx).arg(fail);
                            break;
                        }
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
            Log() << "Read " << ctr.load() << " individual records randomly using " << thrds.size() << " concurrent threads in "
                  << t0.msecStr() << " msec";
            ++nChecksOK;
        }
        {
            t0 = Tic();
            // Read 1000 records at a time randomly from 3 threads concurrently
            std::vector<std::thread> thrds;
            RecordFile f(fileName, HashLen);
            if (f.numRecords() != N) throw Exception("RecordFile has wrong number of records!");
            QString fail;
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
                            size_t idx;
                            Util::getRandomBytes(reinterpret_cast<std::byte *>(&idx), sizeof(idx));
                            idx = idx % N;
                            recNums[j] = idx;
                            ++ctr;
                        }
                        const auto results = f.readRandomRecords(recNums, &fail, false);
                        if (results.size() != recNums.size())
                            fail = QString("Failed to read random records: ") + fail;
                        for (size_t i = 0; fail.isEmpty() && i < results.size(); ++i) {
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
            if (!fail.isEmpty()) throw Exception(fail);
            Log() << "Read " << ctr.load() << " batched records randomly using " << thrds.size() << " concurrent threads in "
                  << t0.msecStr() << " msec";
            ++nChecksOK;
        }
        {
            t0 = Tic();
            // truncate to N / 2, and verify
            {
                RecordFile f(fileName, HashLen);
                f.truncate(hashes.size() / 2);
            }
            RecordFile f(fileName, HashLen);
            if (f.numRecords() != hashes.size() / 2) throw Exception("Trunace failed");
            QString fail;
            const auto results = f.readRecords(0, hashes.size() / 2, &fail);
            if (!fail.isEmpty() || results.size() != hashes.size() / 2) throw Exception(QString("Failed to verify truncated data: %1").arg(fail));
            for (size_t i = 0; i < results.size(); ++i)
                if (results[i] != hashes[i])
                    throw Exception(QString("After truncation, record %1 no longer compares equal!").arg(i));
            Log() << "Truncated file to size " << f.numRecords() << " and verified in "<< t0.msecStr() << " msec";
            ++nChecksOK;
        }
        {
            t0 = Tic();
            // truncate the file to 0, then write N / 10 records using single-append calls and verify
            {
                RecordFile f(fileName, HashLen);
                f.truncate(0);
            }
            RecordFile f(fileName, HashLen);
            if (f.numRecords() != 0) throw Exception("Failed to truncate file to 0");
            const auto NN = hashes.size() / 10;
            for (size_t i = 0; i < NN; ++i) {
                QString err;
                const auto res = f.appendRecord(hashes[i], true, &err);
                if (!res || *res != i || !err.isEmpty() || f.numRecords() != i + 1)
                    throw Exception(QString("Failed to append record %1: %2").arg(i).arg(err));
            }
            QString fail;
            const auto results = f.readRecords(0, NN, &fail);
            if (!fail.isEmpty() || results.size() != NN) throw Exception(QString("Failed to verify truncated data: %1").arg(fail));
            for (size_t i = 0; i < results.size(); ++i)
                if (results[i] != hashes[i])
                    throw Exception(QString("After truncation, record %1 no longer compares equal!").arg(i));
            Log() << "Truncated file to size 0, appended using single-append calls to size " << f.numRecords() << ", and verified in "<< t0.msecStr() << " msec";
            ++nChecksOK;
        }
        {
            // try mismatch on recSz
            static_assert (!std::is_base_of_v<RecordFile::FileFormatError, Exception>); // to ensure below works.. this is obviously always the case
            try {
                RecordFile f(fileName, HashLen + 1 /* bad recsz */);
                throw Exception("Failed to catch expected exception!");
            } catch (const RecordFile::FileFormatError &e) {
                Log() << "Got expected exception: \"" << e.what() << "\" ok";
            }
            ++nChecksOK;
        }
        {
            // try mismatch on magic
            static_assert (!std::is_base_of_v<RecordFile::FileFormatError, Exception>); // to ensure below works.. this is obviously always the case
            try {
                RecordFile f(fileName, HashLen, 0x01020304 /* bad magic */);
                throw Exception("Failed to catch expected exception!");
            } catch (const RecordFile::FileFormatError &e) {
                Log() << "Got expected exception: \"" << e.what() << "\" ok";
            }
            ++nChecksOK;
        }
        Log() << nChecksOK << " RecordFile checks passed ok";
    }
    const auto test = App::registerTest("recordfile", testRecordFile);
}
#endif
