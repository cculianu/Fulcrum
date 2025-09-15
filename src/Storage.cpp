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
#include "App.h"
#include "BTC.h"
#include "ByteView.h"
#include "CostCache.h"
#include "CoTask.h"
#include "Mempool.h"
#include "Merkle.h"
#include "Rpa.h"
#include "Span.h"
#include "Storage.h"
#include "Storage/ConcatOperator.h"
#include "Storage/DBRecordArray.h"
#include "Storage/RecordFile.h"
#include "SubsMgr.h"
#include "Util.h"
#include "VarInt.h"

#include "bitcoin/hash.h"

#if __has_include(<rocksdb/advanced_cache.h>)
// Newer rocksdb 8.1 defines the `Cache` class in this header. :/
#include <rocksdb/advanced_cache.h>
#endif
#include <rocksdb/cache.h>
#include <rocksdb/db.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/iterator.h>
#include <rocksdb/merge_operator.h>
#include <rocksdb/options.h>
#include <rocksdb/slice.h>
#include <rocksdb/table.h>
#include <rocksdb/version.h>
#include <rocksdb/write_buffer_manager.h>

#include <QByteArray>
#include <QDir>
#include <QFileInfo>
#include <QStorageInfo> // used to check disk size when upgrading db from Fulcrum 1.x -> 2.x
#include <QSysInfo>
#include <QVector> // we use this for the Height2Hash cache to save on memcopies since it's implicitly shared.

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstddef> // for std::byte, offsetof, ptrdiff_t
#include <cstdlib>
#include <cstring> // for memcpy
#include <functional>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

DatabaseError::~DatabaseError(){} // weak vtable warning suppression
DatabaseSerializationError::~DatabaseSerializationError() {} // weak vtable warning suppression
DatabaseFormatError::~DatabaseFormatError() {} // weak vtable warning suppression
DatabaseKeyNotFound::~DatabaseKeyNotFound() {} // weak vtable warning suppression
HeaderVerificationFailure::~HeaderVerificationFailure() {} // weak vtable warning suppression
UndoInfoMissing::~UndoInfoMissing() {} // weak vtable warning suppression
HistoryTooLarge::~HistoryTooLarge() {} // weak vtable warning suppression

namespace {
    /// Encapsulates the 'meta' db table
    struct Meta {
        static constexpr uint32_t kCurrentVersion = 0x4u;
        static constexpr uint32_t kMinSupportedVersion = 0x1u;
        static constexpr uint32_t kMinBCHUpgrade9Version = 0x2u;
        static constexpr uint32_t kMinHasExtraPlatformInfoVersion = 0x3u;

        static constexpr uint32_t kMagic = 0xf33db33fu;
        static constexpr uint16_t kPlatformBits = sizeof(void *)*8U;

        uint32_t magic = kMagic, version = kCurrentVersion;
        QString chain; ///< "test", "main", etc
        /// We save the platform pointer size to the db. Previous to v3 (kMinHasExtraPlatformInfoVersion), this field
        /// was unreliable between Windows & Linux and should be ignored for versions < kMinHasExtraPlatformInfoVersion.
        uint16_t platformBits = kPlatformBits;

        // -- New in 1.3.0 (this field is not in older db's)
        /// "BCH", "BTC", or "".  May be missing in DB data for older db's, in which case we take the default ("BCH")
        /// when we deserialize, if we detect that it was missing.
        ///
        /// On uninitialized, newly-created DB's this is present but empty "". The fact that it is empty allows us
        /// to auto-detect the Coin in question in Controller.
        QString coin = QString();

        /// -- New in 1.11.0
        /// These fields only are valid in v3 or above (.version >= kMinHasExtraPlatformInfoVersion)
        /// These fields get re-saved to the DB from the current program's info each time (along with `platformBits`
        /// above) in function: Storage::checkUpgradeDBVersion().
        QString appName; // "Fulcrum"
        QString appVersion; // e.g. "1.11.0 (Release d884cb4)"
        QString rocksDBVersion; // e.g. "9.2.1-08f9322"
        QString buildABI; // ABI used at build-time, e.g. "x86_64-little_endian-lp64"
        QString osName; // OS name e.g. "macOS 14.5"
        QString cpuArch; // CPU arch e.g. "x86_64"

        // C'tor used *not for deser*; object constructed with good values
        Meta() { makePlatformInfoCurrent(); }

        // C'tor used for deser; a cleared object is constructed
        struct ClearedForUnser_t {};
        static inline constexpr ClearedForUnser_t ClearedForUnser{};
        explicit Meta(ClearedForUnser_t) : magic{0}, version{0}, platformBits{0} {}

        bool isVersionSupported() const { return version >= kMinSupportedVersion && version <= kCurrentVersion; }
        bool isMagicOk() const { return magic == kMagic; }
        bool isMinimumExtraPlatformInfoVersion() const { return version >= kMinHasExtraPlatformInfoVersion; }

        // Set this instance's platform info to correspond to the current process's valid info.
        void makePlatformInfoCurrent();
    };

    // type "tag" that specifies legacy deserialization (see: getMetaFromDBAndDoBasicCompatibilityCheck in this file)
    struct MetaLegacy : Meta {
        // move-construct from Meta
        MetaLegacy(Meta &&m) : Meta(std::move(m)) {}
    };

    void Meta::makePlatformInfoCurrent() {
        platformBits = kPlatformBits;
        if (const auto *app = App::globalInstance()) {
            appName = app->applicationName();
            appVersion = app->applicationVersion();
        }
        rocksDBVersion = Storage::rocksdbVersion();
        buildABI = QSysInfo::buildAbi();
        osName = QSysInfo::prettyProductName();
        cpuArch = QSysInfo::currentCpuArchitecture();
    }

    static const QString kDBName = "fulc2_db"; // the entire db lives in this subdirectory in `datadir`

    // Some database keys we use in the `Meta` table; if this grows large, move it elsewhere.
    static const bool falseMem = false, trueMem = true;
    static const rocksdb::Slice kMeta{"meta"}, kDirty{"dirty"}, kUtxoCount{"utxo_count"}, kRpaNeedsFullCheck{"rpa_needs_full_check"},
                                kTrue(reinterpret_cast<const char *>(&trueMem), sizeof(trueMem)),
                                kFalse(reinterpret_cast<const char *>(&falseMem), sizeof(falseMem));

    static constexpr QByteArray::size_type kRpaShortBlockHashLen = 4; // Changing this will cause RPA DB format incompatibility
    static_assert(kRpaShortBlockHashLen <= HashLen);

    template <typename T>
    concept NonPointer = !std::is_pointer_v<std::remove_cv_t<T>>;

    template <typename T>
    concept TrivCopObj = std::is_trivially_copyable_v<T> && NonPointer<T> && std::has_unique_object_representations_v<T>;

    template <typename T>
    concept Scalar = std::is_scalar_v<T> && TrivCopObj<T> && !std::is_floating_point_v<T> /* No float support for now */;

    /// Return a shallow, temporary copy of the memory of an object as a QByteArray. This reduces typing of the
    /// boilerplate: "QByteArray::fromRawData(reinterpret_cast...." etc everywhere in this file.
    /// Note: It is unsafe to use this function for anything other than obtaining a weak reference to the memory of an
    /// object as a QByteArray for temporary purposes. The original object must live at least as long as this returned
    /// QByteArray.  Note that even copy-constructing a new QByteArray from this returned QByteArray will lead to
    /// dangling pointers. See: https://doc.qt.io/qt-5/qbytearray.html#fromRawData.
    template <TrivCopObj Object>
    QByteArray ShallowTmp(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(mem), static_cast<QByteArray::size_type>(size));
    }

    /// Construct a QByteArray from a deep copy of any object's memory area. Slower than ShallowTmp above but
    /// 100% safe to use after the original object's lifetime ends since the returned QByteArray takes ownership of its
    /// private copy of the memory it allocated.
    template <TrivCopObj Object>
    QByteArray DeepCpy(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray(reinterpret_cast<const char *>(mem), static_cast<QByteArray::size_type>(size));
    }

    /// Serialize a simple value such as an int directly, without using the space overhead that QDataStream imposes.
    /// This is less safe but is more compact since the bytes of the passed-in value are written directly to the
    /// returned QByteArray, without any encapsulation.  Note that if on a big endian system we will be byte swapping
    /// to little endian (all scalars are little endian unless BigEndian = true).
    template <bool BigEndian = false, bool ForEphemeralUse = false, Scalar S>
    QByteArray SerializeScalar(const S & s) {
        if constexpr (sizeof(S) <= 1u || BigEndian == Util::isBigEndian()) {
            // fast-path where endianness matches or if 1-byte value; just copy the memory directly
            return ForEphemeralUse ? ShallowTmp(&s) : DeepCpy(&s);
        } else {
            // otherwise ephemeral-ness cannot be respected; create a new DeepCpy of the byte-swapped data
            using US = std::make_unsigned_t<S>;
            US us = static_cast<US>(s);
            if constexpr (BigEndian)
                us = Util::hToBe(us);
            else
                us = Util::hToLe(us);
            return DeepCpy(&us);
        }
    }
    template <bool BigEndian = false, Scalar S> QByteArray SerializeScalarEphemeral(const S &s) {
        return SerializeScalar<BigEndian, true>(s);
    }
    /// Inverse of above.  Pass in an optional 'pos' pointer if you wish to continue reading raw scalars from the same
    /// QByteArray during subsequent calls to this template function.  *ok, if specified, is set to false if we ran off
    /// the QByteArray's bounds, and a default-constructed value of 'Scalar' is returned.  No other safety checking is
    /// done.  On successful deserialization of the scalar, *pos (if specified) is updated to point just past the
    /// last byte of the successuflly converted item.  On failure, *pos is always set to point past the end of the
    /// QByteArray.
    template <Scalar S, bool BigEndian = false>
    S DeserializeScalar(const QByteArray &ba, bool *ok = nullptr, QByteArray::size_type *pos_out = nullptr) {
        S ret{};
        QByteArray::size_type dummy = 0;
        QByteArray::size_type & pos = pos_out ? *pos_out : dummy;
        if (pos >= 0 && pos + QByteArray::size_type(sizeof(ret)) <= ba.size()) {
            if (ok) *ok = true;
            std::memcpy(reinterpret_cast<std::byte *>(&ret), ba.constData() + pos, sizeof(ret));
            pos += sizeof(ret);
            if constexpr (sizeof(S) > 1u && BigEndian != Util::isBigEndian()) {
                // need to do a byte swap for >1 byte values if the requested endian-ness does not match
                using US = std::make_unsigned_t<S>;
                ret = static_cast<S>(BigEndian ? Util::beToH(static_cast<US>(ret)) : Util::leToH(static_cast<US>(ret)));
            }
        } else {
            if (ok) *ok = false;
            pos = ba.size();
        }
        return ret;
    }

    // serialize/deser -- for basic int types we use SerializeScalar, but we also have specializations at the end of this file.
    // Note that no completely generic implementation is provided intentionally to catch missing Ser/Deser code paths at compile-time.
    template <typename Type> QByteArray Serialize(const Type & n);
    template <typename Type> Type Deserialize(const QByteArray &ba, bool *ok = nullptr);

    // Specialziation for Scalars (ints, basically) -- serialized as little endian bytes.
    template <Scalar Type> Type Serialize(const Type &n) { return SerializeScalar<false, false>(n); }
    template <Scalar Type> Type Deserialize(const QByteArray &ba, bool *ok) { return DeserializeScalar<Type>(ba, ok, nullptr); }

    struct SHUnspentValue {
        bool valid = false;
        bitcoin::Amount amount;
        bitcoin::token::OutputDataPtr tokenDataPtr;
    };

    // Ensures we store RPA db keys in big endian for faster scans of adjacent heights
    struct RpaDBKey {
        uint32_t height;

        explicit RpaDBKey(uint32_t h) : height(h) {}

        QByteArray toBytes() const { return SerializeScalar</*BigEndian=*/true, /*Ephemeral=*/false>(height); }

        static RpaDBKey fromBytes(const QByteArray &ba, bool *ok = nullptr, bool strictSize = false) {
            RpaDBKey k(DeserializeScalar<uint32_t, /*BigEndian=*/true>(ba, ok, nullptr));
            if (strictSize && size_t(ba.size()) != sizeof(uint32_t)) { // enforce `strictSize` if specified by caller
                k.height = 0u;
                if (ok) *ok = false;
            }
            return k;
        }

        bool operator==(const RpaDBKey &o) const { return height == o.height; }
        bool operator!=(const RpaDBKey &o) const { return ! this->operator==(o); }
    };

    // specializations
    template <> QByteArray Serialize(const Meta &);
    template <> Meta Deserialize(const QByteArray &, bool *);
    template <> MetaLegacy Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXO &);
    template <> TXO Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXOInfo &);
    template <> TXOInfo Deserialize(const QByteArray &, bool *);
    template <> Rpa::PrefixTable Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const RpaDBKey &k) { return k.toBytes(); }
    template <> RpaDBKey Deserialize(const QByteArray &ba, bool *ok) { return RpaDBKey::fromBytes(ba, ok); }
    QByteArray Serialize2(const bitcoin::Amount &, const bitcoin::token::OutputData *);
    template <> SHUnspentValue Deserialize(const QByteArray &, bool *);

    // TxNumVec
    using TxNumVec = std::vector<TxNum>;
    // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
    template <> QByteArray Serialize(const TxNumVec &);
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize(const QByteArray &, bool *);

    // CompactTXO
    template <> CompactTXO Deserialize(const QByteArray &, bool *);


    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return ShallowTmp(s.data(), s.size()); }

    /// Generic conversion from any type we operate on to a rocksdb::Slice. Note that the type in question should have
    /// a conversion function written (eg Serialize) if it is anything other than a QByteArray, ByteView, or a Scalar.
    template <typename Thing>
    auto ToSlice(const Thing &thing) {
        if constexpr (std::is_base_of_v<rocksdb::Slice, Thing>) {
            // same type, no-op, return ref to thing (const Slice &)
            return static_cast<const rocksdb::Slice &>(thing);
        } else if constexpr (std::is_base_of_v<QByteArray, Thing>) {
            // QByteArray conversion, return reference to data in QByteArray
            return rocksdb::Slice(thing.constData(), size_t(thing.size()));
        } else if constexpr (std::is_same_v<ByteView, Thing>) {
            // ByteView conversion, return reference to data in ByteView
            return rocksdb::Slice(thing.charData(), thing.size());
        } else {
            // the purpose of this holder is to keep the temporary QByteArray alive for as long as the slice itself is alive
            struct BagOfHolding {
                QByteArray bytes;
                operator rocksdb::Slice () const { return ToSlice(bytes); }
            } h;
            if constexpr (Scalar<Thing>) h.bytes = SerializeScalarEphemeral</*BigEndian=*/false>(thing);
            else h.bytes = Serialize(thing);
            return h; // this holder type "acts like" a Slice due to its operator const Slice &()
        }
    };

    /// Helper to get a column family name. `cf` may be nullptr
    QString CFName(const rocksdb::ColumnFamilyHandle *cf) { return QString::fromStdString(cf ? cf->GetName() : std::string{"unk"}); }

    /// Helper to get db name (basename of path)
    QString DBName(const rocksdb::DB *db, const rocksdb::ColumnFamilyHandle *cf = nullptr) {
        const auto dbname = QFileInfo(QString::fromStdString(db ? db->GetName() : "???")).baseName();
        if (!cf) return dbname;
        return QString("%1 (cf: %2)").arg(dbname, CFName(cf));
    }
    /// Helper to just get the status error string as a QString
    QString StatusString(const rocksdb::Status & status) { return QString::fromStdString(status.ToString()); }

    /// DB read/write helpers
    /// NOTE: these may throw DatabaseError
    /// If missingOk=false, then the returned optional is guaranteed to have a value if this function returns without throwing.
    /// If missingOk=true, then if there was no other database error and the key was not found, the returned optional !has_value()
    template <typename RetType, typename KeyType>
    std::optional<RetType> GenericDBGet(rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf,
                                        const KeyType & keyIn, bool missingOk = false,
                                        const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                                        bool acceptExtraBytesAtEndOfData = false,
                                        const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions()) ///< if true, we are ok with extra unparsed bytes in data. otherwise we throw. (this check is only done for !safeScalar mode on basic types)
    {
        rocksdb::PinnableSlice datum;
        std::optional<RetType> ret;
        if (!db || !cf) [[unlikely]] throw InternalError("GenericDBGet was passed a null pointer!");
        const auto status = db->Get(ropts, cf, ToSlice(keyIn), &datum);
        if (status.IsNotFound()) {
            if (missingOk)
                return ret; // optional will not has_value() to indicate missing key
            throw DatabaseKeyNotFound(QString("%1: %2")
                                      .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Key not found in db %1").arg(DBName(db, cf)))
                                      .arg(StatusString(status)));
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error reading a key from db %1").arg(DBName(db, cf)))
                                .arg(StatusString(status)));
        } else {
            // ok status
            if constexpr (std::is_base_of_v<QByteArray, std::remove_cv_t<RetType> >) {
                // special compile-time case for QByteArray subclasses -- return a deep copy of the data bytes directly.
                // TODO: figure out a way to do this without the 1 extra copy! (PinnableSlice -> ret).
                ret.emplace( reinterpret_cast<const char *>(datum.data()), QByteArray::size_type(datum.size()) );
            } else if constexpr (std::is_same_v<rocksdb::PinnableSlice, std::remove_cv_t<RetType>>) {
                static_assert (!std::is_same_v<rocksdb::PinnableSlice, std::remove_cv_t<RetType>>,
                               "FIXME: rocksdb C++ is broken. This doesn't actually work.");
                ret.emplace(std::move(datum)); // avoids an extra copy -- but it doesn't work because Facebook doesn't get how C++ works.
            } else if constexpr (Scalar<RetType>) {
                if (!acceptExtraBytesAtEndOfData && datum.size() > sizeof(RetType)) {
                    // reject extra stuff at end of data stream
                    throw DatabaseFormatError(QString("%1: Extra bytes at the end of data")
                                              .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Database format error in db %1").arg(DBName(db, cf))));
                }
                bool ok{};
                ret.emplace( DeserializeScalar<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized as a scalar '%2'")
                                .arg((!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing a scalar from db %1").arg(DBName(db, cf))),
                                     QString(typeid (RetType).name())));
                }
            } else {
                if (acceptExtraBytesAtEndOfData) [[unlikely]]
                    Debug() << "Warning:  Caller misuse of function '" << __func__
                            << "'. 'acceptExtraBytesAtEndOfData=true' is ignored when deserializing using QDataStream.";
                bool ok{};
                ret.emplace( Deserialize<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing an object from db %1").arg(DBName(db, cf))));
                }
            }
        }
        return ret;
    }

    /// Conveneience for above with the missingOk flag set to false. Will always throw or return a real value.
    template <typename RetType, typename KeyType>
    RetType GenericDBGetFailIfMissing(rocksdb::DB * db, rocksdb::ColumnFamilyHandle * cf,
                                      const KeyType &k, const QString &errMsgPrefix = QString(), bool extraDataOk = false,
                                      const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions())
    {
        return GenericDBGet<RetType>(db, cf, k, false, errMsgPrefix, extraDataOk, ropts).value();
    }

    /// Throws on all errors. Otherwise writes to db.
    template <typename KeyType, typename ValueType>
    void GenericDBPut
                (rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                 const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Put(opts, cf, ToSlice(key), ToSlice(value));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2").arg(
                                    (!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error writing to db %1").arg(DBName(db, cf))),
                                    StatusString(st)));
    }
    /// Throws on all errors. Otherwise enqueues a write to the batch.
    template <typename KeyType, typename ValueType>
    void GenericBatchPut
                (rocksdb::WriteBatch & batch, rocksdb::ColumnFamilyHandle *cf, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Put(cf, ToSlice(key), ToSlice(value));
        if (!st.ok())
            throw DatabaseError(QString("%1 (cf: %3): %2")
                                    .arg((!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Put"),
                                         StatusString(st), CFName(cf)));
    }
    /// Throws on all errors. Otherwise enqueues a delete to the batch.
    template <typename KeyType>
    void GenericBatchDelete
                (rocksdb::WriteBatch & batch, rocksdb::ColumnFamilyHandle *cf, const KeyType & key,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Delete(cf, ToSlice(key));
        if (!st.ok())
            throw DatabaseError(QString("%1 (cf: %3): %2")
                                    .arg((!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Delete"),
                                         StatusString(st), CFName(cf)));
    }

    //// A helper data struct -- written to the blkinfo table. This helps localize a txnum to a specific position in
    /// a block.  The table is keyed off of block_height(uint32_t) -> serialized BlkInfo (raw bytes)
    struct BlkInfo {
        TxNum txNum0 = 0;
        uint32_t nTx = 0;
        BlkInfo() = default;
        BlkInfo(const BlkInfo &) = default;
        [[maybe_unused]] BlkInfo (TxNum txn, uint32_t ntx) : txNum0(txn), nTx(ntx) {}
        bool operator==(const BlkInfo &o) const { return txNum0 == o.txNum0 && nTx == o.nTx; }
        bool operator!=(const BlkInfo &o) const { return !(*this == o); }
        [[maybe_unused]] bool operator<(const BlkInfo &o) const { return txNum0 == o.txNum0 ? nTx < o.nTx : txNum0 < o.txNum0; }
        BlkInfo &operator=(const BlkInfo &) = default;

        // serializes data members as little endian integers
        QByteArray toBytes(QByteArray *bufAppend = nullptr) const;
    };
    // deserializes as little endian integers from struct
    template <> BlkInfo Deserialize(const QByteArray &, bool *);

    /// Block rewind/undo information. One of these is kept around in the db for the last configuredUndoDepth() blocks.
    /// It basically stores a record of all the UTXO's added and removed, as well as the set of
    /// scripthashes.
    struct UndoInfo {
        using ScriptHashSet = std::unordered_set<HashX, HashHasher>;
        using UTXOAddUndo = std::tuple<TXO, HashX, CompactTXO>;
        using UTXODelUndo = std::tuple<TXO, TXOInfo>;

        BlockHeight height = 0; ///< we save a copy of this infomation as a sanity check
        BlockHash hash; ///< we save a copy of this information as a sanity check. (bytes are in "reversed", bitcoind ToHex()-style memory order)
        BlkInfo blkInfo; ///< we save a copy of this from the global value for convenience and as a sanity check.

        // below is the actual critical undo information
        ScriptHashSet scriptHashes;
        std::vector<UTXOAddUndo> addUndos;
        std::vector<UTXODelUndo> delUndos;

        uint16_t deserVersion = 0u; ///< Only ever read-in from db, never written out (we write out the latest version always)

        [[maybe_unused]] QString toDebugString() const;

        [[maybe_unused]] bool operator==(const UndoInfo &) const; // for debug ser/deser

        bool isValid() const { return hash.size() == HashLen; } ///< cheap, imperfect check for validity
        void clear() { height = 0; hash.clear(); blkInfo = BlkInfo(); scriptHashes.clear(); addUndos.clear(); delUndos.clear(); deserVersion = 0u; }
    };

    QString UndoInfo::toDebugString() const {
        QString ret;
        QTextStream ts(&ret);
        ts  << "<Undo info for height: " << height << " addUndos: " << addUndos.size() << " delUndos: " << delUndos.size()
            << " scriptHashes: " << scriptHashes.size() << " nTx: " << blkInfo.nTx << " txNum0: " << blkInfo.txNum0
            << " hash: " << hash.toHex() << " deserVersion: " << int(deserVersion) << ">";
        return ret;
    }

    bool UndoInfo::operator==(const UndoInfo &o) const {
        return height == o.height && hash == o.hash && blkInfo == o.blkInfo && scriptHashes == o.scriptHashes
                && addUndos == o.addUndos && delUndos == o.delUndos;
    }

    // serialize as raw bytes mostly (no QDataStream)
    template <> QByteArray Serialize(const UndoInfo &);
    // serialize from raw bytes mostly (no QDataStream)
    template <> UndoInfo Deserialize(const QByteArray &, bool *);

    /// Thrown if user hits Ctrl-C / app gets a signal while we run the slow db checks
    struct UserInterrupted : public Exception { using Exception::Exception; ~UserInterrupted() override; };
    UserInterrupted::~UserInterrupted() {} // weak vtable warning suppression

    /// Manages the txhash2txnum rocksdb table.  The schema is:
    /// Key: N bytes from POS position from the big-endian ordered (JSON ordered) txhash (default 6 from the End)
    /// Value: One or more serialized VarInts. Each VarInt represents a "TxNum" (which tells us where the actual hash
    ///     lives in the txnum2txhash DBRecordArray).
    ///
    /// This class is mainly a thin wrapper around the rocksdb and DBRecordArray facilities and they are both
    /// thread-safe and reentrant. It takes no locks itself.
    class TxHash2TxNumMgr {
        rocksdb::DB * const db;
        rocksdb::ColumnFamilyHandle * const cf;
        const rocksdb::ReadOptions & rdOpts; // references into Storage::Pvt
        const rocksdb::WriteOptions & wrOpts;
        DBRecordArray * const dra;
        std::shared_ptr<rocksdb::MergeOperator> mergeOp;
        StorageDetail::ConcatOperator * concatOp;  // this is a "weak" pointer into above, dynamic casted down. always valid.
        Tic lastWarnTime; ///< this is not guarded by any locks. Assumption is calling code always holds an exclusive lock when calling truncateForUndo()
        int64_t largestTxNumSeen = -1;
    public:
        const size_t keyBytes;

        enum KeyPos : uint8_t { Beginning=0, Middle=1, End=2, KP_Invalid=3 };
        const KeyPos keyPos;

        TxHash2TxNumMgr(rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf,
                        const rocksdb::ReadOptions & rdOpts, const rocksdb::WriteOptions &wrOpts,
                        DBRecordArray *txnum2txhash, size_t keyBytes /*= 6*/, KeyPos keyPos /*= End*/)
            : db(db), cf(cf), rdOpts(rdOpts), wrOpts(wrOpts), dra(txnum2txhash), keyBytes(keyBytes), keyPos(keyPos)
        {
            if (!this->db || !this->cf || !dra || !this->keyBytes || this->keyBytes > HashLen || this->keyPos >= KP_Invalid)
                throw BadArgs("Bad argumnets supplied to TxHash2TxNumMgr constructor");
            mergeOp = db->GetOptions(cf).merge_operator;
            if (!mergeOp || ! (concatOp = dynamic_cast<StorageDetail::ConcatOperator *>(mergeOp.get())))
                throw BadArgs("This db lacks a merge operator of type `ConcatOperator`");
            loadLargestTxNumSeen();
            Debug() << "TxHash2TxNumMgr: largestTxNumSeen = " << largestTxNumSeen;
        }

        std::unique_ptr<rocksdb::Iterator> newIterChecked() {
            std::unique_ptr<rocksdb::Iterator> iter{db->NewIterator(rdOpts, cf)};
            if (UNLIKELY(!iter)) throw DatabaseError("Unable to obtain an iterator to the txhash2txnum db"); // should never happen
            return iter;
        }

        size_t mergeCount() const { return concatOp->merges.load(); }

        QString dbName() const { return QString::fromStdString(cf->GetName()); }

        /// Returns the largest tx num we have ever inserted into the db, or -1 if no txnums were inserted
        int64_t maxTxNumSeenInDB() const { return largestTxNumSeen; }

        /// Returned from insertForBlockPhased and/or truncateForUndoPhased. Intended to be an opaque type to capture
        /// some state information for the async and then sync phase. Caller should call doAsyncPhase1() from a worker
        /// thread and then when that completes, should call doSyncPhase2() from the caller's thread.
        class PhasedOpBase {
            friend class ::TxHash2TxNumMgr;
        protected:
            Tic t0;
            std::function<void()> asyncPhase1, syncPhase2;
            PhasedOpBase() = default;
        public:
            virtual ~PhasedOpBase() {
                if (asyncPhase1 || syncPhase2) [[unlikely]]
                    Warning() << __func__ << " destructor called but the lambdas are still alive. FIXME!"; // should never happen
            }
            PhasedOpBase(PhasedOpBase &&) = delete;
            PhasedOpBase(const PhasedOpBase &) = delete;

            PhasedOpBase * doAsyncPhase1() {
                if (asyncPhase1) {
                    asyncPhase1();
                    asyncPhase1 = nullptr; // clear lambda
                } else [[unlikely]]
                    Warning() << __func__ << " called but asyncPhase1 is null!"; // defensive programming, should never happen
                return this;
            }
            PhasedOpBase * doSyncPhase2() {
                if (syncPhase2) {
                    syncPhase2();
                    syncPhase2 = nullptr; // clear lambda
                } else [[unlikely]]
                    Warning() << __func__ << " called but syncPhase2 is null!"; // defensive programming, should never happen
                return this;
            }
        };

        using PhasedOp = std::unique_ptr<PhasedOpBase>;

    private:
        inline void insertForBlockInner1(const size_t i, rocksdb::WriteBatch &batch, const ByteView &key, const VarInt &val,
                                         const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            // Save by appending VarInt. Note that this uses the 'ConcatOperator' class we defined in this file,
            // which requires rocksdb be compiled with RTTI.
            if (auto st = batch.Merge(cf, ToSlice(key), ToSlice(val.byteView())); !st.ok()) [[unlikely]]
                throw DatabaseError(QString("%1: batch merge fail for txHash %2: %3")
                                        .arg(dbName(), QString(txInfos[i].hash.toHex()), StatusString(st)));
        }
        inline void insertForBlockInner2(rocksdb::WriteBatch &batch, const TxNum blockTxNum0, const qint64 elapsedNanos,
                                         const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            const Tic t2;
            if (!txInfos.empty()) {
                largestTxNumSeen = blockTxNum0 + txInfos.size() - 1;
                saveLargestTxNumSeen(batch);
            }
            if (auto elapsed = elapsedNanos + t2.nsec(); elapsed >= /* 50msec */ 50'000'000)
                DebugM("insertForBlock", ": inserted ", txInfos.size(), Util::Pluralize(" hash", txInfos.size()),
                       " in ", QString::asprintf("%1.3f msec", elapsed / 1e6));
        }

    public:
        [[nodiscard]]
        PhasedOp insertForBlockPhased(rocksdb::WriteBatch &batch, TxNum blockTxNum0, const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            struct InsertPhased : PhasedOpBase {
                std::vector<std::pair<ByteView, VarInt>> kv;
                InsertPhased() = default;
                ~InsertPhased() override {}
            };
            auto ret = std::make_unique<InsertPhased>();
            ret->asyncPhase1 = [this, self = ret.get(), &txInfos, blockTxNum0] {
                self->kv.reserve(txInfos.size());
                for (TxNum i = 0; i < txInfos.size(); ++i)
                    self->kv.emplace_back(makeKeyFromHash(txInfos[i].hash), blockTxNum0 + i);
                self->t0.fin();
            };
            ret->syncPhase2 = [this, self = ret.get(), &batch, blockTxNum0, &txInfos] {
                const Tic t1;
                size_t i{};
                for (const auto & [key, val] : self->kv)
                    insertForBlockInner1(i++, batch, key, val, txInfos); // may throw on error
                insertForBlockInner2(batch, blockTxNum0, self->t0.nsec() + t1.nsec(), txInfos);
            };
            return ret;
        }

        void insertForBlock(rocksdb::WriteBatch &batch, TxNum blockTxNum0, const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            // insertForBlockPhased(batch, blockTxNum0, txInfos)->doAsyncPhase1()->doSyncPhase2();
            // Ideally we do the above, but the above would do some extra allocations which we want to avoid, so
            // for performance we duplicate the code somewhat below ...
            const Tic t0;
            for (TxNum i = 0; i < txInfos.size(); ++i) {
                const ByteView key = makeKeyFromHash(txInfos[i].hash);
                const VarInt val(blockTxNum0 + i);
                insertForBlockInner1(i, batch, key, val, txInfos); // may throw on error
            }
            insertForBlockInner2(batch, blockTxNum0, t0.nsec(), txInfos);
        }

        void insertForBlockNoBatch(TxNum blockTxNum0, const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            rocksdb::WriteBatch batch;
            insertForBlock(batch, blockTxNum0, txInfos);
            if (auto st = db->Write(wrOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("%1: batch merge fail: %2").arg(dbName(), StatusString(st)));
        }

        /// This is called during blockundo. Returns immediately with 2 lambdas to be invoked later.
        ///
        /// The lambdas delete records from the db having their TxNum >= `txNum`. The async almbda requires that
        /// rf not yet be truncated. The second sync lambda commits the changes to the db.
        ///
        /// This is slow so don't call it with huge numbers of records beyond what fits into a block.
        [[nodiscard]]
        PhasedOp truncateForUndoPhased(rocksdb::WriteBatch &batch, const TxNum txNum) {
            struct UndoPhased : PhasedOpBase {
                std::vector<QByteArray> recs;
                std::vector<rocksdb::Slice> keySlices; ///< slices are views into above `recs`
                std::vector<std::string> valsBackToDb;
                std::vector<bool> ok;
                unsigned dels{}, keeps{}, filts{}; // for DEBUG print
                UndoPhased() = default;
                ~UndoPhased() override {}
            };
            auto ret = std::make_unique<UndoPhased>();
            ret->asyncPhase1 = [this, self = ret.get(), txNum] {
                const auto rfNR = dra->numRecords();
                if (rfNR < txNum) [[unlikely]]
                    throw DatabaseError(dbName() + ": DBRecordArray does not have the hashes required for the specified truncation");
                else if (rfNR == txNum) [[unlikely]] {
                    // defensive programming warning -- this should never happen
                    Warning() << "truncateForUndo: called with txNum == DBRecordArray->numRecords -- FIXME!";
                    return;
                }
                QString err;
                auto &recs = self->recs = dra->readRecords(txNum, rfNR - txNum, &err);
                if (recs.size() != rfNR - txNum || !err.isEmpty()) [[unlikely]]
                    throw DatabaseError(QString("%1: short read count or error reading DBRecordArray: %2").arg(dbName(), err));

                DebugM("truncateForUndo: read ", recs.size(), Util::Pluralize(" record", recs.size()),
                       " from txNums file, elapsed: ", self->t0.msecStr(), " msec");

                // first read all existing entries from the db -- we must delete the VarInts in their data blobs that
                // have TxNums > txNum
                auto &keySlices = self->keySlices;
                keySlices.clear();
                keySlices.reserve(recs.size());
                for (const auto &rec : recs) {
                    const auto bv = makeKeyFromHash(rec);
                    keySlices.emplace_back(bv.charData(), bv.size());
                }
                std::vector<rocksdb::PinnableSlice> dbValues(keySlices.size());
                std::vector<rocksdb::Status> statuses(keySlices.size());
                db->MultiGet(rdOpts, cf, keySlices.size(), keySlices.data(), dbValues.data(), statuses.data());
                DebugM("truncateForUndo: MultiGet for ", statuses.size(), Util::Pluralize(" key", statuses.size()),
                       " elapsed: ", self->t0.msecStr(), " msec");

                // next filter out all VarInts >= txNum, deleting records that have no more VarInts left and writing
                // back records that still have VarInts in them
                auto &valsBackToDb = self->valsBackToDb;
                valsBackToDb.resize(dbValues.size());
                self->ok.resize(dbValues.size(), true);
                for (size_t i = 0; i < dbValues.size(); ++i) {
                    if (!statuses[i].ok()) [[unlikely]] {
                        if (lastWarnTime.secs() >= 1.0) {
                            lastWarnTime = Tic();
                            // not sure what to do here... this should never happen. But warn anyway.
                            Warning() << "truncateForUndo: " << dbName() << ", got a non-ok status (" << StatusString(statuses[i])
                                      << ") when reading a key for txhash " << recs[i].toHex() << ". Proceeding anyway "
                                      << "but there may be DB corruption. Start " << APPNAME
                                      << " again with -C -C to check the database for consistency.";
                        }
                        self->ok[i] = false; // mark as to-be-skipped in sync lambda loop (should never happen!)
                        continue;
                    }
                    auto span = Span<const char>{dbValues[i]};
                    std::string &valBackToDb = valsBackToDb[i];
                    while (!span.empty()) {
                        try {
                            const VarInt val = VarInt::deserialize(span); // this may throw
                            if (val.value<TxNum>() >= txNum) {
                                // skip, filter out...
                                ++self->filts;
                            } else {
                                // was a collision, keep
                                valBackToDb.append(val.byteView().charData(), val.size());
                                ++self->keeps;
                            }
                        } catch (const std::exception &e) {
                            throw DatabaseFormatError(QString("%1: caught exception in truncateForUndo: %2").arg(dbName(),e.what()));
                        }
                    }
                }
            };
            ret->syncPhase2 = [this, self = ret.get(), &batch, txNum] {
                const Tic t1;
                const size_t N = std::min(std::min(self->keySlices.size(), self->valsBackToDb.size()), self->ok.size());
                if (!N) [[unlikely]] return; // nothing to do!
                for (size_t i = 0; i < N; ++i) {
                    if (!self->ok[i]) [[unlikely]]
                        continue; // error reading from DB, already warned above in asyncPhase1, just continue (should never happen)
                    const rocksdb::Slice &keySlice = self->keySlices[i];
                    const std::string &valBackToDb = self->valsBackToDb[i];
                    if (valBackToDb.empty()) {
                        // delete, key now has no VarInts
                        if (auto st = batch.Delete(cf, keySlice); !st.ok()) [[unlikely]] {
                            if (lastWarnTime.secs() >= 1.0) {
                                lastWarnTime = Tic();
                                Warning() << "truncateForUndo: " << dbName() << " failed to delete a key from db: "
                                          << StatusString(st) << ". Continuing anyway ...";
                            }
                        }
                        ++self->dels;
                    } else {
                        // keep key, key has some VarInts left
                        if (auto st = batch.Put(cf, keySlice, valBackToDb); !st.ok()) [[unlikely]]
                            throw DatabaseError(dbName() + ": failed to write back a key to the db: " + StatusString(st));
                    }
                }

                const int64_t txNumI = int64_t(txNum);
                 // we always add at the end and truncare at the end; this invariant should always hold
                largestTxNumSeen = std::max(txNumI - 1, int64_t{-1});
                saveLargestTxNumSeen(batch);

                DebugM("truncateForUndo: txNum: ", txNum, ", nrecs: ", self->recs.size(), ", dels: ", self->dels,
                       ", keeps: ", self->keeps, ", filts: ", self->filts, ", elapsed: ",
                       QString::asprintf("%1.3f", (self->t0.usec() + t1.usec()) / 1e3), " msec");
            };

            return ret;
        }

        /// Returns a valid optional containing the TxNum of txHash if txHash is found in the db. A nullopt otherwise.
        /// May throw DatabaseError if there is a low-level deserialization error.
        std::optional<TxNum> find(const TxHash &txHash) const {
            std::optional<TxNum> ret;
            const auto key = makeKeyFromHash(txHash);
            auto optBytes = GenericDBGet<QByteArray>(db, cf, key, true, dbName(), true, rdOpts);
            if (!optBytes) return ret; // missing
            auto span = Span<const char>{*optBytes};
            std::vector<uint64_t> txNums;
            txNums.reserve(1 + span.size() / 5); // rough heuristic
            try {
                while (!span.empty())
                    txNums.push_back(VarInt::deserialize(span).value<uint64_t>()); // this may throw
                if (txNums.empty()) [[unlikely]] throw DatabaseFormatError(QString("Missing data for txHash: ") + QString(txHash.toHex()));
                QString errStr;
                // we may get more than 1 txNum for a particular key, so examine them all
                const auto recs = dra->readRandomRecords(txNums, &errStr, true);
                if (recs.size() != txNums.size()) [[unlikely]] throw DatabaseError("Expected recs.size() == txNums.size()!");
                size_t i = 0;
                for (const auto & rec : recs) {
                    if (rec == txHash) {
                        // found!
                        ret = txNums[i];
                        return ret;
                    }
                    ++i;
                }
            } catch (const std::exception &e) {
                throw DatabaseError(dbName() + ": failed lookup for txHash " + QString(txHash.toHex()) + ": " + e.what());
            }
            return ret; // if we get here, ret is nullopt and txHash does not exist in db
        }

        /// Find the TxNums for a batch of hashes. Returns a vector that is exactly the same size as hashes.
        /// Not-found hashes are std::nullopt optionals. Found hashes will have the correct TxNum for that hash
        /// filled-in.
        ///
        /// May throw DatabaseError on low-level db error.
        std::vector<std::optional<TxNum>> findMany(const std::vector<TxHash> &hashes) const {
            std::vector<std::optional<TxNum>> ret;
            if (hashes.empty()) return ret; // short-circuit return on no work to do
            const Tic t0;
            ret.resize(hashes.size());
            std::vector<rocksdb::Slice> keySlices;
            std::vector<rocksdb::PinnableSlice> dbResults;
            keySlices.reserve(hashes.size());
            dbResults.reserve(hashes.size());
            // build keys
            for (const auto & hash : hashes) {
                keySlices.push_back(ToSlice(makeKeyFromHash(hash))); // shallow view into bytes in hashes
                dbResults.emplace_back();
            }
            std::vector<rocksdb::Status> statuses(keySlices.size());
            db->MultiGet(rdOpts, cf, keySlices.size(), keySlices.data(), dbResults.data(), statuses.data()); // this should be faster than single gets..?
            //DebugM(__func__, ": MultiGet of ", keySlices.size(), " items took ", t0.msecStr(), " msec");
            if (statuses.size() != hashes.size() || dbResults.size() != hashes.size())
                throw DatabaseError(dbName() + ": db returned an unexpected number of results"); // should never happen
            std::vector<uint64_t> recNums;
            std::vector<std::optional<std::pair<size_t, size_t>>> idx2RecNums;
            idx2RecNums.resize(hashes.size());
            recNums.reserve(hashes.size());
            for (size_t i = 0; i < statuses.size(); ++i) {
                auto & st = statuses[i];
                if (st.IsNotFound()) continue; // skip NotFound
                if (!st.ok()) throw DatabaseError(dbName() + ": got a status that is not ok in findMany: " + StatusString(st));
                auto & dataBlob = dbResults[i];
                if (dataBlob.empty()) {
                    Warning() << dbName() << ": Empty record for " << hashes[i].toHex() << ". FIXME!";
                    continue;
                }
                auto span = Span<const char>{dataBlob};
                std::pair<size_t, size_t> p(recNums.size(), recNums.size());
                while (!span.empty()) {
                    try {
                        recNums.push_back(VarInt::deserialize(span).value<uint64_t>());
                    } catch (const std::exception &e) {
                        throw DatabaseSerializationError(dbName() + ": failed to deserialize a VarInt: " + e.what());
                    }
                    ++p.second;
                }
                if (p.second > p.first)
                    idx2RecNums[i] = p;
            }
            QString errStr;
            const auto recs = dra->readRandomRecords(recNums, &errStr, true);
            if (recs.size() != recNums.size()) [[unlikely]] throw DatabaseError(QString("Expected recs.size() == recNums.size()! Error: %1").arg(errStr));
            assert(ret.size() == hashes.size() && ret.size() == idx2RecNums.size());
            for (size_t i = 0; i < ret.size(); ++i) {
                auto & optRange = idx2RecNums[i];
                if (!optRange) continue; // key not found, skip
                for (size_t j = optRange->first; j < optRange->second; ++j) {
                    if (recs[j] == hashes[i]) {
                        // found!
                        ret[i] = recNums[j]; // mark this in the return set
                        break;
                    }
                }
            }
            DebugM(__func__, ": ", ret.size(), " result(s), elapsed ", t0.msecStr(), " msec");
            return ret;
        }

        bool exists(const TxHash &txHash) const { return bool(find(txHash)); }

    private:
        ByteView makeKeyFromHash(const ByteView &bv) const {
            const auto len = bv.size();
            if (len != HashLen) [[unlikely]]
                throw DatabaseFormatError(QString("Hash \"%1\" is not %2 bytes").arg(QString(Util::ToHexFast(bv.substr(0, 80).toByteArray(false)))).arg(HashLen));
            if (keyPos == End)
                return bv.substr(len - keyBytes, keyBytes);
            else if (keyPos == Middle)
                return bv.substr(len/2 - keyBytes/2, keyBytes);
            else // Beginning
                return bv.substr(0, keyBytes);
        }
        static const QByteArray kLargestTxNumSeenKeyPrefix;
        QByteArray makeLargestTxNumSeenKey() const {
            auto ret = kLargestTxNumSeenKeyPrefix;
            if (size_t(ret.length()) <= keyBytes)
                // ensure a key that can never exist in db for a real tx hash (> keyBytes)
                ret.append(keyBytes - size_t(ret.length()) + 1, '-');
            return ret;
        }
        void loadLargestTxNumSeen() {
            auto opt = GenericDBGet<int64_t>(db, cf, makeLargestTxNumSeenKey(), true, QString{}, false, rdOpts);
            if (opt && *opt >= 0) largestTxNumSeen = *opt;
            else largestTxNumSeen = -1;
        }
        void saveLargestTxNumSeen(rocksdb::WriteBatch &batch) const {
            const auto key = makeLargestTxNumSeenKey();
            if (largestTxNumSeen > -1)
                GenericBatchPut(batch, cf, key, largestTxNumSeen, QString{});
            else
                GenericBatchDelete(batch, cf, key, QString{});
        }
        // Deletes *all* keys from db! May throw.
        void deleteAllEntries() {
            std::string firstKey, endKey;
            {
                std::unique_ptr<rocksdb::Iterator> iter = newIterChecked();
                iter->SeekToFirst();
                if (iter->Valid())
                    firstKey = iter->key().ToString();
                iter->SeekToLast();
                if (iter->Valid())
                    endKey = iter->key().ToString();
            }
            if (!endKey.empty()) {
                endKey.insert(endKey.end(), char(0xff)); // make sure our lastKey spec is larger than the actual lastKey
                Debug() << "Deleting keys in the range [" << Util::ToHexFast(QByteArray::fromStdString(firstKey)) << ", "
                        << Util::ToHexFast(QByteArray::fromStdString(endKey)) << "] ...";
            }
            rocksdb::WriteBatch batch;
            rocksdb::FlushOptions fopts;
            rocksdb::Status st;
            fopts.wait = true; fopts.allow_write_stall = true;
            if (!(st = batch.DeleteRange(cf, firstKey, endKey)).ok())
                throw DatabaseError(dbName() + ": failed to delete all keys: " + StatusString(st));
            largestTxNumSeen = -1;
            saveLargestTxNumSeen(batch);
            if (!(st = db->Write(wrOpts, &batch)).ok())
                throw DatabaseError(dbName() + ": failed to write batch when deleting all keys: " + StatusString(st));
            if (!(st = db->Flush(fopts, cf)).ok())
                throw DatabaseError(dbName() + ": failed to flush when deleting all keys: " + StatusString(st));

            std::unique_ptr<rocksdb::Iterator> iter = newIterChecked();
            iter->SeekToFirst();
            if (iter->Valid())
                throw InternalError(dbName() + ": delete all keys failed -- iterator still points to a row! FIXME!");
        }

    public:
        // -- Utility / consistency check, etc ..

        void consistencyCheck() { // this throws if the checks fail
            const Tic t0;
            Log() << "CheckDB: Verifying txhash index (this may take some time) ...";
            std::unique_ptr<rocksdb::Iterator> iter = newIterChecked();
            size_t i = 0, verified = 0;
            QString err;
            constexpr size_t batchSize = 50'000;
            std::vector<std::pair<std::string, uint64_t>> batch;
            std::vector<uint64_t> batchNums;
            batch.reserve(batchSize + 500);
            batchNums.reserve(batchSize + 500);
            auto ProcBatch = [this, &batch, &batchNums, &err, &verified]{
                std::sort(batch.begin(), batch.end(), [](const auto & a, const auto & b){
                    return a.second < b.second;
                });
                std::sort(batchNums.begin(), batchNums.end());
                const auto recs = dra->readRandomRecords(batchNums, &err);
                if (recs.size() != batchNums.size()) throw InternalError(QString("short read of records: ") + err);
                for (size_t i = 0; i < recs.size(); ++i) {
                    const auto &hash = recs[i];
                    const auto txNum = batchNums[i];
                    if (batch[i].second != txNum) throw DatabaseError("txNum mismatch");
                    if (hash.length() != HashLen) throw DatabaseFormatError("bad record");
                    const auto expect = makeKeyFromHash(hash).toByteArray();
                    const auto &keyStr = batch[i].first;
                    const auto key = QByteArray::fromRawData(keyStr.data(), keyStr.size());
                    if (key != expect)
                        throw DatabaseError(QString("record %1 does not match key. expected: %2, got: %3")
                                            .arg(txNum).arg(QString(expect.toHex()), QString(key.toHex())));
                    ++verified;
                }
                batch.resize(0);
                batchNums.resize(0);
            };
            App *ourApp = app();
            const auto nrec = dra->numRecords();
            for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
                if (UNLIKELY(0 == i % 100 && ourApp && ourApp->signalsCaught()))
                    throw UserInterrupted("User interrupted, aborting check"); // if the user hits Ctrl-C, stop the operation
                if (i && 0 == i % 1'000'000) {
                    *(0 == i % 5'000'000 ? std::make_unique<Log>() : std::make_unique<Debug>())
                    << "Verified " << verified << "/" << nrec << ", merge ops so far: " << mergeCount() << " ...";
                }
                const auto keySlice = iter->key();
                const auto valSlice = iter->value();
                const auto key = FromSlice(keySlice);
                if (key.startsWith(kLargestTxNumSeenKeyPrefix))
                    continue; // skip this meta entry
                const auto val = FromSlice(valSlice);
                Span<const std::byte> bytes(reinterpret_cast<const std::byte *>(val.constData()), val.size());
                if (bytes.empty()) throw DatabaseFormatError("Empty db data!");
                while (!bytes.empty()) {
                    auto vint = VarInt::deserialize(bytes);
                    auto txNum = vint.value<uint64_t>();
                    batch.emplace_back(keySlice.ToString(), txNum);
                    batchNums.push_back(txNum);
                    ++i;
                }
                if (batch.size() >= batchSize) {
                    ProcBatch();
                }
            }
            if (!batch.empty()) ProcBatch();
            iter->Reset();
            Log() << "CheckDB: txhash index verified " << verified << " entries in " << t0.secsStr(1) << " secs";
        }

        void rebuildDB() {
            deleteAllEntries();

            constexpr size_t batchSize = 50'000;
            Debug() << "Using key bytes: " << keyBytes << ", batchSize: " << batchSize;
            const Tic t0;
            App *ourApp = app();
            const auto nrec = dra->numRecords();
            std::vector<PreProcessedBlock::TxInfo> fakeInfos;
            for (size_t i = 0; i < nrec; /*i += batchSize*/) {
                if (UNLIKELY(0 == i % 100 && ourApp && ourApp->signalsCaught()))
                    throw UserInterrupted("User interrupted, aborting check"); // if the user hits Ctrl-C, stop the operation
                if (i && 0 == i % 1'000'000) {
                    const double pct = double(i) * 100. / nrec;
                    Log() << "Progress: " << QString::number(pct, 'f', 1) << "%, merge ops so far: " << mergeCount();
                }
                QString err;
                const auto recs = dra->readRecords(i, std::min<size_t>(batchSize, dra->numRecords() - i), &err);
                if (!err.isEmpty()) throw InternalError(QString("Got error from DBRecordArray: ") + err);
                // fake it
                fakeInfos.resize(recs.size());
                for (size_t j = 0; j < recs.size(); ++j)
                    fakeInfos[j].hash = recs[j];
                insertForBlockNoBatch(i, fakeInfos); // this throws on error
                i += fakeInfos.size();
            }
            fakeInfos.clear();
            rocksdb::FlushOptions fopts;
            fopts.wait = true; fopts.allow_write_stall = true;
            if (auto st = db->Flush(fopts, cf); !st.ok())
                Warning() << "DB Flush error: " << StatusString(st);
            Log() << "Indexed " << nrec << " txhash entries, elapsed: " << t0.secsStr(2) << " sec";
        }

        void consistencyCheckSlowRev() {
            Log() << "CheckDB: Verifying txhash index using the thorough reverse-check (this may take a long time) ...";
            const Tic t0;
            size_t i = 0, verified = 0;
            const auto nrec = dra->numRecords();
            constexpr size_t batchSize = 50'000;
            App *ourApp = app();
            for (i = 0; i < nrec; /*i += batchSize*/) {
                if (i && 0 == i % 100'000)
                    Log() << "Verified: " << verified << "/" << nrec << ", merge ops so far: " << mergeCount() << " ...";
                QString err;
                auto recs = dra->readRecords(i, batchSize, &err);
                recs.emplace_back(HashLen, char(0)); // add a dummy at the end
                Util::getRandomBytes(recs.back().data(), HashLen); // put a random hash at the end
                auto results = findMany(recs);
                if (results.size() != recs.size()) throw InternalError("size mismatch: " + err);
                for (size_t j = 0; j < results.size()-1; ++j) {
                    if (!results[j]) throw DatabaseError("Expected a value not nullopt");
                    if (*results[j] != i) {
                        static const std::set<QByteArray> DupeTxHashes = {
                            // Before BIP34, there were dupe coinbase tx's... so we tolerate those here.
                            Util::ParseHexFast("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"),
                            Util::ParseHexFast("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"),
                        };
                        if (!DupeTxHashes.count(recs[j]))
                            throw DatabaseError(QString("Mismatched TxNum for hash: ") + QString(recs[j].toHex()));
                    }
                    ++verified;
                    ++i;
                    if (0 == i % 10 && ourApp && ourApp->signalsCaught()) [[unlikely]]
                        throw UserInterrupted("User interrupted, aborting check"); // if the user hits Ctrl-C, stop the operation
                }
                if (results.back()) Warning() << "Expected last entry to be \"not found\"!";
            }

            Log() << "CheckDB: Verified " << verified << " total tx hashes, merge operations: " << mergeCount()
                  << ", elapsed: " << t0.secsStr(2) << " sec";
        }
    }; // end class TxHash2TxNumMgr

    /* static */ const QByteArray TxHash2TxNumMgr::kLargestTxNumSeenKeyPrefix = "+largestTxNumSeen";

} // namespace

struct Storage::Pvt
{
    Pvt(const unsigned cacheSizeBytes)
        : lruNum2Hash(std::max(unsigned(cacheSizeBytes*kLruNum2HashCacheMemoryWeight), 1u)),
          lruHeight2Hashes_BitcoindMemOrder(std::max(unsigned(cacheSizeBytes*kLruHeight2HashesCacheMemoryWeight), 1u))
    {}

    Pvt(const Pvt &) = delete;

    static constexpr int blockHeaderSize() noexcept { return BTC::GetBlockHeaderSize(); }

    /* NOTE: If taking multiple locks, all locks should be taken in the order they are declared, to avoid deadlocks. */

    Meta meta;
    RWLock metaLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBHandlesEtc {
        const rocksdb::ReadOptions defReadOpts; ///< avoid creating this each time
        const rocksdb::WriteOptions defWriteOpts; ///< avoid creating this each time

        rocksdb::Options opts;
        rocksdb::ColumnFamilyOptions shistOpts, txhash2txnumOpts,txnum2txhashOpts, headersOpts, utxosetOpts;
        std::weak_ptr<rocksdb::Cache> blockCache; ///< shared across all dbs, caps total block cache size across all db instances
        std::weak_ptr<rocksdb::WriteBufferManager> writeBufferManager; ///< shared across all dbs, caps total memtable buffer size across all db instances

        std::shared_ptr<StorageDetail::ConcatOperator> concatOperatorShist, concatOperatorTxHash2TxNum,
                                                       concatOperatorTxNum2TxHash, concatOperatorHeaders;

        std::unique_ptr<rocksdb::DB> db; // the single database we open.
        std::vector<rocksdb::ColumnFamilyHandle *> columnFamilies;

        // These are all either nullptr or pointers for handles that are also contained in the above `columnFamilies` vector
        rocksdb::ColumnFamilyHandle *meta{}, *blkinfo{}, *utxoset{},
                                    *shist{}, *shunspent{}, // scripthash_history and scripthash_unspent
                                    *undo{}, // undo (reorg rewind)
                                    *txnum2txhash{}, // mapping of txNum -> 32-byte hashes
                                    *headers{}, // all blockchain headers
                                    *txhash2txnum{}, // new: index of txhash -> txNumsFile
                                    *rpa{}; // new: height -> Rpa::PrefixTable

        // DBRecordArrays (formerly RecordFiles), these rely on the `db` and ColumnFamilyHandles above being properly opened.
        std::unique_ptr<DBRecordArray> txNumsDRA;
        std::unique_ptr<DBRecordArray> headersDRA;

        struct ColFamSpecificRefs {
            rocksdb::ColumnFamilyHandle *& handle;
            const rocksdb::ColumnFamilyOptions & options;
            std::unique_ptr<DBRecordArray> *const dra = nullptr; // points to null or txNumsDRA or headersDRA above.
        };
        // Some introspection here: the ColFamSpecificRefs point to some of the above members.
        // Note: The order here is important since it influences the order of checkFulc1xUpgradeDB() import!
        const std::vector<std::pair<std::string, ColFamSpecificRefs>> colFamsTable = {
            { "meta",               {.handle = meta,         .options = opts} }, // NB: this *must* be first
            { "blkinfo",            {.handle = blkinfo,      .options = opts} },
            { "headers",            {.handle = headers,      .options = headersOpts,      .dra = &headersDRA} },
            { "utxoset",            {.handle = utxoset,      .options = utxosetOpts} },
            { "scripthash_history", {.handle = shist,        .options = shistOpts} },
            { "scripthash_unspent", {.handle = shunspent,    .options = opts} },
            { "undo",               {.handle = undo,         .options = opts} },
            { "txnum2txhash",       {.handle = txnum2txhash, .options = txnum2txhashOpts, .dra = &txNumsDRA} },
            { "txhash2txnum",       {.handle = txhash2txnum, .options = txhash2txnumOpts} },
            // Note: For Fulc1x import to work 100%, `rpa` below must come *after* `headers` above
            { "rpa",                {.handle = rpa,          .options = opts} },
        };
        auto colFamsTableFind(std::string_view name) {
            return std::find_if(colFamsTable.begin(), colFamsTable.end(),
                                [name](const auto &pair){ return pair.first == name; });
        }

        std::unique_ptr<TxHash2TxNumMgr> txhash2txnumMgr; ///< provides a bit of a higher-level interface into the db

        rocksdb::DB *get() { return db.get(); }
        const rocksdb::DB *get() const { return db.get(); }
        operator rocksdb::DB *() { return get(); }
        operator const rocksdb::DB *() const { return get(); }
        rocksdb::DB * operator->() { return get(); }
        const rocksdb::DB * operator->() const { return get(); }
    };
    unsigned dbReopenCt = 0; ///< The number of times openOrCreateDB() was called
    RocksDBHandlesEtc db;

    bool openOrCreateDBCanNoLongerBeCalled = false; ///< Latched to true after we begin to populate the below data structures from DB.

    /// Big lock used for block/history updates. Public methods that read the history such as getHistory and listUnspent
    /// take this as read-only (shared), and addBlock and undoLatestBlock take this as read/write (exclusively).
    /// This is intended to be a coarse lock.  Currently the update code takes this along with headerVerifierLock and
    /// blkInfoLock at the same time, so it's (as of now) equivalent to either of those two locks.
    /// TODO: See about removing all the other locks and keeping one general RWLock for all updates?
    mutable RWLock blocksLock;

    BTC::HeaderVerifier headerVerifier;
    mutable RWLock headerVerifierLock;

    std::atomic<TxNum> txNumNext{0};

    std::vector<BlkInfo> blkInfos;
    std::map<TxNum, unsigned> blkInfosByTxNum; ///< ordered map of TxNum0 for a block -> index into above blkInfo array
    RWLock blkInfoLock; ///< locks blkInfos and blkInfosByTxNum

    std::atomic_int64_t utxoCt = 0;

    static constexpr uint32_t InvalidUndoHeight = std::numeric_limits<uint32_t>::max();

    std::atomic<uint32_t> earliestUndoHeight = InvalidUndoHeight; ///< the purpose of this is to control when we issue "delete" commands to the db for deleting expired undo infos from the undo db

    // Ratios of cacheMemoryBytes that we give to each of the 2 lru caches -- we do 50/50
    static constexpr double kLruNum2HashCacheMemoryWeight = 0.50;
    static constexpr double kLruHeight2HashesCacheMemoryWeight = 1.0 - kLruNum2HashCacheMemoryWeight;

    /// This cache is anticipated to see heavy use for get_history, so is configurable (config option: txhash_cache)
    /// This gets cleared by undoLatestBlock.
    CostCache<TxNum, TxHash> lruNum2Hash; // NOTE: max size in bytes initted in constructor
    static constexpr unsigned lruNum2HashSizeCalc(unsigned nItems = 1) {
        // NB: each TxHash (aka QByteArray) actually stores HashLen+1 bytes (QByteArray always appends a nul byte)
        // NB2: each TxHash also has the QArrayData overhead (qByteArrayPvtDataSize())
        return unsigned( decltype(lruNum2Hash)::itemOverheadBytes() + (nItems * (Util::qByteArrayPvtDataSize() + HashLen+1)) );
    }

    /// Cache BlockHeight -> vector of txHashes for the block (in bitcoind memory order -- little endian).
    /// This is used by the txHashesForBlock function only (which is used by get_merkle and id_from_pos in the RPC protocol).
    CostCache<BlockHeight, QVector<TxHash>> lruHeight2Hashes_BitcoindMemOrder; // NOTE: max size in bytes initted in constructor
    /// returns the cost for a particular cache item based on the number of hashes in the vector
    static constexpr unsigned lruHeight2HashSizeCalc(size_t nHashes) {
        // each cache item with nHashes takes roughly this much memory
        return unsigned( (nHashes * ((HashLen+1) + sizeof(TxHash) + Util::qByteArrayPvtDataSize()))
                         + decltype(lruHeight2Hashes_BitcoindMemOrder)::itemOverheadBytes() );
    }

    struct LRUCacheStats {
        std::atomic_size_t num2HashHits = 0, num2HashMisses = 0,
                           height2HashesHits = 0, height2HashesMisses = 0;
    } lruCacheStats;

    /// this object is thread safe, but it needs to be initialized with headers before allowing client connections.
    std::unique_ptr<Merkle::Cache> merkleCache;

    HeaderHash genesisHash; // written-to once by either loadHeaders code or addBlock for block 0. Guarded by headerVerifierLock.

    Mempool mempool; ///< app-wide mempool data -- does not get saved to db. Controller.cpp writes to this
    Mempool::FeeHistogramVec mempoolFeeHistogram; ///< refreshed periodically by refreshMempoolHistogram()
    RWLock mempoolLock;

    Tic lastWarned; ///< to rate-limit potentially spammy warning messages (guarded by blocksLock)

    std::unique_ptr<CoTask> blocksWorker; ///< work to be done in parallel can be submitted to this co-task in addBlock and undoLatestBlock

    /// Info specific to the `rpa` index
    struct RpaInfo {
        std::atomic_int32_t firstHeight = -1, lastHeight = -1; // inclusive height range that we have in the DB. -1 means undefined/missing.
        std::atomic_uint64_t nReads{0u}, nWrites{0u}, nDeletions{0u}; // keep track of number of times we read/write/delete from this db
        std::atomic_uint64_t nBytesWritten{0u}, nBytesRead{0u}; // keep track of number of bytes written and read during Storage object lifetime
        mutable std::atomic_int rpaNeedsFullCheckCachedVal = -1; // if > -1, the last value written to the DB. If < 0, no cached val, just read from DB when querying isRpaNeedsFullCheck()
    } rpaInfo;

    /// Set of recent block txids seen, only valid if "notify" is enabled and if app-wide zmq "hashtx" notifs are enabled.
    /// Guarded by `blocksLock`.
    std::unordered_set<TxHash, HashHasher> recentBlockTxHashes;
};

namespace {
    /// returns a key that is hashX concatenated with the serializd ctxo -> size 41 byte vector
    /// Note hashX must be valid and sized HashLen otherwise this throws.
    QByteArray mkShunspentKey(const QByteArray & hashX, const CompactTXO &ctxo) {
        // we do it this way for performance:
        using Size = QByteArray::size_type;
        const Size hxlen = hashX.length();
        if (hxlen != HashLen) [[unlikely]]
            throw InternalError(QString("mkShunspentKey -- scripthash is not exactly %1 bytes: %2").arg(HashLen).arg(QString(hashX.toHex())));
        constexpr bool forceWide = true, bigEndian = true; // this is new Fulcrum 2.x format
        const Size ctxoSerLen = ctxo.serializedSize(forceWide);
        QByteArray key(hxlen + ctxoSerLen, Qt::Uninitialized);
        std::memcpy(key.data(), hashX.constData(), size_t(hxlen));
        const Size nTxoSerBytes = ctxo.toBytesInPlace(reinterpret_cast<std::byte *>(key.data()) + hxlen,
                                                      ctxoSerLen, forceWide, bigEndian);
        if (nTxoSerBytes != ctxoSerLen) [[unlikely]]
            throw InternalError(QString("mkShunspentKey -- nTxoSerBytes != ctxoSerLen! FIXME! (%1 != %2)").arg(nTxoSerBytes).arg(ctxoSerLen));
        return key;
    }
    /// throws if key is not the correct size (must be exactly 40 or 41 bytes)
    CompactTXO extractCompactTXOFromShunspentKey(const rocksdb::Slice &key, bool const legacy) {
        static const auto ExtractHashXHex = [](const rocksdb::Slice &key) -> QString {
            if (key.size() >= HashLen)
                return QString(FromSlice(key).left(HashLen).toHex());
            else
                return "<undecipherable scripthash>";
        };
        if (const auto ksz = key.size();
                (!legacy || ksz != HashLen + CompactTXO::minSize()) && ksz != HashLen + CompactTXO::maxSize()) [[unlikely]]
            // should never happen, indicates db corruption
            throw InternalError(QString("Key size for scripthash %1 is invalid").arg(ExtractHashXHex(key)));
        static_assert (Util::ByteLike<std::remove_pointer_t<decltype(key.data())>>, "Assumption is rocksdb::Slice is basically a byte vector");
        const CompactTXO ctxo =
            CompactTXO::fromBytesInPlaceExactSizeRequired(reinterpret_cast<const std::byte *>(key.data()) + HashLen,
                                                          key.size() - HashLen, !legacy);
        if (UNLIKELY(!ctxo.isValid()))
            // should never happen, indicates db corruption
            throw InternalError(QString("Deserialized CompactTXO is invalid for scripthash %1").arg(ExtractHashXHex(key)));
        return ctxo;
    }
    std::pair<HashX, CompactTXO> extractShunspentKey(const rocksdb::Slice & key, bool const legacy) {
        const CompactTXO ctxo = extractCompactTXOFromShunspentKey(key, legacy); // throws if wrong size
        return {DeepCpy(key.data(), HashLen), ctxo}; // if we get here size ok, can extract HashX
    }

    // Used in openOrCreateDB() and checkFulc1xUpgradeDB().
    constexpr bool BULKLOAD_DISABLES_AUTOCOMPACTION = true;

} // namespace


Storage::Storage(const std::shared_ptr<const Options> & options_)
    : Mgr(nullptr), options(options_),
      subsmgr(new ScriptHashSubsMgr(options, this)),
      dspsubsmgr(new DSProofSubsMgr(options, this)),
      txsubsmgr(new TransactionSubsMgr(options, this)),
      p(std::make_unique<Pvt>(options->txHashCacheBytes))
{
    setObjectName("Storage");
    _thread.setObjectName(objectName());
}

Storage::~Storage() { Debug() << __func__; cleanup(); }

#if ((ROCKSDB_MAJOR << 16)|(ROCKSDB_MINOR << 8)|(ROCKSDB_PATCH)) > ((6 << 16)|(17 << 8)|(3)) // 6.17.3
#define HAS_ROCKSDB_NEW_VERSION_API 1
#else
#define HAS_ROCKSDB_NEW_VERSION_API 0
extern const char* rocksdb_build_git_sha; // internal to rocksdb lib -- if this breaks remove me
#endif
/* static */
QString Storage::rocksdbVersion()
{
#if !HAS_ROCKSDB_NEW_VERSION_API
    QString sha(rocksdb_build_git_sha);
    // rocksdb git commit sha: try and pop off the front part, and keep the rest and take the first 7 characters of that
    if (auto l = sha.split(':'); l.size() == 2) // must match what we expect otherwise don't truncate
        sha = l.back().left(7);
    return QString("%1.%2.%3-%4").arg(ROCKSDB_MAJOR).arg(ROCKSDB_MINOR).arg(ROCKSDB_PATCH).arg(sha);
#else
    const auto dbversion = QString::fromStdString(rocksdb::GetRocksVersionAsString(true));
    const auto sha = []{
        const auto &props = rocksdb::GetRocksBuildProperties();
        if (auto it = props.find("rocksdb_build_git_sha"); it != props.end())
            return QString::fromStdString(it->second).left(7);
        return QString("unk");
    }();
    return QString("%1-%2").arg(dbversion, sha);
#endif
}

namespace {
std::optional<Meta> getMetaFromDBAndDoBasicCompatibilityCheck(rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf, bool legacy)
{
    const QString errMsg1{"Incompatible database format -- delete the datadir and resynch."};
    const QString errMsg2{errMsg1 + " RocksDB error"};
    std::optional<Meta> opt;
    if (!legacy)
        opt = GenericDBGet<Meta>(db, cf, kMeta, true, errMsg2);
    else if (auto opt2 = GenericDBGet<MetaLegacy>(db, cf, kMeta, true, errMsg2)) // use a "type tag" approach to specify legacy deserialization
        opt.emplace(std::move(*opt2)); // slice object back down to `Meta` type
    if (opt) {
        if (!opt->isMagicOk() || !opt->isVersionSupported()
            || (opt->isMinimumExtraPlatformInfoVersion() && opt->platformBits != Meta::kPlatformBits)) {
            throw DatabaseFormatError(errMsg1);
        }
    }
    return opt;
}
} // namespace

void Storage::startup()
{
    Log() << "Loading database ...";

    if (UNLIKELY(!subsmgr || !options || !dspsubsmgr || !txsubsmgr))
        throw BadArgs("Storage instance constructed with nullptr for `options` and/or `subsmgr` and/or `dspsubsmgr` and/or `txsubsmgr` -- FIXME!");

    subsmgr->startup(); // trivial, always succeeds if constructed correctly
    dspsubsmgr->startup(); // trivial, always succeeds if constructed correctly
    txsubsmgr->startup(); // trivial, always succeeds if constructed correctly

    {
        // set up the merkle cache object
        using namespace std::placeholders;
        p->merkleCache = std::make_unique<Merkle::Cache>(std::bind(&Storage::merkleCacheHelperFunc, this, _1, _2, _3));
    }

    // open DB and all column families ...
    openOrCreateDB();

    // check and/or do Fulcrum 1.x -> 2.x DB upgrade (this is different than the internal "checkUpgradeDBVersion" done later
    checkFulc1xUpgradeDB();

    // latch this flag to true to prohibit future calls to openOrCreateDB()
    p->openOrCreateDBCanNoLongerBeCalled = true;

    // load/check meta
    {
        if (const auto opt = getMetaFromDBAndDoBasicCompatibilityCheck(p->db, p->db.meta, false)) {
            const Meta &m_db = *opt;
            p->meta = m_db;
            Debug () << "Read meta from db ok";
            if (!p->meta.coin.isEmpty())
                Log() << "Coin: " << p->meta.coin;
            if (!p->meta.chain.isEmpty())
                Log() << "Chain: " << p->meta.chain;
        } else {
            // ok, did not exist .. write a new one to db
            saveMeta_impl();
        }
        if (isDirty()) {
            throw DatabaseError("It appears that " APPNAME " was forcefully killed in the middle of committing a block to the db. "
                                "We cannot figure out where exactly in the update process " APPNAME " was killed, so we "
                                "cannot undo the inconsistent state caused by the unexpected shutdown. Sorry!"
                                "\n\nThe database has been corrupted. Please delete the datadir and resynch to bitcoind.\n");
        }
    }

    // load headers -- may throw.. this must come first
    loadCheckHeadersInDB();
    // check txnums
    loadCheckTxNumsDRAAndBlkInfo();
    // construct the TxHash2TxNum manager -- depends on the above function having constructed the txNumFile
    loadCheckTxHash2TxNumMgr();
    // count utxos -- note this depends on "blkInfos" being filled in so it much be called after loadCheckTxNumsDRAAndBlkInfo()
    loadCheckUTXOsInDB();
    // very slow check, only runs if -C -C (specified twice)
    loadCheckShunspentInDB();
    // load check earliest undo to populate earliestUndoHeight
    loadCheckEarliestUndo();
    // load rpa data
    if (isRpaEnabled()) loadCheckRpaDB();
    // if user specified --compact-dbs on CLI, run the compaction now before returning
    compactAllDBs();

    // start up the co-task we use in addBlock and undoLatestBlock
    p->blocksWorker = std::make_unique<CoTask>("Storage Worker");

    // Detect old DB version and see if upgrade is permitted, and maybe do a DB upgrade...
    checkUpgradeDBVersion();

    start(); // starts our thread
}

void Storage::openOrCreateDB(bool bulkLoad)
{
    if (p->openOrCreateDBCanNoLongerBeCalled) [[unlikely]] // defensive programming
        throw InternalError(QString("Storage::%1 called after startup has progressed past the point where it can no longer be called! FIXME!").arg(__func__));

    gentlyCloseDB(); // Ensure we start from a clean slate (in case this function is ever called to hot-reopen the DB)

    if (p->dbReopenCt++ > 0) {
        // We must do this to properly reset things to a clean slate
        Util::reconstructAt(&p->db);
    }

    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    rocksdb::Options & opts(p->db.opts);
    rocksdb::ColumnFamilyOptions &shistOpts(p->db.shistOpts), &txhash2txnumOpts(p->db.txhash2txnumOpts),
                                 &txnum2txhashOpts(p->db.txnum2txhashOpts), &headersOpts(p->db.headersOpts),
                                 &utxosetOpts(p->db.utxosetOpts);
    opts.IncreaseParallelism(std::min<int>(16, Util::getNPhysicalProcessors()));
    opts.OptimizeLevelStyleCompaction();
    opts.atomic_flush = true; // flush atomically across all column families
    if constexpr (BULKLOAD_DISABLES_AUTOCOMPACTION)  {
        if (bulkLoad) {
            opts.PrepareForBulkLoad();
            opts.disable_auto_compactions = true;
        }
    }
    for (auto & cmp: opts.compression_per_level) cmp = rocksdb::kNoCompression; // force default "no compression" on all levels

    // setup shared block cache
    rocksdb::BlockBasedTableOptions tableOptions;
    tableOptions.block_cache = rocksdb::NewLRUCache(options->db.maxMem /* capacity limit */, -1, false /* strict capacity limit=off, turning it on made db writes sometimes fail */);
    p->db.blockCache = tableOptions.block_cache; // save shared_ptr to weak_ptr
    tableOptions.cache_index_and_filter_blocks = true; // from the docs: this may be a large consumer of memory, which is why we do the two-level index below

    static constexpr bool TWO_LEVEL_INDEX = true; // enabled for now -- appears to help with performance
    static constexpr auto SetupTwoLevelIndex [[maybe_unused]] = [](rocksdb::BlockBasedTableOptions &topts) {
        topts.index_type = rocksdb::BlockBasedTableOptions::IndexType::kTwoLevelIndexSearch;
        topts.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
        topts.partition_filters = true;
        topts.metadata_block_size = 4096;
        topts.cache_index_and_filter_blocks = true;
        topts.pin_top_level_index_and_filter = true;
        topts.cache_index_and_filter_blocks_with_high_priority = true;
        topts.pin_l0_filter_and_index_blocks_in_cache = true;
    };

    if constexpr (TWO_LEVEL_INDEX)
        SetupTwoLevelIndex(tableOptions);

    // shared TableFactory for all column families
    opts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tableOptions));

    // setup shared write buffer manager (for memtables memory budgeting)
    // - TODO right now we fix the cap of the write buffer manager's buffer size at db.maxMem / 2; tweak this.
    auto writeBufferManager = std::make_shared<rocksdb::WriteBufferManager>(options->db.maxMem / 2/* Disabled to reduce lock contention: , tableOptions.block_cache*/ /* cost to block cache: hopefully this caps memory better? it appears to use locks though so many this will be slow?! TODO: experiment with and without this!! */);
    p->db.writeBufferManager = writeBufferManager; // save shared_ptr to weak_ptr
    opts.write_buffer_manager = writeBufferManager; // will be shared across all column families

    // create the DB if it's not already present
    opts.create_if_missing = true;
    opts.error_if_exists = false;
    opts.compression = rocksdb::CompressionType::kNoCompression; // for now we go without compression. TODO: characterize what is fastest and best..
    if (!bulkLoad) {
        opts.max_open_files = options->db.maxOpenFiles <= 0 ? -1 : options->db.maxOpenFiles; ///< this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112
        opts.keep_log_file_num = options->db.keepLogFileNum;
        opts.use_fsync = options->db.useFsync; // the false default is perfectly safe, but Jt asked for this as an option, so here it is.
    }

    auto OptimizeForPointLookup = [this](rocksdb::ColumnFamilyOptions &cfopts) {
        rocksdb::BlockBasedTableOptions block_based_options;
        block_based_options.data_block_index_type = rocksdb::BlockBasedTableOptions::kDataBlockBinaryAndHash;
        block_based_options.data_block_hash_table_util_ratio = 0.75;
        if constexpr (TWO_LEVEL_INDEX)
            SetupTwoLevelIndex(block_based_options);
        else
            block_based_options.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10));
        block_based_options.block_cache = p->db.blockCache.lock();
        block_based_options.cache_index_and_filter_blocks = true;
        cfopts.table_factory.reset(rocksdb::NewBlockBasedTableFactory(block_based_options));
        cfopts.memtable_prefix_bloom_size_ratio = 0.02;
        cfopts.memtable_whole_key_filtering = true;
    };

    shistOpts = opts; // copy what we just did (will implicitly copy over the shared table_factory and write_buffer_manager)
    shistOpts.merge_operator = p->db.concatOperatorShist = std::make_shared<StorageDetail::ConcatOperator>(); // this set of options uses the concat merge operator (we use this to append to history entries in the db)
    OptimizeForPointLookup(shistOpts);

    txhash2txnumOpts = opts;
    txhash2txnumOpts.merge_operator = p->db.concatOperatorTxHash2TxNum = std::make_shared<StorageDetail::ConcatOperator>();
    OptimizeForPointLookup(txhash2txnumOpts);

    txnum2txhashOpts = opts;
    txnum2txhashOpts.merge_operator = p->db.concatOperatorTxNum2TxHash = std::make_shared<StorageDetail::ConcatOperator>();

    headersOpts = opts;
    headersOpts.merge_operator = p->db.concatOperatorHeaders = std::make_shared<StorageDetail::ConcatOperator>();

    utxosetOpts = opts;
    OptimizeForPointLookup(utxosetOpts);

    using ColFamsTableRow = decltype(p->db.colFamsTable)::value_type;
    std::map<ColFamsTableRow::first_type, ColFamsTableRow::second_type> colFamsNeeded;
    for (const auto & pair : p->db.colFamsTable)
        if ( ! colFamsNeeded.emplace(pair).second) [[unlikely]]
            throw InternalError(QString("INTERNAL ERROR! Duplicate colFamsTable key %1 in %2. FIXME!")
                                    .arg(QString::fromStdString(pair.first), __func__));

    // First, open the DB, and then determine which column families it has, and open them all.
    {
        const QString path = options->datadir + QDir::separator() + kDBName;

        if (bulkLoad) {
            // For bulkLoad mode, we should just start with a clean slate. rm -fr the current DB
            QDir existingDB(path);
            if (existingDB.exists()) {
                Debug() << "BulkLoad mode requires a fresh DB; deleting existing directory \"" << path << "\" ...";
                if (!existingDB.removeRecursively()) throw InternalError("Error removing directory: " + path);
            }
        }

        rocksdb::Status s;

        std::vector<rocksdb::ColumnFamilyDescriptor> colFamDescs;
        {
            std::vector<std::string> haveColFams;
            s = rocksdb::DB::ListColumnFamilies(opts, path.toStdString(), &haveColFams);
            if (s.ok()) {
                colFamDescs.reserve(haveColFams.size());
                for (const auto &colName : haveColFams) {
                    QString extra;
                    // determine option for this column family
                    std::optional<rocksdb::ColumnFamilyOptions> optOptions;
                    if (auto it = colFamsNeeded.find(colName); it != colFamsNeeded.end()) {
                        optOptions = std::move(it->second.options);
                        // mark db cols that the db has that we want as "no longer needed"
                        colFamsNeeded.erase(it);
                    } else if (colName == rocksdb::kDefaultColumnFamilyName) {
                        extra = " (ignored)";
                    } else {
                        extra = " (UNKNOWN)";
                    }
                    Debug() << "Found DB column family '" << QString::fromStdString(colName) << "'" << extra;
                    colFamDescs.emplace_back(colName, optOptions.value_or(opts));
                }
            } else {
                QString sstr;
                if (s.IsIOError() && !QFileInfo::exists(path))
                    sstr = " (new db)";
                else
                    sstr = ": " + StatusString(s);
                Debug() << "Failed to list column families for DB '" << kDBName << "'" << sstr;
                // Might as well specify that we want to open the "default" column family here
                colFamDescs.emplace_back(rocksdb::kDefaultColumnFamilyName, opts);
            }
        }

        rocksdb::DB *db = nullptr;
        s = rocksdb::DB::Open(opts, path.toStdString(), colFamDescs, &p->db.columnFamilies, &db);
        p->db.db.reset(db);
        if (!s.ok() || !db)
            throw DatabaseError(QString("Error opening %1 database: %2 (path: %3)")
                                    .arg(kDBName, StatusString(s), path));
    }

    rocksdb::DB * const db = p->db;
    assert(db != nullptr);

    // Next, for all the colFamsNeeded that weren't in the DB already (new DB, etc), create them!
    {
        std::vector<rocksdb::ColumnFamilyDescriptor> colFamDescs;
        for (const auto & [name, params] : colFamsNeeded) {
            colFamDescs.emplace_back(name, params.options);
        }
        if (!colFamDescs.empty()) {
            std::vector<rocksdb::ColumnFamilyHandle *> handles;
            auto s = db->CreateColumnFamilies(colFamDescs, &handles);
            // "save" the successfully opened handles so we can close them later even on erro
            for (auto *h : handles) {
                p->db.columnFamilies.push_back(h);
                colFamsNeeded.erase(h->GetName());
            }
            // error out if there was a problem
            if (!s.ok()) {
                throw DatabaseError(QString("Error opening %1 column families: %2").arg(quint64(colFamDescs.size()))
                                        .arg(StatusString(s)));
            }
        }
    }

    // Lastly, assign the ColumnFamilyHandle pointers ...
    for (rocksdb::ColumnFamilyHandle *h : p->db.columnFamilies) {
        const auto &name = h->GetName();
        if (auto it = p->db.colFamsTableFind(name); it != p->db.colFamsTable.end()) [[likely]] {
            // assign ptr; this modifies members: p.db.meta, p.db.blkinfo, etc..
            it->second.handle = h;
        } else if (name != rocksdb::kDefaultColumnFamilyName) [[unlikely]] {
            throw DatabaseError(QString("Encountered an unknown column family in DB: %1"
                                        " -- incompatible or newer than expected database, perhaps?")
                                    .arg(QString::fromStdString(name)));
        }
    }

    if (!colFamsNeeded.empty()) [[unlikely]] {
        QStringList names;
        for (const auto & [name, _] : colFamsNeeded) names.append(QString::fromStdString(name));
        throw InternalError("Missing column families: " + names.join(", "));
    }

    if (!p->db.blkinfo || !p->db.meta || !p->db.rpa || !p->db.shist || !p->db.shunspent || !p->db.txhash2txnum
        || !p->db.utxoset || !p->db.undo || !p->db.txnum2txhash || !p->db.headers) [[unlikely]]
        throw InternalError("A required column family handle is still nullptr! FIXME!");

    // Open the two DBRecordArrays now. Note: Changing the recordSize, bucketNItems, and magic params *WILL* produce a
    // database incompatibility!
    p->db.txNumsDRA =  std::make_unique<DBRecordArray>(*p->db, *p->db.txnum2txhash,
                                                       /* recSize = */ HashLen,
                                                       /* bucketNItems = */ 16,
                                                       /* magic = */ 0x000012e2); // may throw
    p->db.headersDRA = std::make_unique<DBRecordArray>(*p->db, *p->db.headers,
                                                       /* recSz = */ size_t(p->blockHeaderSize()),
                                                       /* bucketNItems = */ 8,
                                                       /* magic = */ 0x00f026a1); // may throw


    Debug() << "DB opened in " << (!bulkLoad ? "normal" : "\"bulk load\"") << " mode";

    if (p->dbReopenCt == 1)
        Log() << "DB memory: " << QString::number(options->db.maxMem / 1024. / 1024., 'f', 2) << " MiB";
}

void Storage::checkFulc1xUpgradeDB()
{
    // ---- Fulcrum 1.x DB upgrade test code ----

    // Ensure "meta" column family is first (below code relies on this invariant)
    if (p->db.colFamsTableFind("meta") != p->db.colFamsTable.begin())
        throw InternalError("The `meta` column family MUST be listed first in `colFamsTable`! FIXME!");

    const QString dataDirPrefix = options->datadir + QDir::separator();
    qint64 largestElementSeenByteSize{};
    const bool hasAllFulcrum1DBElements = [&] {
        // check if all of the recordfiles and db dirs exist
        for (const auto & [name, params] : p->db.colFamsTable) {
            if (params.dra) { // old 1.x format for this item is a RecordFile, check the file exists
                QFileInfo info(dataDirPrefix + QString::fromStdString(name));
                if (!info.exists() || !info.isFile())
                    return false;
                largestElementSeenByteSize = std::max(info.size(), largestElementSeenByteSize);
            } else { // old 1.x format is a separate database dir
                QDir dir(dataDirPrefix + QString::fromStdString(name));
                if (! dir.exists())
                    return false;
                qint64 totalSize = 0;
                for (const auto & info : dir.entryInfoList(QDir::Filter::Files | QDir::Filter::NoSymLinks))
                    totalSize += info.size();
                largestElementSeenByteSize = std::max(totalSize, largestElementSeenByteSize);
            }
        }
        return true;
    }();

    if (!hasAllFulcrum1DBElements) {
        if (options->db.doUpgrade)
            Warning() << "CLI argument --db-upgrade requested but no " << APPNAME << " 1.x database found in "
                      << options->datadir;
        return;
    } // else ...
    // hasAllFulcrum1DBElements == true below..
    if (!options->db.doUpgrade)
        throw BadArgs(QString("\nThe data directory \"%1\" contains an older %2 1.x database. It can be upgraded"
                              "\nto the latest format, but you need to explicitly request this to occur, since"
                              "\nthe upgrade process is destructive and irreversible.\n\n"
                              "Please specify CLI argument --db-upgrade to upgrade the database to the latest"
                              "\nformat.").arg(options->datadir, APPNAME));

    // Ok, upgrade DB

    constexpr int timeoutSecs = 10;
    auto PrintCountdownMessage = [&] {
        Log() << "\n\n************************\n"
                 "*** Database Upgrade ***\n"
                 "************************\n"
                 "This will take some time and is irreversible and uninterruptible. If unsure, hit CTRL-C"
                 "\nnow and either take a backup of the database directory or do a full resynch to bitcoind."
                 "\nOtherwise, wait for the timeout to occur and the upgrade process will commence.\n";
        for (int i = 0; i < timeoutSecs && !app()->signalsCaught(); ++i) {
            const auto secs = (timeoutSecs - i);
            Log() << "Upgrade will begin in " << secs << Util::Pluralize(" second", secs) << ", hit CTRL-C now to abort ...";
            using namespace std::chrono_literals;
            std::this_thread::sleep_for(1s);
        };
    };
    if (QThread::currentThread() != app()->thread()) {
        std::promise<void> promise;
        auto future = promise.get_future();
        Util::AsyncOnObject(app(), [&]{
            PrintCountdownMessage();
            promise.set_value();
        });
        future.get(); // wait for above to complete
    } else {
        PrintCountdownMessage();
    }
    if (app()->signalsCaught()) throw UserInterrupted("User interrupted, aborting upgrade");

    // Reopen the DB in "bulk load" mode
    openOrCreateDB(true);

    // Size sanity check -- we need enough space for each old DB table and/or record file to be copied and then
    // deleted item by item...paranoia: require largest element seen size + 1GB
    if (qint64 req = largestElementSeenByteSize + 1'000'000'000u, avail = QStorageInfo(options->datadir).bytesAvailable(); avail < req)
        throw Exception(QString("Not enough disk space in directory \"%1\" to proceed with upgrade. Free up at least %2 MB of space.")
                            .arg(options->datadir).arg(static_cast<qint64>(std::ceil((req - avail) / 1024.0 / 1024.0))));

    // Commence the upgrade....!
    Tic totalElapsed;
    uint64_t totalRowCt{}, totalByteCt{}, totalBatchCt{}, totalConvCt{};
    size_t totalTableCt{};

    // We disable signals since it would be *unsafe* to close the app during this process!
    app()->setSignalsIgnored(true);
    Defer d([]{ app()->setSignalsIgnored(false); }); // restore signals on scope end

    constexpr size_t batchSize = 2'000'000u;
    Debug() << "Using batch size: " << batchSize;

    rocksdb::DB * const db = p->db;
    assert(db);
    rocksdb::WriteOptions fastButLessSafeWrOpts;
    // this option leads to faster writes at the expense of potential database corruption on hard crash :/
    fastButLessSafeWrOpts.disableWAL = true;

    auto doCompaction = [&](const auto &name, const auto &info) {
        Log() << "Compacting: " << name << " ...";
        rocksdb::CompactRangeOptions copts;
        copts.exclusive_manual_compaction = true;
        copts.allow_write_stall = true;
        if (auto st = db->CompactRange(copts, info.handle, nullptr, nullptr); !st.ok())
            Warning() << "CompactRange of " << name << " returned error status: " << StatusString(st);
    };

    auto performFlush = [&](const auto &name, const auto &info) {
        if constexpr (BULKLOAD_DISABLES_AUTOCOMPACTION)
            doCompaction(name, info);
        Debug() << "Flushing column family: " << name << " ...";
        rocksdb::FlushOptions fopts;
        fopts.wait = true; fopts.allow_write_stall = true;
        if (auto st = db->Flush(fopts, info.handle); !st.ok())
            Warning() << "Flush of " << name << " returned error status: " << StatusString(st);
        Debug() << "Synching WAL ...";
        db->SyncWAL();
    };

    auto deleteAllRowsInColumnFamily = [&](const auto &name, const auto &info, const bool isMetaTable) {
        std::unique_ptr<rocksdb::Iterator> iter(db->NewIterator(p->db.defReadOpts, info.handle));
        iter->SeekToLast();
        std::optional<rocksdb::WriteBatch> optBatch;
        if (iter->Valid()) {
            Debug() << "Clearing all rows in column family " << name << " ...";
            std::string pastEndKey;
            const rocksdb::Slice lastKey = iter->key();
            pastEndKey.reserve(1u + lastKey.size());
            pastEndKey.insert(pastEndKey.end(), static_cast<char>(0xffu));
            pastEndKey.insert(pastEndKey.end(), lastKey.data(), lastKey.data() + lastKey.size());
            iter.reset(); // kill the iterator now to free "snapshot" resources before doing the delete
            if (auto st = optBatch.emplace().DeleteRange(info.handle, {}, pastEndKey); !st.ok())
                throw DatabaseError("rocksdb::WriteBatch::DeleteRange returned error: " + StatusString(st));
        }
        if (isMetaTable) {
            // we just encountered the `meta` table, which is always first -- set the dirty flag now!
            if (!optBatch) optBatch.emplace();
            setDirty(*optBatch, true);
            Debug() << "Set DB 'dirty' flag";
        }
        if (optBatch) {
            if (auto st = p->db->Write(p->db.defWriteOpts, &*optBatch); !st.ok())
                throw DatabaseError("rocksdb::DB::Write returned error: " + StatusString(st));
        }
    };

    std::optional<std::vector<QByteArray>> shortBlockHashes; // calculated for us as we import `headers` and used by the rpa table import

    for (const auto & [sname, info] : p->db.colFamsTable) {
        const auto name = QString::fromStdString(sname);
        const auto fname = dataDirPrefix + name;
        if (!info.dra) {
            // DB table -> DB column family import (full db table copy for each Fulcrum 1.x table)
            Tic t0;
            Log() << "Importing table `" << name << "` ...";
            rocksdb::Options dbopts;
            // NB: the below should match original DB, in particular the num_levels must match otherwise Open() errors out.
            dbopts.IncreaseParallelism(std::min<int>(16, Util::getNPhysicalProcessors()));
            dbopts.OptimizeLevelStyleCompaction();
            dbopts.disable_auto_compactions = true;
            dbopts.create_if_missing = false;
            dbopts.error_if_exists = false;
            dbopts.compression = rocksdb::kNoCompression;
            if (info.options.merge_operator) dbopts.merge_operator = info.options.merge_operator;
            dbopts.comparator = info.options.comparator; // should always be default BytewiseComparator, but defensively we ensure that is the case

            rocksdb::DB *dbin_raw{};
            if (auto st = rocksdb::DB::Open(dbopts, fname.toStdString(), &dbin_raw); !st.ok()) {
                throw DatabaseError("rocksdb::DB::Open returned error for " + name + ": " + StatusString(st));
            }
            std::unique_ptr<rocksdb::DB> dbin(dbin_raw);
            const bool isMetaTable = info.handle == p->db.meta;
            std::optional<QByteArray> convertedDbMetaSerialization; // upgraded/converted 'kMeta' row (class: Meta)

            const bool isTableRequiringLEtoBEKeyConv = info.handle == p->db.undo || info.handle == p->db.blkinfo;
            const bool isShunspentTable = info.handle == p->db.shunspent;
            const bool isRpaTable = info.handle == p->db.rpa;

            // If encountering the "meta" table (which is always first!), check that Fulcrum 1.x did not have the DB
            // flaged as "dirty".
            if (isMetaTable) {
                if (isDirty_impl(dbin.get(), dbin->DefaultColumnFamily())) {
                    throw DatabaseError(QString("It appears that the database in \"%1\" from %2 1.x is corrupt. Cannot"
                                                " proceed with DB upgrade. Sorry!"
                                                "\n\nPlease delete the datadir and resynch to bitcoind.\n")
                                            .arg(fname, APPNAME));
                }
                // The below throws if the 'Meta' entry is bad due to endian mismatch (since Fuclrum 1.x saved data in host endian format)
                if (auto legacyMeta = getMetaFromDBAndDoBasicCompatibilityCheck(dbin.get(), dbin->DefaultColumnFamily(), /*legacy=*/true))
                    convertedDbMetaSerialization.emplace(Serialize(*legacyMeta));

            }
            else if (isTableRequiringLEtoBEKeyConv)
                Debug() << name << " table conversion will take place; will convert all height keys to big endian";
            else if (isShunspentTable)
                Debug() << name << " table conversion will take place; will convert all hashx:ctxo keys to use big-endian encoding for ctxos";
            else if (isRpaTable)
                Debug() << name << " table conversion will take place; will convert all values to have the "
                        << kRpaShortBlockHashLen << "-byte shortBlockHash prefix";

            // Everything so far ok, create an iterator over the input DB table
            auto rdOpts = p->db.defReadOpts;
            rdOpts.auto_readahead_size = false;
            rdOpts.adaptive_readahead = false;
            rdOpts.readahead_size = 128 * 1024 * 1024;
            rdOpts.async_io = true;
            rdOpts.fill_cache = false;
            std::unique_ptr<rocksdb::Iterator> iterin(dbin->NewIterator(rdOpts));

            // Clear existing table from our DB
            deleteAllRowsInColumnFamily(name, info, isMetaTable);

            // Copy each row in dbin to the correct column family
            rocksdb::WriteBatch batch;
            uint64_t byteCt{}, totalCt{};
            size_t batchCt{};
            long lastPrt = 0;
            Tic t1;
            auto doDBWrite = [&] {
                if (auto st = db->Write(fastButLessSafeWrOpts, &batch); !st.ok())
                    throw DatabaseError("Error writing batch: " + StatusString(st));
                Util::reconstructAt(&batch); // NB: We must do this because the WriteBatch object appears to leak and/or eat enormous memory if it keeps getting re-used
                Debug() << "Processed " << batchCt << " rows in " << t1.msecStr() << " msec";
                if (auto now = t0.secs<long>(); now >= lastPrt + 10) {
                    lastPrt = now;
                    const auto & [scaled, unit] = Util::ScaleBytes(byteCt);
                    const auto scaledStr = QString::number(scaled, 'f', unit != "bytes" ? 1 : 0);
                    Log() << "Progress: " << totalCt << " rows, " << scaledStr << " " << unit << ", in " << t0.secsStr() << " secs";
                }
                ++totalBatchCt;
                batchCt = 0;
                t1 = Tic();
            };
            for (iterin->SeekToFirst(); iterin->Valid(); iterin->Next()) {
                // Do any conversions below. We convert the following:
                // - `meta` table entry "meta", we little-endian-ify the struct Meta serialization
                // - `undo` & `blkinfo` table: All keys get converted from little endian -> big endian encoding (for better sorting)
                // - `shunspent` table: All keys get reformated with uniform-sized keys and the CompactTXO is serialized in big-endian order for better sorting.
                rocksdb::Slice keyToWrite = iterin->key(), valueToWrite = iterin->value();
                std::optional<QByteArray> convertedKeyBytes, convertedValueBytes;
                if (isMetaTable) [[unlikely]]  {
                    if (keyToWrite == kDirty) {
                        // do *not* copy the dirty flag for the meta table so as to not clear the fact that we are "dirty" now...
                        Debug() << "Skipped meta table entry: " << keyToWrite.ToString();
                        continue;
                    } else if (keyToWrite == kMeta) {
                        // NB: if this branch is taken, `convertedDbMetaSerialization` must .has_value()
                        FatalAssert(convertedDbMetaSerialization.has_value(), "Defensive programming check failed");
                        valueToWrite = ToSlice(convertedDbMetaSerialization.value()); // ensure endian-neutral encoding
                        Debug() << "Converted meta table entry: " << keyToWrite.ToString();
                        ++totalConvCt;
                    }
                } else if (isTableRequiringLEtoBEKeyConv) {
                    // Convert the "height" key from little endian to big endian (should perform slightly better because it will be fully sorted)
                    bool ok;
                    const uint32_t height = DeserializeScalar<uint32_t, /*BigEndian=*/false>(FromSlice(iterin->key()), &ok);
                    if (!ok || height >= MAX_HEADERS)
                        throw DatabaseFormatError(QString("Expected a key in table '%1' to be a serialized little-endian"
                                                          " integer < %3; instead got: %4 (hex: %2)")
                                                  .arg(name, QString::fromLatin1(FromSlice(iterin->key()).toHex())).arg(MAX_HEADERS).arg(height));
                    // convert to big endian encoding
                    keyToWrite = ToSlice(convertedKeyBytes.emplace(SerializeScalar</*BigEndian=*/true,
                                                                                   /*Ephemeral=*/false>(height)));
                    ++totalConvCt;
                } else if (isShunspentTable) {
                    const auto & [hashX, ctxo] = extractShunspentKey(iterin->key(), /*legacy=*/true); // parse legacy key; may throw
                    keyToWrite = ToSlice(convertedKeyBytes.emplace(mkShunspentKey(hashX, ctxo))); // convert to latest format
                    ++totalConvCt;
                } else if (isRpaTable) {
                    try {
                        bool ok = false;
                        const uint32_t height = Deserialize<RpaDBKey>(FromSlice(keyToWrite), &ok).height;
                        if (!ok) [[unlikely]] throw Exception("Failed to deserialize RpaDBKey");
                        if (!shortBlockHashes) [[unlikely]] throw Exception("No `shortBlockHashes` exists. Was table `headers` imported yet?");
                        if (height >= shortBlockHashes->size()) [[unlikely]] {
                            Debug() << "Got rpa entry for height: " << height << ", which is >= the shortBlockHashes"
                                    << " size of: " << shortBlockHashes->size() << ", skipping ...";
                            continue; // skip this row
                        }
                        convertedValueBytes.emplace().reserve(kRpaShortBlockHashLen + valueToWrite.size());
                        convertedValueBytes->append((*shortBlockHashes)[height]);
                        convertedValueBytes->append(FromSlice(valueToWrite));
                        valueToWrite = ToSlice(*convertedValueBytes); // make the valueToWrite slice point to our new buffer
                    } catch (const std::exception &e) {
                        Warning() << "Got an exception in processing a row for the RPA table, aborting RPA data import"
                                  << "early. Exception: " << e.what();
                        break; // break out of enclosing for() loop that iterates over the rpa table
                    }
                    ++totalConvCt;
                }
                const auto byteSz = keyToWrite.size() + valueToWrite.size();
                byteCt += byteSz;
                totalByteCt += byteSz;
                if (auto st = batch.Put(info.handle, keyToWrite, valueToWrite); !st.ok())
                    throw DatabaseError("rocksdb batch.Put returned error: " + StatusString(st));
                ++totalCt; ++totalRowCt;
                if (++batchCt >= batchSize) [[unlikely]]
                    doDBWrite();
            }
            if (batchCt) // write final batch, if any
                doDBWrite();

            // perform flush
            performFlush(name, info);

            if (isRpaTable) shortBlockHashes.reset(); // clear this memory since it's no longer needed

            const auto & [scaled, unit] = Util::ScaleBytes(byteCt);
            const auto scaledStr = QString::number(scaled, 'f', unit != "bytes" ? 1 : 0);
            Log() << "Imported " << totalCt << " rows, " << scaledStr << " " << unit << ", in " << t0.secsStr() << " secs";
            iterin.reset();
            if (auto st = dbin->Close(); !st.ok())
                Warning() << "rocksdb::DB::Close returned error: " << st.ToString();
            dbin.reset();
            // Delete directory for old DB
            Log() << "Deleting directory \"" << fname << "\" ...";
            if (!QDir(fname).removeRecursively()) Warning() << "Error removing directory: " << fname;
        } else {
            // RecordFile -> DBRecordArray import
            const size_t rfBatchSize = batchSize / 10u;
            DBRecordArray *dra = info.dra->get();
            auto rf = std::make_unique<RecordFile>(fname, dra->recordSize(), dra->magicBytes());
            const size_t numRecs = rf->numRecords();
            Tic t0;
            Log() << "Importing " << numRecs << " records from RecordFile `" << name << "` ...";

            // Clear existing table from our DB
            deleteAllRowsInColumnFamily(name, info, false);

            struct ShortHashTask {
                std::mutex lock;
                std::vector<Header> queue; // guarded by lock
                std::vector<QByteArray> shortHashes; // guarded by lock
                std::atomic_size_t totalBytes{0u};

                std::vector<Header> headerBatch; // buffer used by master thread

                CoTask task{"ShortHashTask", true};
                std::optional<CoTask::Future> fut;

                ShortHashTask() = default;

                void pushBatch(const std::vector<Header> & hdrs) {
                    headerBatch.insert(headerBatch.end(), hdrs.begin(), hdrs.end());
                    workOnBatchInParallel();
                }

                void workOnBatchInParallel() {
                    if (headerBatch.empty()) return;
                    {
                        std::unique_lock g(lock);
                        if (queue.empty()) queue.swap(headerBatch);
                        else {
                            queue.insert(queue.end(), headerBatch.begin(), headerBatch.end());
                            headerBatch.clear();
                        }
                    }
                    // re-assigning to an existing `fut` may implicitly wait for previous work to complete
                    fut.emplace(task.submitWork([this]{ processQueue(); }));
                }

                void waitForWorkToComplete() { if (fut) fut.reset(); }

            private:
                void processQueue() {
                    for (;;) {
                        std::vector<Header> q;
                        { std::unique_lock g(lock); q.swap(queue); }
                        if (q.empty()) return;
                        std::vector<QByteArray> res;
                        res.reserve(q.size());
                        for (const auto & header : q)
                            totalBytes += res.emplace_back(BTC::HashRev(header).right(kRpaShortBlockHashLen)).size();
                        std::unique_lock g(lock);
                        if (shortHashes.empty()) shortHashes.swap(res);
                        else shortHashes.insert(shortHashes.end(), res.begin(), res.end());
                    }
                }
            };

            std::optional<ShortHashTask> headerTask;

            if (info.handle == p->db.headers && numRecs)
                headerTask.emplace(); // when importing headers, we also calculate the "short hashes" for later rpa import

            Tic t1;
            long lastPrt = 0;
            uint64_t totalCt{}, byteCt{};
            size_t writeBatchCt{};
            rocksdb::WriteBatch batch;
            auto doDBWrite = [&] {
                if (headerTask) headerTask->workOnBatchInParallel();
                if (auto st = db->Write(fastButLessSafeWrOpts, &batch); !st.ok())
                    throw DatabaseError("Error writing batch: " + StatusString(st));
                Util::reconstructAt(&batch); // NB: We must do this because the WriteBatch object appears to leak and/or eat enormous memory if it keeps getting re-used
                Debug() << "Processed " << writeBatchCt << " records in " << t1.msecStr() << " msec";
                if (auto now = t0.secs<long>(); now >= lastPrt + 10) {
                    lastPrt = now;
                    const auto & [scaled, unit] = Util::ScaleBytes(byteCt);
                    const auto scaledStr = QString::number(scaled, 'f', unit != "bytes" ? 1 : 0);
                    Log() << "Progress: " << totalCt << " records, " << scaledStr << " " << unit << ", in " << t0.secsStr() << " secs";
                }
                writeBatchCt = 0;
                t1 = Tic();
            };
            for (size_t recNum = 0, lastBatchSize = 0; recNum < numRecs; recNum += lastBatchSize) {
                QString err;
                auto records = rf->readRecords(recNum, rfBatchSize, &err);
                lastBatchSize = records.size();
                if (!lastBatchSize) [[unlikely]]
                    throw DatabaseError("Error reading RecordFile: " + err);

                if (headerTask)
                    headerTask->pushBatch(records);

                auto ctx = dra->beginBatchWrite(batch);
                if (!recNum) [[unlikely]] ctx.truncate(0); // first pass through, truncate DBRecordArray to 0.
                for (const auto & rec : records) {
                    if (rec.isEmpty()) [[unlikely]] throw DatabaseError("Empty record found in recordfile!");
                    if (!ctx.append(rec, &err)) [[unlikely]] throw DatabaseError("Error writing to DBRecordArray: " + err);
                    byteCt += static_cast<size_t>(rec.size());
                    totalByteCt += static_cast<size_t>(rec.size());
                    ++totalCt;
                    ++totalRowCt;
                    ++writeBatchCt;
                }
                ++totalBatchCt;

                if (writeBatchCt >= batchSize)
                    doDBWrite();
            }
            if (writeBatchCt)
                doDBWrite();

            // perform flush
            performFlush(name, info);

            // wait for header work, if any
            if (headerTask) {
                DebugM(name, ": grabbing short block hashes from CoTask ...");
                headerTask->waitForWorkToComplete();
                shortBlockHashes.emplace(std::move(headerTask->shortHashes)).shrink_to_fit();
                const size_t memUsed = headerTask->totalBytes.load() + sizeof(*shortBlockHashes)
                                       + shortBlockHashes->size() * Util::qByteArrayPvtDataSize(false)
                                       + shortBlockHashes->capacity() * sizeof(decltype(shortBlockHashes)::value_type::value_type);
                headerTask.reset();
                const auto ct = shortBlockHashes->size();
                const auto & [scaled, unit] = Util::ScaleBytes(memUsed);
                DebugM(name, ": calculated ", ct, Util::Pluralize(" short block hash", ct), ", ",
                       QString::number(scaled, 'f', unit != "bytes" ? 1 : 0), " ", unit, " (for upcoming potential rpa import)");
            }

            const auto & [scaled, unit] = Util::ScaleBytes(byteCt);
            const auto scaledStr = QString::number(scaled, 'f', 1);
            Log() << "Imported " << totalCt << " records, " << scaledStr << " " << unit << ", in " << t0.secsStr() << " secs";

            // Delete the RecordFile we just imported
            rf.reset();
            Log() << "Deleting file \"" << fname << "\" (size: " << QFileInfo(fname).size() << ") ...";
            if (!QFile::remove(fname)) Warning() << "Error deleting: " << fname;
        }
        ++totalTableCt;
    }

    // Everything is done, clear the "dirty" flag and print some stats
    {
        rocksdb::WriteBatch batch;
        setDirty(batch, false);
        if (auto st = p->db->Write(fastButLessSafeWrOpts, &batch); !st.ok())
            throw DatabaseError("Error writing batch: " + StatusString(st));
        {
            rocksdb::FlushOptions fopts;
            fopts.wait = true; fopts.allow_write_stall = true;
            if (auto st = db->Flush(fopts, p->db.meta); !st.ok())
                Warning() << "Flush of meta: " << StatusString(st);
            db->SyncWAL();
        }
        Debug() << "Cleared DB 'dirty' flag";
    }

    // Finally, re-open in non-bulk mode
    openOrCreateDB(false);

    const auto & [scaled, unit] = Util::ScaleBytes(totalByteCt);
    const auto scaledStr = QString::number(scaled, 'f', 1);

    Log() << "Completed DB upgrade. Imported " << totalTableCt << " tables, " << totalRowCt << " rows (of which "
          << totalConvCt << " were converted), " << totalBatchCt << " write batches, "
          << scaledStr << " " << unit << " in "
          << totalElapsed.secsStr(1) << " seconds.";
}

void Storage::checkUpgradeDBVersion()
{
    // Note: A precondition for this function is that database, headers, etc are already loaded.

    // Original Fulcrum DB version before 1.9.0 was v1, then there was v2 which added CashToken data for BCH.
    // Now we are on v3 as of 1.11.0+, whose only difference vs v2 is additional platform info saved to `Meta`.
    //
    // Going from v1 on BTC/LTC -> v2+ is ok without caveats. For BCH, we must warn the user if their DB is v1
    // and it's after the upgrade9 activation time, because then the DB will be missing token data and may have
    // token-containing UTXOs indexed to the wrong script hash.
    Log() << "DB version: v" << p->meta.version;
    if (p->meta.isMinimumExtraPlatformInfoVersion()) {
        Debug() << "DB last written-to by: " << p->meta.appName << " " << p->meta.appVersion
                << " using rocksdb: " << p->meta.rocksDBVersion;
        Debug() << "DB last written-to OS: " << p->meta.osName << ", CPU: " << p->meta.cpuArch << ", ABI: " << p->meta.buildABI
                << ", bits: " << p->meta.platformBits;
    }
    if (p->meta.version < Meta::kCurrentVersion) {
        if (BTC::coinFromName(p->meta.coin) == BTC::Coin::BCH && p->meta.version < Meta::kMinBCHUpgrade9Version) {
            // Get the latest header to detect if we are after the activation time
            const Header hdr = headerVerifier().first.lastHeaderProcessed().second;
            if (hdr.size() == BTC::GetBlockHeaderSize()) {
                const auto bhdr = [&hdr] {
                    try {
                        return BTC::Deserialize<bitcoin::CBlockHeader>(hdr, 0, false, false, true, true);
                    } catch (const std::ios_base::failure &e) {
                        throw InternalError(QString("checkUpgradeDBVersion: Failed to deserialize the latest block"
                                                    " header: %1").arg(e.what()));
                    }
                }();
                const int64_t upgrade9ActivationTime = BTC::NetFromName(p->meta.chain) == BTC::Net::ChipNet
                                                       ? 1668513600  // ChipNet: November 15, 2022 12:00:00 UTC
                                                       : 1684152000; // MainNet, etc: May 15, 2023 12:00:00 UTC
                if (bhdr.GetBlockTime() >= upgrade9ActivationTime) {
                    // Uh-oh. They have a synched db that is v1, but the upgrade has already activated. Complain
                    // and abort out, insisting that the user re-synch the DB.
                    throw DatabaseError("This datadir was synched using an older version of " APPNAME " which lacked"
                                        " full CashToken support, however Upgrade9 has already activated for this"
                                        " chain.\n\nPlease delete the datadir and resynch to bitcoind.\n");
                }
            }
        }

        Log() << "DB version is older but compatible, updating version to v" << Meta::kCurrentVersion << " ...";
        p->meta.version = Meta::kCurrentVersion;
    }
    // Set the platform info from the current process, and re-save to DB
    p->meta.makePlatformInfoCurrent();
    saveMeta_impl();
}

void Storage::compactAllDBs()
{
    if (!options->compactDBs)
        return;
    auto *db = p->db.get();
    if (!db) return;
    size_t ctr = 0;
    App *ourApp = app();
    Tic t0;
    Log() << "Compacting DB column families, please wait ...";
    for (const auto &cf : p->db.columnFamilies) {
        if (ourApp->signalsCaught())
            break;
        if (!cf) continue;
        const auto name = CFName(cf);
        Log() << "Compacting " << name << " ...";
        rocksdb::CompactRangeOptions opts;
        opts.allow_write_stall = true;
        opts.exclusive_manual_compaction = true;
        opts.change_level = true;
        auto s = db->CompactRange(opts, cf, nullptr, nullptr);
        if (!s.ok()) {
            throw DatabaseError(QString("Error compacting column family %1: %2")
                                .arg(name, StatusString(s)));
        }
        ++ctr;
    }
    Log() << "Compacted " << ctr << " column families in " << t0.secsStr(1) << " seconds";
}

void Storage::gentlyCloseDB()
{
    p->db.txhash2txnumMgr.reset();
    p->db.txNumsDRA.reset();
    p->db.headersDRA.reset();

    // do Flush of each column family, and close the handles
    auto *db = p->db.get();
    if (!db) return;
    // flush all column families at once (in case atomic flush is enabled and supported)
    {
        std::vector<rocksdb::ColumnFamilyHandle *> cfsToFlush; cfsToFlush.reserve(p->db.columnFamilies.size());
        QStringList cfsToFlushNames; cfsToFlushNames.reserve(cfsToFlush.capacity());
        for (auto * cf : p->db.columnFamilies) {
            if (!cf) continue;
            cfsToFlush.push_back(cf);
            cfsToFlushNames.push_back(CFName(cf));
        }
        Debug() << "Flushing column families: " << cfsToFlushNames.join(", ") << " ...";
        rocksdb::FlushOptions fopts;
        fopts.wait = true; fopts.allow_write_stall = true;
        auto status = db->Flush(fopts, cfsToFlush);
        if (!status.ok())
            Warning() << "Flush of all column families returned: " << StatusString(status);
    }
    // gracefully close column family handles
    for (auto & cf : p->db.columnFamilies) {
        if (!cf) continue;
        auto status = db->DestroyColumnFamilyHandle(cf);
        if (!status.ok())
            Warning() << "Release of " << CFName(cf) << ": " << StatusString(status);
        cf = nullptr;
    }
    p->db.columnFamilies.clear();
    // Clear members (they were all pointers owned by the p->db.columnFamilies array)
    p->db.blkinfo = p->db.meta = p->db.shist = p->db.shunspent = p->db.rpa = p->db.txhash2txnum = p->db.undo = p->db.utxoset = p->db.txnum2txhash = p->db.headers = nullptr;

    // do SyncWAL() and Close() to gently close the DB
    auto name = DBName(p->db);
    Debug() << "Synching WAL: " << name << " ...";
    auto status = db->SyncWAL();
    if (!status.ok())
        Warning() << "SyncWAL of " << name << ": " << StatusString(status);
    Debug() << "Closing DB: " << name << " ...";
    status = db->Close();
    if (!status.ok())
        Warning() << "Close of " << name << ": " << StatusString(status);
    // kill the concat operators we used
    p->db.concatOperatorShist = p->db.concatOperatorTxHash2TxNum = p->db.concatOperatorTxNum2TxHash = p->db.concatOperatorHeaders = nullptr;
    // delete db
    p->db.db.reset(db = nullptr);
}

void Storage::cleanup()
{
    stop(); // joins our thread
    if (p->blocksWorker) p->blocksWorker.reset(); // stop the co-task
    if (txsubsmgr) txsubsmgr->cleanup();
    if (dspsubsmgr) dspsubsmgr->cleanup();
    if (subsmgr) subsmgr->cleanup();
    gentlyCloseDB();
}


auto Storage::stats() const -> Stats
{
    // TODO ... more stuff here, perhaps
    QVariantMap ret;
    auto & c = p->db.concatOperatorShist, & c2 = p->db.concatOperatorTxHash2TxNum, & c3 = p->db.concatOperatorTxNum2TxHash,
         & c4 = p->db.concatOperatorHeaders;
    ret["merge calls (scripthash_history)"] = c ? static_cast<quint64>(c->merges.load()) : QVariant();
    ret["merge calls (txhash2txnum)"] = c2 ? static_cast<quint64>(c2->merges.load()) : QVariant();
    ret["merge calls (txnum2txhash)"] = c3 ? static_cast<quint64>(c3->merges.load()) : QVariant();
    ret["merge calls (headers)"] = c4 ? static_cast<quint64>(c4->merges.load()) : QVariant();
    QVariantMap caches;
    {
        QVariantMap m;

        const auto sz = p->lruNum2Hash.size(), szBytes = p->lruNum2Hash.totalCost(), maxSzBytes = p->lruNum2Hash.maxCost();
        m["Size bytes"] = qlonglong(szBytes);
        m["max bytes"] = qlonglong(maxSzBytes);
        m["nItems"] = qlonglong(sz);
        m["~hits"] = qlonglong(p->lruCacheStats.num2HashHits);
        m["~misses"] = qlonglong(p->lruCacheStats.num2HashMisses);
        caches["LRU Cache: TxNum -> TxHash"] = m;
    }
    {
        QVariantMap m;
        const unsigned nItems = p->lruHeight2Hashes_BitcoindMemOrder.size(), szBytes = p->lruHeight2Hashes_BitcoindMemOrder.totalCost(),
                       maxSzBytes = p->lruHeight2Hashes_BitcoindMemOrder.maxCost();
        m["Size bytes"] = szBytes;
        m["max bytes"] = qlonglong(maxSzBytes);
        m["nBlocks"] = nItems;
        m["~hits"] = qlonglong(p->lruCacheStats.height2HashesHits);
        m["~misses"] = qlonglong(p->lruCacheStats.height2HashesMisses);
        caches["LRU Cache: Block Height -> TxHashes"] = m;
    }
    {
        const size_t nHashes = p->merkleCache->size(), bytes = nHashes * (HashLen + sizeof(HeaderHash));
        caches["merkleHeaders_Size"] = qulonglong(nHashes);
        caches["merkleHeaders_SizeBytes"] = qulonglong(bytes);
    }
    ret["caches"] = caches;
    {
        const auto &db = p->db.db;
        // db stats
        QVariantMap m;
        QVariantMap m2;
        const QString name = QFileInfo(QString::fromStdString(db->GetName())).fileName();
        for (const auto prop : { "rocksdb.estimate-table-readers-mem", "rocksdb.cur-size-all-mem-tables"}) {
            if (std::string s; LIKELY(db->GetProperty(prop, &s)) )
                m2[prop] = QString::fromStdString(s);
        }
        if (auto fact = db->GetOptions().table_factory; fact) [[likely]] {
            // parse the table factory options string, which is of the form "     opt1: val1\n     opt2: val2\n  ... "
            QVariantMap m3;
            QString rocksdbOptionsString;
#if __has_include(<rocksdb/configurable.h>)
            // Newer rocksdb API uses GetPrintableOptions
            rocksdbOptionsString = QString::fromStdString( fact->GetPrintableOptions() );
#else
            // Older rocksdb API used GetPrintableTableOptions
            rocksdbOptionsString = QString::fromStdString( fact->GetPrintableTableOptions() );
#endif
            for (const auto & line : rocksdbOptionsString.split("\n")) {
                const auto nvp = line.split(":");
                if (nvp.size() < 2)
                    continue;
                auto n = nvp.first().trimmed().simplified();
                auto v = nvp.mid(1).join(":").trimmed().simplified();
                m3[n] = v;
            }
            m2["table factory options"] = m3;
        } else
            m2["table factory options"] = QVariant(); // explicitly state it was null (this branch should not normally happen)
        m2["max_open_files"] = db->GetOptions().max_open_files;
        m2["keep_log_file_num"] = qulonglong(db->GetOptions().keep_log_file_num);
        m[name] = m2;
        ret["DB Stats"] = m;
        if (const auto cache = p->db.blockCache.lock(); cache) {
            QVariantMap cmap;
            cmap["usage"] = qulonglong(cache->GetUsage());
            cmap["capacity"] = qulonglong(cache->GetCapacity());
            ret["DB Shared Block Cache"] = cmap;
        }
        if (const auto wbm = p->db.writeBufferManager.lock(); wbm) {
            QVariantMap wmap;
            const bool en = wbm->enabled();
            wmap["enabled"] = en;
            if (en) {
                // these stats are invalid if not enabled, so only add them if enabled
                wmap["is costed to cache"] = wbm->cost_to_cache();
                wmap["buffer size"] = qulonglong(wbm->buffer_size());
                wmap["memory usage"] = qulonglong(wbm->memory_usage());
            }
            ret["DB Shared Write Buffer Manager"] = wmap;
        }

        {
            // RPA-specific stats
            QVariantMap rm;
            rm["firstHeight"] = p->rpaInfo.firstHeight.load(std::memory_order_relaxed);
            rm["lastHeight"] = p->rpaInfo.lastHeight.load(std::memory_order_relaxed);
            rm["nReads"] = qulonglong(p->rpaInfo.nReads.load(std::memory_order_relaxed));
            rm["nWrites"] = qulonglong(p->rpaInfo.nWrites.load(std::memory_order_relaxed));
            rm["nDeletions"] = qulonglong(p->rpaInfo.nDeletions.load(std::memory_order_relaxed));
            rm["nBytesRead"] = qulonglong(p->rpaInfo.nBytesRead.load(std::memory_order_relaxed));
            rm["nBytesWritten"] = qulonglong(p->rpaInfo.nBytesWritten.load(std::memory_order_relaxed));
            rm["needsFullCheck"] = p->rpaInfo.rpaNeedsFullCheckCachedVal.load(std::memory_order_relaxed);
            ret["RPA Index Info"] = rm;
        }
    }
    return ret;
}

// Keep returned LockGuard in scope while you use the HeaderVerifier
auto Storage::headerVerifier() -> std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard>
{
    return std::pair<BTC::HeaderVerifier &, ExclusiveLockGuard>( p->headerVerifier, p->headerVerifierLock );
}
auto Storage::headerVerifier() const -> std::pair<const BTC::HeaderVerifier &, SharedLockGuard>
{
    return std::pair<const BTC::HeaderVerifier &, SharedLockGuard>( p->headerVerifier, p->headerVerifierLock );
}


QString Storage::getChain() const
{
    SharedLockGuard l(p->metaLock);
    return p->meta.chain;
}

void Storage::setChain(const QString &chain)
{
    {
        ExclusiveLockGuard l(p->metaLock);
        p->meta.chain = chain; // set chain for saving
    }
    if (!chain.isEmpty())
        Log() << "Chain: " << chain;
    save(SaveItem::Meta);
}

QString Storage::getCoin() const
{
    SharedLockGuard l(p->metaLock);
    return p->meta.coin;
}

void Storage::setCoin(const QString &coin) {
    {
        ExclusiveLockGuard l(p->metaLock);
        p->meta.coin = coin;
    }
    if (!coin.isEmpty())
        Log() << "Coin: " << coin;
    save(SaveItem::Meta);
}

bool Storage::isRpaEnabled() const
{
    using ES = Options::Rpa::EnabledSpec;
    switch(options->rpa.enabledSpec) {
    case ES::Enabled: return true;
    case ES::Disabled: return false;
    case ES::Auto: return BTC::coinFromName(getCoin()) == BTC::Coin::BCH;
    }
    return false; // not normally reached; suppress compiler warnings
}

int Storage::getConfiguredRpaStartHeight() const
{
    if (!isRpaEnabled()) return -1; // -1 to caller means "rpa not enabled"
    if (const int reqHt = options->rpa.requestedStartHeight; reqHt >= 0)
        return reqHt; // user requested a specific start height >= 0

    // otherwise, do "auto", which is 825,000 for mainnet, 0 for all other nets
    if (BTC::NetFromName(getChain()) == BTC::Net::MainNet)
        return Options::Rpa::defaultStartHeightForMainnet;
    return Options::Rpa::defaultStartHeightOtherNets;
}

auto Storage::getRpaDBHeightRange() const -> std::optional<HeightRange>
{
    std::optional<HeightRange> ret;
    if (isRpaEnabled())
        if (const int from = p->rpaInfo.firstHeight, to = p->rpaInfo.lastHeight; from >= 0 && to >= 0)
            ret.emplace(static_cast<BlockHeight>(from), static_cast<BlockHeight>(to));
    return ret;
}

/// returns the "next" TxNum
TxNum Storage::getTxNum() const { return p->txNumNext.load(); }

auto Storage::latestTip(Header *hdrOut) const -> std::pair<int, HeaderHash> {
    static_assert(std::is_same_v<Header, HeaderHash> && std::is_same_v<Header, QByteArray>); // both must be QByteArray
    std::pair<int, HeaderHash> ret = headerVerifier().first.lastHeaderProcessed(); // ok; lock stays locked until statement end.
    if (hdrOut) *hdrOut = ret.second; // this is not a hash but the actual block header
    if (ret.second.isEmpty() || ret.first < 0) {
        ret.first = -1;
        ret.second.clear();
        if (hdrOut) hdrOut->clear();
    } else {
        // .ret now has the actual header but we want the hash
        ret.second = BTC::HashRev(ret.second);
    }
    return ret;
}

auto Storage::latestHeight() const -> std::optional<BlockHeight>
{
    std::optional<BlockHeight> ret;
    SharedLockGuard g(p->blkInfoLock);
    if (!p->blkInfos.empty())
        ret = BlockHeight(p->blkInfos.size()-1);
    return ret;
}

void Storage::save(SaveSpec typed_spec)
{
    using IntType = decltype(p->pendingSaves.load());
    // enqueue save on event loop if not previously enqueued (we know it was previously enqueued if the p->pendingSaves
    // atomic variable is not 0).
    if (const auto spec = IntType(typed_spec); ! p->pendingSaves.fetch_or(spec))
    {
        QTimer::singleShot(0, this, [this]{save_impl();});
    }
}

void Storage::save_impl(SaveSpec override)
{
    if (const auto flags = SaveSpec(p->pendingSaves.exchange(0))|override; flags) { // atomic clear of flags, grab prev val
        try {
            if (flags & SaveItem::Meta) { // Meta
                SharedLockGuard l(p->metaLock);
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
    if (auto status = p->db->Put(p->db.defWriteOpts, p->db.meta, kMeta, ToSlice(Serialize(p->meta))); !status.ok()) {
        throw DatabaseError("Failed to write meta to db");
    }

    DebugM("Wrote new metadata to db");
}

void Storage::appendHeader(rocksdb::WriteBatch &batch, const Header &h, BlockHeight height)
{
    auto ctx = p->db.headersDRA->beginBatchWrite(batch);
    const auto targetHeight = p->db.headersDRA->numRecords();
    if (height != targetHeight) [[unlikely]]
        throw InternalError(QString("Bad use of appendHeader -- expected height %1, got height %2").arg(targetHeight).arg(height));
    QString err;
    const auto res = ctx.append(h, &err);
    if (!err.isEmpty()) [[unlikely]]
        throw DatabaseError(QString("Failed to append header %1: %2").arg(height).arg(err));
    else if (!res || p->db.headersDRA->numRecords() != height + 1u) [[unlikely]]
        throw DatabaseError(QString("Failed to append header %1: result is bad").arg(height));
}

void Storage::deleteHeadersPastHeight(rocksdb::WriteBatch &batch, BlockHeight height)
{
    QString err;
    auto ctx = p->db.headersDRA->beginBatchWrite(batch);
    const auto res = ctx.truncate(height + 1u, &err);
    if (!err.isEmpty())
        throw DatabaseError(QString("Failed to truncate headers past height %1: %2").arg(height).arg(err));
    else if (!res || p->db.headersDRA->numRecords() != height + 1u)
        throw InternalError("header truncate resulted in an unexepected value");
}

auto Storage::headerForHeight(BlockHeight height, QString *err, HeaderHash *hashOut) const -> std::optional<Header>
{
    std::optional<Header> ret;
    Header tipheader;
    const auto & [tipHeight, tipHash] = latestTip(&tipheader);
    if (int(height) == tipHeight && int(height) >= 0) {
        ret = tipheader;
        if (hashOut) *hashOut = tipHash;
    } else if (int(height) < tipHeight && int(height) >= 0) {
        ret = headerForHeight_nolock(height, err);
        if (ret && hashOut) *hashOut = BTC::HashRev(*ret);
    } else if (err) { *err = QStringLiteral("Height %1 is out of range").arg(height); }
    return ret;
}

auto Storage::headerForHeight_nolock(BlockHeight height, QString *err) const -> std::optional<Header>
{
    std::optional<Header> ret;
    try {
        QString err1;
        ret.emplace( p->db.headersDRA->readRecord(height, &err1) );
        if (!err1.isEmpty()) {
            ret.reset();
            throw DatabaseError(QString("failed to read header %1: %2").arg(height).arg(err1));
        }
    } catch (const std::exception &e) {
        if (err) *err = e.what();
    }
    return ret;
}

auto Storage::headersFromHeight_nolock_nocheck(BlockHeight height, unsigned num, QString *err) const -> std::vector<Header>
{
    if (err) err->clear();
    std::vector<Header> ret = p->db.headersDRA->readRecords(height, num, err);

    if (ret.size() != num && err && err->isEmpty())
        *err = "short header count returned from headers file";

    ret.shrink_to_fit();
    return ret;
}

auto Storage::hashForHeight(BlockHeight height, QString *err) const -> std::optional<HeaderHash>
{
    if (HeaderHash hash; headerForHeight(height, err, &hash))
        return hash;
    return std::nullopt;
}

/// Convenient batched alias for above. Returns a set of headers starting at height. May return < count if not
/// all headers were found. Thead safe.
auto Storage::headersFromHeight(BlockHeight height, unsigned count, QString *err) const -> std::vector<Header>
{
    std::vector<Header> ret;
    SharedLockGuard g(p->blocksLock); // to ensure clients get a consistent view
    int num = std::min(1 + latestTip().first - int(height), int(count)); // note this also takes a lock briefly so we need to do this after the lockguard above
    if (num > 0) {
        ret = headersFromHeight_nolock_nocheck(height, count, err);
    } else if (err) *err = "No headers in the specified range";
    return ret;
}


void Storage::loadCheckHeadersInDB()
{
    assert(p->blockHeaderSize() > 0);
    assert(bool(p->db.headersDRA));

    Log() << "Verifying headers ...";
    uint32_t num = static_cast<uint32_t>(p->db.headersDRA->numRecords());
    std::vector<QByteArray> hVec;
    const Tic t0;
    {
        if (num > MAX_HEADERS)
            throw DatabaseFormatError(QString("Header count (%1) in database exceeds MAX_HEADERS (%2)! This is likely due to"
                                              " a database format mistmatch. Delete the datadir and resynch it.")
                                          .arg(num).arg(MAX_HEADERS));
        // verify headers: hashPrevBlock must match what we actually read from db
        if (num) {
            Debug() << "Verifying " << num << " " << Util::Pluralize("header", num) << " ...";
            QString err;
            hVec = headersFromHeight_nolock_nocheck(0, num, &err);
            if (!err.isEmpty() || hVec.size() != num)
                throw DatabaseFormatError(QString("%1. Possible databaase corruption. Delete the datadir and resynch.").arg(err.isEmpty() ? "Could not read all headers" : err));

            auto [verif, lock] = headerVerifier();
            // set genesis hash
            p->genesisHash = BTC::HashRev(hVec.front());

            err.clear();
            // read db
            for (uint32_t i = 0; i < num; ++i) {
                auto & bytes = hVec[i];
                if (!verif(bytes, &err))
                    throw DatabaseFormatError(QString("%1. Possible databaase corruption. Delete the datadir and resynch.").arg(err));
                bytes = BTC::Hash(bytes); // replace the header in the vector with its hash because it will be needed below...
            }
        }
    }
    if (num) {
        if (const auto mops = p->db.concatOperatorHeaders->merges.load(); mops)
            Debug() << CFName(p->db.headers) << " merge ops: " << mops;
        Debug() << "Read & verified " << num << " " << Util::Pluralize("header", num) << " from db in " << t0.msecStr() << " msec";
    }

    if (!p->merkleCache->isInitialized() && !hVec.empty())
        p->merkleCache->initialize(hVec); // this may take a few seconds, and it may also throw

}

void Storage::loadCheckTxNumsDRAAndBlkInfo()
{
    // may throw.
    assert(bool(p->db.txNumsDRA));
    p->txNumNext = p->db.txNumsDRA->numRecords();
    Debug() << "Read TxNumNext from file: " << p->txNumNext.load();
    TxNum ct = 0;
    if (const int height = latestTip().first; height >= 0)
    {
        p->blkInfos.reserve(std::min(size_t(height+1), MAX_HEADERS));
        Log() << "Checking tx counts ...";
        for (int i = 0; i <= height; ++i) {
            static const QString errMsg("Failed to read a blkInfo from db, the database may be corrupted");
            const auto blkInfo = GenericDBGetFailIfMissing<BlkInfo>(p->db, p->db.blkinfo,
                                                                    SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(i)),
                                                                    errMsg, false, p->db.defReadOpts);
            if (blkInfo.txNum0 != ct)
                throw DatabaseFormatError(QString("BlkInfo for height %1 does not match computed txNum of %2."
                                                  "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                          .arg(i).arg(ct));
            ct += blkInfo.nTx;
            p->blkInfos.emplace_back(blkInfo);
            p->blkInfosByTxNum[blkInfo.txNum0] = unsigned(p->blkInfos.size()-1);
        }
        Log() << ct << " total transactions";
    }
    if (ct != p->txNumNext) {
        throw DatabaseFormatError(QString("BlkInfo txNums do not add up to expected value of %1 != %2."
                                          "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                  .arg(ct).arg(p->txNumNext.load()));
    }
    // Check that the buckets in the txNumsDRA are monotonically increasing and they have the expected format.
    if (options->doSlowDbChecks >= 2) { // only for -C -C or above
        Tic t0;
        auto name = p->db.txNumsDRA->name().split("/").back();
        Log() << "CheckDB: Verifying " << name << " DB format ...";
        auto iter = p->db.txNumsDRA->seekToFirstBucket();
        uint64_t txNumsSeen = 0, bucketNum = 0;
        const uint64_t expectedNBuckets = p->txNumNext.load() ? (p->txNumNext.load() + p->db.txNumsDRA->bucketNumRecords() - 1)
                                                                / p->db.txNumsDRA->bucketNumRecords()
                                                              : 0;
        Debug() << "CheckDB: Verifying " << expectedNBuckets << " " << name << " buckets ...";
        while (iter->Valid()) {
            if (p->db.txNumsDRA->bucketNumFromDbKey(iter->key()) != bucketNum) [[unlikely]] {
                throw DatabaseFormatError(QString("%1 DBRecordArray has an invalid key for bucket num %2 (key=%3)."
                                                  "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                          .arg(name).arg(bucketNum).arg(QString::fromLatin1(ByteView{iter->key()}.toByteArray(false).toHex())));
            }
            const auto bucketData = iter->value();
            const size_t nrecs = bucketData.size() / HashLen;
            const size_t mod = bucketData.size() % HashLen;
            if (!nrecs || mod || (nrecs != p->db.txNumsDRA->bucketNumRecords() && txNumsSeen + nrecs != ct)) [[unlikely]] {
                throw DatabaseFormatError(QString("%1 DBRecordArray has invalid data of length %2 in bucket number %3."
                                                  "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                          .arg(name).arg(bucketData.size()).arg(bucketNum));
            }
            txNumsSeen += nrecs;
            ++bucketNum;
            if (bucketNum % 1'000'000 == 0) [[unlikely]] {
                Log() << "CheckDB: Verified " << bucketNum << "/" << expectedNBuckets << " " << name
                      << Util::Pluralize(" bucket", bucketNum)  << " ...";
            }
            if (bucketNum % 10'000 == 0 && app()->signalsCaught()) [[unlikely]]
                throw UserInterrupted("User interrupted, aborting check");
            iter->Next();
        }
        if (txNumsSeen != ct || expectedNBuckets != bucketNum) {
            throw DatabaseFormatError(QString("%1 DBRecordArray appears to be missing data."
                                              "\n\nThe database may be corrupted. Delete the datadir and resynch it.\n")
                                      .arg(name));
        }
        if (const auto mops = p->db.concatOperatorTxNum2TxHash->merges.load(); mops)
            Debug() << CFName(p->db.txnum2txhash) << " merge ops: " << mops;
        Log() << "CheckDB: Verified " << bucketNum << " " << name << Util::Pluralize(" bucket", bucketNum)
              << ", " << txNumsSeen << Util::Pluralize(" tx hash", txNumsSeen)
              << ", in " << t0.secsStr() << " secs";
    }
}

// this depends on the above function having been run already
void Storage::loadCheckTxHash2TxNumMgr()
{
    // the below may throw
    p->db.txhash2txnumMgr = std::make_unique<TxHash2TxNumMgr>(p->db.get(), p->db.txhash2txnum, p->db.defReadOpts, p->db.defWriteOpts,
                                                              p->db.txNumsDRA.get(), 6, TxHash2TxNumMgr::KeyPos::End);
    try {
        // basic sanity checks -- ensure we can read the first, middle, and last hash in the txNumsFile,
        // and that those hashes exist in the txhash2txnum db
        const QString errMsg = "The txhash index failed basic sanity checks -- it is missing some records.";
        const auto nrecs = p->db.txNumsDRA->numRecords();
        if (nrecs) {
            for (auto recNum : {uint64_t(0), uint64_t(nrecs/2), uint64_t(nrecs-1)}) {
                if (!p->db.txhash2txnumMgr->exists(p->db.txNumsDRA->readRecord(recNum)))
                    throw DatabaseError(errMsg);
            }
        } else {
            // sanity check on empty db: if no records, db should also have no rows
            std::unique_ptr<rocksdb::Iterator> it(p->db->NewIterator(p->db.defReadOpts, p->db.txhash2txnum));
            if (!it) throw DatabaseError("Unable to obtain an iterator to the txhash2txnum set db");
            for (it->SeekToFirst(); it->Valid(); it->Next()) {
                throw DatabaseFormatError(QString("Failed invariant: empty txNum file should mean empty db; ") + errMsg);
            }
        }

        if (p->db.txhash2txnumMgr->maxTxNumSeenInDB()+1 != int64_t(nrecs))
            throw DatabaseFormatError(QString("Failed invariant: txNumCount != nrecs; ") + errMsg);

        if (options->doSlowDbChecks) // require the slow check for this one
            p->db.txhash2txnumMgr->consistencyCheck();
        if (options->doSlowDbChecks >= 3) // the below check is very slow so we require -C -C -C
            p->db.txhash2txnumMgr->consistencyCheckSlowRev();
    } catch (const DatabaseError &e) {
        // Database error -- user either lacks the database (upgrade needed) or they have it and it is corrupted --
        // attempt to rebuild it.
        if (p->db.txhash2txnumMgr->maxTxNumSeenInDB() > -1) {
            Warning() << e.what();
            Log() << "Rebuilding txhash index, please wait ...";
        } else {
            Debug() << e.what();
            Log() << "Upgrading database, this may take from 1-10 minutes, please wait ...";
        }
        p->db.txhash2txnumMgr->rebuildDB();
    }
}

// NOTE: this must be called *after* loadCheckTxNumsFileAndBlkInfo(), because it needs a valid p->txNumNext
void Storage::loadCheckUTXOsInDB()
{
    FatalAssert(!!p->db.utxoset, __func__, ": Utxo set db is not open");

    if (options->doSlowDbChecks) {
        Log() << "CheckDB: Verifying utxo set (this may take some time) ...";

        // Note: Before the BIP that imposed uniqueness on coinbase tx's,
        // Bitcoin coinbase tx's for heights 91842 and 91812 both have outpoint:
        //      d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599:0
        // And coinbase tx's for heights 91880 and 91722 both have outpoint:
        //      e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468:0
        // Thus the counts may be off by as much as 2 here. So we must detect these
        // utxos and compensate by fudging the count check a little bit if we see
        // the utxo + heights in question.
        const std::map<TXO, std::pair<HashX, std::set<unsigned>>> fudgeDueToBitcoinBugs = {
            {TXO{Util::ParseHexFast("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"), 0},
             { Util::ParseHexFast("49df7a6bfea6c409a5f03fd734a1f1a13cb8fafee6a3e08dd94db352498f99a6"), {91880, 91722} } },
            {TXO{Util::ParseHexFast("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"), 0},
             { Util::ParseHexFast("76d95f02197b7c685b972104f6d7688a78bdcbb6a757fd5a139a195e59505fab"), {91842, 91812} } },
        };
        std::set<TXO> seenExceptions;
        // scan shunspent to see if our counts may be off
        // (this scan guards against these coins being spent in future throwing off our counts yet again!)
        for (const auto & [txo, pair] : fudgeDueToBitcoinBugs) {
            const auto & [hashx, heights] = pair;
            for (const auto & height : heights) {
                if (height >= p->blkInfos.size())
                    continue;
                const TxNum txNum = p->blkInfos[height].txNum0;
                const CompactTXO ctxo(txNum, txo.outN);
                auto opt = GenericDBGet<QByteArray>(p->db, p->db.shunspent, mkShunspentKey(hashx, ctxo), true, "", false, p->db.defReadOpts);
                if (opt.has_value()) {
                    if (seenExceptions.insert(txo).second)
                        Debug() << "Seen exception: " << txo.toString() << ", height: " << height;
                }
            }
        }

        const Tic t0;
        {
            const qint64 currentHeight = latestTip().first;

            std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.utxoset));
            if (!iter) throw DatabaseError("Unable to obtain an iterator to the utxo set db");
            p->utxoCt = 0;
            for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
                // TODO: the below checks may be too slow. See about removing them and just counting the iter.
                const auto txo = Deserialize<TXO>(FromSlice(iter->key()));
                if (!txo.isValid()) {
                    throw DatabaseSerializationError("Read an invalid txo from the utxo set database."
                                                     " This may be due to a database format mismatch."
                                                     "\n\nDelete the datadir and resynch to bitcoind.\n");
                }
                auto info = Deserialize<TXOInfo>(FromSlice(iter->value()));
                if (!info.isValid())
                    throw DatabaseSerializationError(QString("Txo %1 has invalid metadata in the db."
                                                            " This may be due to a database format mismatch."
                                                            "\n\nDelete the datadir and resynch to bitcoind.\n")
                                                     .arg(txo.toString()));

                // compensate for counts being off due to historical bugs in blockchain
                // these outpoints actually generate 2 entries in shunspent and 1 entry here
                // we must tolerate counts being off if we see this utxo.
                if (auto it = fudgeDueToBitcoinBugs.find(txo);
                        it != fudgeDueToBitcoinBugs.end() && it->second.second.count(info.confirmedHeight.value_or(0))) {
                    if (seenExceptions.insert(txo).second)
                        Debug() << "Seen exception: " << txo.toString();
                }
                // this is a deep test: only happens if -C / --checkdb is specified on CLI or in conf.
                const CompactTXO ctxo = CompactTXO(info.txNum, txo.outN);
                const QByteArray shuKey = mkShunspentKey(info.hashX, ctxo);
                static const QString errPrefix("Error reading scripthash_unspent");
                QByteArray tmpBa;
                SHUnspentValue shval;
                if (bool fail1 = false, fail2 = false, fail3 = false, fail4 = false, fail5 = false;
                        (fail1 = (!info.confirmedHeight.has_value() || qint64(*info.confirmedHeight) > currentHeight))
                        || (fail2 = info.txNum >= p->txNumNext)
                        || (fail3 = (tmpBa = GenericDBGet<QByteArray>(p->db, p->db.shunspent, shuKey, true, errPrefix, false, p->db.defReadOpts).value_or("")).isEmpty())
                        || (fail4 = (!(shval = Deserialize<SHUnspentValue>(tmpBa)).valid || info.amount != shval.amount))
                        || (fail5 = (info.tokenDataPtr != shval.tokenDataPtr))) {
                    // TODO: reorg? Inconsisent db?  FIXME
                    QString msg;
                    {
                        QTextStream ts(&msg);
                        ts << "Inconsistent database: txo " << txo.toString();
                        if (info.confirmedHeight) ts << " (height: " << *info.confirmedHeight << ")";
                        else ts << " (missing height)";
                        if (fail1) {
                            ts << " has unexpected height; current height: " << currentHeight << ".";
                        } else if (fail2) {
                            ts << ". TxNum: " << info.txNum << " >= " << p->txNumNext << ".";
                        } else if (fail3) {
                            ts << ". Failed to find ctxo " << ctxo.toString() << " in the scripthash_unspent db.";
                        } else if (fail4) {
                            ts << ". Utxo amount does not match the ctxo amount in the scripthash_unspent db.";
                        } else if (fail5) {
                            ts << ". Token data does not match the ctxo token_data in the scripthash_unspent db.";
                        }
                        ts << "\n\nThe database has been corrupted. Please delete the datadir and resynch to bitcoind.\n";
                    }
                    throw DatabaseError(msg);
                }
                if (0 == ++p->utxoCt % 100'000) {
                    *(0 == p->utxoCt % 2'500'000 ? std::make_unique<Log>() : std::make_unique<Debug>())
                            << "CheckDB: Verified " << p->utxoCt << " utxos ...";
                } else if (0 == p->utxoCt % 1'000 && app() && app()->signalsCaught()) {
                    throw UserInterrupted("User interrupted, aborting check");
                }
            }

            if (const auto metact = readUtxoCtFromDB();
                    // counts may be slightly off due to the dupe tx's outlined above -- after this is run
                    // the utxoset will have the right count (although shunspent will disagree with this,
                    // which we also tolerate). So we tolerate being off due to the "exceptions" above.
                    std::abs(long(p->utxoCt) - long(metact)) > long(seenExceptions.size()))
                    throw DatabaseError(QString("UTXO count in meta table (%1) does not match the actual number of UTXOs in the utxoset (%2)."
                                                "\n\nThe database has been corrupted. Please delete the datadir and resynch to bitcoind.\n")
                                        .arg(metact).arg(p->utxoCt.load()));

        }
        Debug() << "CheckDB: Verified utxos in " << t0.msecStr() << " msec";

    } else {
        p->utxoCt = readUtxoCtFromDB();
    }

    if (const auto ct = utxoSetSize(); ct)
        Log() << "UTXO set: "  << ct << Util::Pluralize(" utxo", ct) << ", " << QString::number(utxoSetSizeMB(), 'f', 3) << " MB";
}

// NOTE: this must be called *after* loadCheckTxNumsFileAndBlkInfo(), because it needs a valid p->txNumNext
void Storage::loadCheckShunspentInDB()
{
    FatalAssert(!!p->db.shunspent, __func__, ": Shunspent db is not open");

    if (options->doSlowDbChecks < 2) // this is so slow it requires -C -C be specified
        return;

    Log() << "CheckDB: Verifying scripthash_unspent (this may take some time) ...";

    const Tic t0;

    std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.shunspent));
    if (!iter) throw DatabaseError("Unable to obtain an iterator to the scripthash unspent db");

    // Note: Before the BIP that imposed uniqueness on coinbase tx's,
    // Bitcoin coinbase tx's for heights 91842 and 91812 both have outpoint:
    //      d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599:0
    // And coinbase tx's for heights 91880 and 91722 both have outpoint:
    //      e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468:0
    // Thus the TXOInfo may be wrong for these entries since we get 2 shunspent
    // entries for each of these coins but only 1 entry in utxodb for each coin.
    // Thus, we just must ignore sanity check for these two coins outright.
    const std::set<TXO> exceptionsDueToBitcoinBugs = {
        TXO{Util::ParseHexFast("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"), 0},
        TXO{Util::ParseHexFast("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"), 0},
    };
    std::set<TXO> seenExceptions;

    constexpr auto errMsg = "This may be due to either a database format mismatch or data corruption."
                            "\n\nDelete the datadir and resynch to bitcoind.\n";
    size_t ctr = 0;
    for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
        const auto &[hashx, ctxo] = extractShunspentKey(iter->key(), false);
        if (!ctxo.isValid())
            throw DatabaseError(QString("Read an invalid compact txo from the scripthash_unspent database. %1").arg(errMsg));
        TXOInfo info;
        {
            SHUnspentValue shuval = Deserialize<SHUnspentValue>(FromSlice(iter->value()));
            if (!shuval.valid || !bitcoin::MoneyRange(shuval.amount)) [[unlikely]]
                throw DatabaseError(QString("Read an invalid SHUnspentValue from the scripthash_unspent database for scripthash: %1. %2")
                                    .arg(QString(hashx.toHex()), errMsg));
            info.txNum = ctxo.txNum();
            info.hashX = hashx;
            info.amount = shuval.amount;
            info.confirmedHeight = heightForTxNum(ctxo.txNum());
            info.tokenDataPtr = std::move(shuval.tokenDataPtr);
        }
        const TxHash txHash = hashForTxNum(ctxo.txNum(), true, nullptr, true).value_or(QByteArray()); // throws if missing
        const TXO txo{txHash, ctxo.N()};
        // look for this in the UTXO db
        const auto optInfo = GenericDBGet<TXOInfo>(p->db, p->db.utxoset, ToSlice(Serialize(txo)), true, "", false, p->db.defReadOpts);
        if (!optInfo) [[unlikely]] {
            // we permit the buggy utxos above to be off -- those are due to collisions in historical blockchain
            if (!exceptionsDueToBitcoinBugs.contains(txo))
                throw DatabaseError(QString("The scripthash_unspent table is missing a corresponding entry in the UTXO table for TXO \"%1\". %2")
                                    .arg(txo.toString(), errMsg));
            else {
                seenExceptions.insert(txo);
                Debug() << "Seen exception: " << txo.toString() << ", height: " << info.confirmedHeight.value_or(0);
            }
        }

        if (!info.isValid() || !optInfo || !optInfo->isValid() || *optInfo != info) [[unlikely]] {
            // we permit the buggy utxos above to be off -- those are due to collisions in historical blockchain
            if (!exceptionsDueToBitcoinBugs.contains(txo))
                throw DatabaseError(QString("TXO \"%1\" mismatch between scripthash_unspent and the UTXO table. %2")
                                    .arg(txo.toString(), errMsg));
            else {
                seenExceptions.insert(txo);
                Debug() << "Seen exception: " << txo.toString() << ", height: " << info.confirmedHeight.value_or(0);
            }
        }
        if (0 == ++ctr % 10000) {
            *(0 == ctr % 200000 ? std::make_unique<Log>() : std::make_unique<Debug>())
                    << "CheckDB: Verified " << ctr << " scripthash_unspent entries ...";
        }
    }

    if (const auto metact = readUtxoCtFromDB();
            // tolerate being off by as much as 2 in case the exceptional utxos get spent!
            std::abs(long(ctr) - long(metact)) > long(seenExceptions.size()))
            throw DatabaseError(QString("UTXO count in meta table (%1) does not match the actual number of UTXOs in shunspent (%2). %3")
                                .arg(metact).arg(ctr).arg(errMsg));

    Log() << "Verified " << ctr << " scripthash_unspent " << Util::Pluralize("entry", ctr)
          << " in " << t0.secsStr() << " sec";
 }

void Storage::loadCheckRpaDB()
{
    FatalAssert(!!p->db.rpa, __func__, ": RPA db is not open");

    const bool doSlowChecks = options->doSlowDbChecks;
    const bool doNeededCheck = isRpaNeedsFullCheck();
    const bool fullCheck = doSlowChecks || doNeededCheck;

    if (doSlowChecks) {
        Log() << "CheckDB: Verifying RPA db (this may take some time) ...";
    } else if (doNeededCheck) {
        Log() << "Performing required check on RPA db, please wait ...";
    } else {
        Log() << "Loading RPA db ...";
    }

    Tic t0;
    bool blowAwayWholeDB = false;
    std::optional<QString> excMessage;
    try {
        auto & firstHeight = p->rpaInfo.firstHeight, & lastHeight = p->rpaInfo.lastHeight;
        firstHeight = lastHeight = -1;
        int forceDeleteAfterHeight = -1; // if >=0, force a delete after this height

        std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.rpa));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the rpa db");
        auto ThrowIfNegativeIfCastedToSigned = [](uint32_t height) {
              if (height > uint32_t(std::numeric_limits<int>::max()))
                  throw DatabaseFormatError(QString("Encountered a height (%1) in the RPA db that is > INT_MAX"
                                                    "; this indicates corruption or an incompatible DB format.").arg(height));
        };
        auto TryDeserializePFTAndUpdateCounts = [&info = p->rpaInfo](uint32_t height, rocksdb::Slice slice,
                                                                     bool extractShortBHash = false) -> QByteArray {
            try {
                bool ok{};
                ++info.nReads;
                info.nBytesRead += sizeof(height) + slice.size();
                if (slice.size() < kRpaShortBlockHashLen) [[unlikely]] throw Exception("Slice should be prefixed with a short block hash");
                const QByteArray shortHash = extractShortBHash ? DeepCpy(slice.data(), kRpaShortBlockHashLen) : QByteArray();
                slice.remove_prefix(kRpaShortBlockHashLen);
                Rpa::PrefixTable pt = Deserialize<Rpa::PrefixTable>(FromSlice(slice), &ok);
                return shortHash;
            } catch (const std::exception &e) {
                throw DatabaseSerializationError(QString("Error deserializing Rpa::PrefixTable for height %1: %2")
                                                 .arg(height).arg(e.what()));
            }
        };
        if (! fullCheck) {
            // Normal fast startup -- just try and figure out what height range we actually have in the DB
            iter->SeekToFirst();
            if (iter->Valid()) {
                bool ok;
                RpaDBKey rk = RpaDBKey::fromBytes(FromSlice(iter->key()), &ok, true);
                if (!ok) throw DatabaseSerializationError("Unable to deserialize RPA db key -> height");
                ThrowIfNegativeIfCastedToSigned(rk.height);
                TryDeserializePFTAndUpdateCounts(rk.height, iter->value()); // this may throw; if it does we will blow away the whole DB below and Controller will do a full resynch of RPA index
                firstHeight = rk.height;
                iter->SeekToLast();
                if (UNLIKELY( ! iter->Valid())) throw DatabaseError("Unable to seek to last entry in RPA db. This is unexpected.");
                rk = RpaDBKey::fromBytes(FromSlice(iter->key()), &ok, true);
                if (!ok) throw DatabaseSerializationError("Unable to deserialize RPA db key -> height");
                ThrowIfNegativeIfCastedToSigned(rk.height);
                TryDeserializePFTAndUpdateCounts(rk.height, iter->value()); // this may throw; if it does we will blow away the whole DB below and Controller will do a full resynch of RPA index
                lastHeight = rk.height;
                if (lastHeight < firstHeight) // this should never happen and indicates some serialization format error
                    throw DatabaseSerializationError(QString("The last record has height less than the first record in the RPA db: first = %1, last = %2").arg(firstHeight.load()).arg(lastHeight.load()));
            }
        } else {
            // Slower -- iterate through entire table to find gaps as well as verify data by deserializing it row by row
            size_t ctr = 0;
            for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
                const auto & k = iter->key();
                if (k.size() == sizeof(uint32_t)) {
                    bool ok;
                    const RpaDBKey rk = Deserialize<RpaDBKey>(FromSlice(k), &ok);
                    if (!ok) throw DatabaseSerializationError("Unable to deserialize RPA db key -> height");
                    ThrowIfNegativeIfCastedToSigned(rk.height);
                    TryDeserializePFTAndUpdateCounts(rk.height, iter->value()); // this may throw; if it does we will blow away the whole DB below and Controller will do a full resynch of RPA index
                    if (firstHeight < 0) {
                        firstHeight = rk.height;
                    }
                    if (lastHeight > -1 && BlockHeight(lastHeight) + 1u != rk.height) { // detect gaps
                        Warning() << QString("Gap in RBA db encountered starting at height %1 to height %2").arg(lastHeight + 1).arg(rk.height);
                        forceDeleteAfterHeight = BlockHeight(lastHeight);
                        break;
                    }
                    lastHeight = rk.height;
                    ++ctr;
                    if (0u == ctr % 1'000u && app() && app()->signalsCaught())
                        throw UserInterrupted("User interrupted, aborting check");
                } else {
                    throw DatabaseFormatError(QString("Encountered a key in the RPA db that is not exactly %1 bytes! Hex for key: %2")
                                              .arg(sizeof(uint32_t)).arg(QString(FromSlice(k).toHex())));
                }
            }
            Debug () << "RPA db has " << ctr << " entries, " << p->rpaInfo.nBytesRead << " bytes; deserialized ok";
        }
        if (lastHeight < firstHeight || ((lastHeight <= -1 || firstHeight <= -1) && lastHeight != firstHeight)) // defensive programming: enforce invariant here
            throw InternalError(QString("Programming error in %1. FIXME!").arg(__func__));
        if (firstHeight > -1) {
            const int currentHeight = latestTip().first;
            if (currentHeight < lastHeight || forceDeleteAfterHeight > -1) {
                // delete either form the "forceDeleteAfterHeight" height or the current height, whichever is smaller
                const int delheight = forceDeleteAfterHeight > -1 ? std::min(forceDeleteAfterHeight, currentHeight)
                                                                  : currentHeight;
                const auto delheightplus1 = static_cast<BlockHeight>(std::max(delheight, -1) + 1);

                Log() << "Deleting unneeded or gap RPA entries from height " << delheightplus1 << " ...";
                // on success, updates p->rpaInfo.lastHeight, firstHeight, etc
                if (!deleteRpaEntriesFromHeight(nullptr, delheightplus1, true, true))
                    throw DatabaseError("Failed to delete the required keys from the DB. Please report this situation to the developers.");
            }
        }
        if (firstHeight > -1) {
            auto GetShortHashForHeightFromRpa = [&TryDeserializePFTAndUpdateCounts, this](uint32_t height) -> std::optional<QByteArray> {
                if (auto opt = GenericDBGet<QByteArray>(p->db, p->db.rpa, RpaDBKey(height), true))
                    return TryDeserializePFTAndUpdateCounts(height, ToSlice(*opt), true);
                return std::nullopt;
            };
            auto GetShortHashForHeightFromHeaders = [this](uint32_t height) -> std::optional<QByteArray> {
                if (auto opt = hashForHeight(height)) return opt->right(kRpaShortBlockHashLen);
                return std::nullopt;
            };
            const std::optional<QByteArray> firstShortHash = GetShortHashForHeightFromRpa(firstHeight.load()),
                                            lastShortHash  = GetShortHashForHeightFromRpa(lastHeight.load()),
                                            expectFirstShortHash = GetShortHashForHeightFromHeaders(firstHeight.load()),
                                            expectLastShortHash  = GetShortHashForHeightFromHeaders(lastHeight.load());
            if (expectFirstShortHash != firstShortHash || expectLastShortHash != lastShortHash) [[unlikely]]
                throw DatabaseError("RPA db doesn't appear to cover the active chain");
        }
        // Print some info -- note firstHeight can mutate above which is why we do this here last
        if (firstHeight >= 0) Debug() << "RPA db data covers heights: " << firstHeight << " -> " << lastHeight;
        else Debug() << "RPA db is empty";
    } catch (const std::ios_base::failure &e) {
        excMessage = e.what();
        blowAwayWholeDB = true;
    } catch (const DatabaseError &e) {
        excMessage = e.what();
        blowAwayWholeDB = true;
    }
    if (excMessage) Warning() << *excMessage;
    if (blowAwayWholeDB) {
        Log() << "RPA db is inconsistent and will be resynched from bitcoind. Deleting existing entries ...";
        deleteRpaEntriesFromHeight(nullptr, 0, true, true);
        p->rpaInfo.firstHeight = p->rpaInfo.lastHeight = -1;
    }

    // Lastly, if we were in check mode, flag the DB as clean now
    if (fullCheck) setRpaNeedsFullCheck(false);

    Debug() << (doSlowChecks ? "CheckDB: Verified" : (doNeededCheck ? "Checked" : "Loaded"))
            << " RPA db in " << t0.msecStr() << " msec";
}

bool Storage::deleteRpaEntriesFromHeight(rocksdb::WriteBatch *batch, const BlockHeight height, bool flush, bool force)
{
    if (!force && p->rpaInfo.firstHeight <= -1) return true; // fast path for disabled or empty index)
    if (height > unsigned(std::numeric_limits<int>::max())) throw InternalError(QString("Bad argument to ") + __func__);
    constexpr uint32_t u32max = std::numeric_limits<uint32_t>::max();
    QByteArray endKey = RpaDBKey(u32max).toBytes();
    endKey.append('\xff'); // ensue covers entire remaining uint32 range by appending a single 0xff byte to make this endkey longer than the last uint32 possible.

    rocksdb::Status status;

    if (batch)
        status = batch->DeleteRange(p->db.rpa, ToSlice(RpaDBKey(height)), ToSlice(endKey));
    else
        status = p->db->DeleteRange(p->db.defWriteOpts, p->db.rpa, ToSlice(RpaDBKey(height)), ToSlice(endKey));

    if (!status.ok()) {
        Warning() << __func__ << ": failed in call to db DeleteRange for height (>= " << height << "): "
                  << StatusString(status);
        return false;
    }
    // Update deletion count and firstHeight and lastHeight as necessary
    p->rpaInfo.nDeletions += 1; // we have no idea how many records were deleted, just increment by 1 since most common case is the undo case, where we delete 1.
    auto & firstHeight = p->rpaInfo.firstHeight, & lastHeight = p->rpaInfo.lastHeight;
    if (lastHeight > -1 && BlockHeight(lastHeight) >= height)
        lastHeight = height > 0u ? int(height - 1u) : -1;
    if (firstHeight > lastHeight)
        firstHeight = lastHeight.load();
    if (flush && !batch) {
        rocksdb::FlushOptions f;
        f.wait = true;
        f.allow_write_stall = true;
        p->db->Flush(f, p->db.rpa);
        p->db->SyncWAL();
    }
    return true;
}

bool Storage::deleteRpaEntriesToHeight(rocksdb::WriteBatch *batch, const BlockHeight height, bool flush, bool force)
{
    if (!force && p->rpaInfo.lastHeight <= -1) return true; // fast path for disabled or empty index
    if (height > unsigned(std::numeric_limits<int>::max())) throw InternalError(QString("Bad argument to ") + __func__);

    rocksdb::Status status;
    if (batch)
        status = batch->DeleteRange(p->db.rpa, ToSlice(RpaDBKey(0u)), ToSlice(RpaDBKey(height + 1u)));
    else
        status = p->db->DeleteRange(p->db.defWriteOpts, p->db.rpa, ToSlice(RpaDBKey(0u)), ToSlice(RpaDBKey(height + 1u)));

    if (!status.ok()) {
        Warning() << __func__ << ": failed in call to db DeleteRange for height (<= " << height << "): "
                  << StatusString(status);
        return false;
    }
    // Update deletion count and firstHeight and lastHeight as necessary
    p->rpaInfo.nDeletions += 1; // we have no idea how many records were deleted, just increment by 1 since most common case is the undo case, where we delete 1.
    auto & firstHeight = p->rpaInfo.firstHeight, & lastHeight = p->rpaInfo.lastHeight;
    if (firstHeight > -1 && BlockHeight(firstHeight) <= height)
        firstHeight = int(height + 1u);
    if (firstHeight > lastHeight)
        firstHeight = lastHeight.load();
    if (flush && !batch) {
        rocksdb::FlushOptions f;
        f.wait = true;
        f.allow_write_stall = true;
        p->db->Flush(f, p->db.rpa);
        p->db->SyncWAL();
    }
    return true;
}

void Storage::clampRpaEntries(BlockHeight from, BlockHeight to)
{
    ExclusiveLockGuard g(p->blocksLock);
    rocksdb::WriteBatch batch;
    clampRpaEntries_nolock(&batch, from, to);
    auto s = p->db->Write(p->db.defWriteOpts, &batch);
    if (!s.ok()) Warning() << __func__ << ": failed in batch write for (" << from << ", " << to << "): " << StatusString(s);
}

void Storage::clampRpaEntries_nolock(rocksdb::WriteBatch *batch, BlockHeight from, BlockHeight to)
{
    if (from > 0u) deleteRpaEntriesToHeight(batch, from - 1u, true);
    if (to < std::numeric_limits<uint32_t>::max()) deleteRpaEntriesFromHeight(batch, to + 1u, true);
    DebugM("Clamped RPA index to: ", from, " -> ", to);
}

void Storage::loadCheckEarliestUndo()
{
    FatalAssert(p->db.undo && p->db,  __func__, ": Undo column family is not open");

    const Tic t0;
    unsigned ctr = 0;
    using UIntSet = std::set<uint32_t>;
    UIntSet swissCheeseDetector;
    {
        std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.undo));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the undo db");
        for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
            const auto keySlice = iter->key();
            if (keySlice.size() != sizeof(uint32_t))
                throw DatabaseFormatError("Unexpected key in undo database. We expect only 32-bit unsigned ints!");
            const uint32_t height = DeserializeScalar<uint32_t, /*BigEndian=*/true>(FromSlice(keySlice));
            if (height < p->earliestUndoHeight) p->earliestUndoHeight = height;
            swissCheeseDetector.insert(height);
            ++ctr;
        }
    }
    if (ctr) {
        Debug() << "Undo db contains " << ctr << " entries, earliest is " << p->earliestUndoHeight.load() << ", "
                << t0.msecStr(2) << " msec elapsed.";
    }
    auto doBatchWrite = [this](rocksdb::WriteBatch &batch) {
        if (auto st = p->db->Write(p->db.defWriteOpts, &batch); !st.ok()) [[unlikely]]
            throw DatabaseError(QString("rocksdb::DB::Write returned an error: %1 ").arg(StatusString(st)));
        p->db->SyncWAL();
    };
    // Detect swiss cheese holes in the height range, and delete the unusable non-contiguous area from the undo db.
    // (This can happen in a very unlikely scenario where the user set max_reorg high then switched back to an old
    // Fulcrum version then switched to this new version again).
    if (unsigned testval{}; !swissCheeseDetector.empty()
                            && (testval = (*swissCheeseDetector.rbegin() - *swissCheeseDetector.begin()) + 1) != ctr) {
        // uh-oh -- there are holes! Argh! User must have run an older Fulcrum version that didn't delete entries past
        // 100 properly -- we need to delete all old undo entries before the first hole
        auto eraseUntil = swissCheeseDetector.end();  --eraseUntil; // point to last element as last 1 by itself is "contiguous"!
        Warning() << "Hole(s) detected in undo db: range (" << testval << ") != counted size (" << ctr << ")";
        for (auto rit = swissCheeseDetector.rbegin(), rprev = rit++; rit != swissCheeseDetector.rend(); rprev = rit++) {
            if (*rprev - *rit == 1) {
                eraseUntil = rit.base(); // no hole here, move the firstContig iterator to point to this element
                --eraseUntil; // rit points to it + 1 so move back 1 (grr)
            } else
                break; // found a hole, abort loop
        }
        // delete everything up until the first contiguous height we saw
        int delctr = 0;
        rocksdb::WriteBatch batch;
        for (auto it = swissCheeseDetector.begin(); it != eraseUntil; ++delctr) {
            GenericBatchDelete(batch, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(*it)));
            it = swissCheeseDetector.erase(it);
        }
        if (delctr)
            doBatchWrite(batch);

        p->earliestUndoHeight = !swissCheeseDetector.empty() ? *swissCheeseDetector.begin() : p->InvalidUndoHeight;
        ctr = swissCheeseDetector.size();
        if (delctr) {
            Warning() << "Deleted " << delctr << Util::Pluralize(" undo entry", delctr) << ", earliest undo entry is now "
                      << p->earliestUndoHeight.load() << ", total undo entries now in db: " << ctr;
        }
    }
    // sanity check that the latest Undo block deserializes correctly (detects older Fulcrum loading newer db)
    if (!swissCheeseDetector.empty()) {
        const uint32_t height = *swissCheeseDetector.rbegin();
        const QString errMsg(QString("Unable to read undo data for height %1").arg(height));
        const UndoInfo undoInfo = GenericDBGetFailIfMissing<UndoInfo>(p->db, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(height), errMsg);
        if (!undoInfo.isValid()) throw DatabaseFormatError(errMsg);
        Debug() << "Latest undo verified ok: " << undoInfo.toDebugString();
    }
    if (ctr > configuredUndoDepth()) {
        // User lowered undo config -- now configured for less undo depth than before.  Simply respect user wishes
        // on startup and delete oldest entries if that happens.  Note the assumption here is that the undo entries
        // are all without holes starting at p->earliestUndoHeight.  That assumption holds in the current code in
        // addBlock(), as it's impossible to get holes due to the way we walk the blockchain history forward, adding
        // blocks 1 at a time. However if the user runs older Fulcrum after having run this newer version on non-default
        // settings, holes MAY appear, hence the warning above.
        const unsigned n2del = ctr - configuredUndoDepth();
        Warning() << "Found " << ctr << " undo entries in db, but max_reorg is " << configuredUndoDepth() << "; "
                  << "deleting " << n2del << Util::Pluralize(" oldest entry", n2del) << " ...";
        const Tic t1;
        rocksdb::WriteBatch batch;
        for (unsigned i = 0; i < n2del; ++i)
            GenericBatchDelete(batch, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(p->earliestUndoHeight++)));
        if (n2del)
            doBatchWrite(batch);
        Warning() << n2del << Util::Pluralize(" undo entry", n2del) << " deleted from db in " << t1.msecStr() << " msec";
    }
}

bool Storage::hasUndo() const {
    return p->earliestUndoHeight != p->InvalidUndoHeight;
}

struct Storage::UTXOBatch::P {
    rocksdb::WriteBatch &batch; ///< batch writes/deletes end up in the utxoset and shunspent column families
    rocksdb::ColumnFamilyHandle &utxoset, &shunspent;
    std::atomic_int64_t &utxoCtr;

    P(rocksdb::WriteBatch &b, rocksdb::ColumnFamilyHandle &u, rocksdb::ColumnFamilyHandle &s, std::atomic_int64_t &uc)
        : batch(b), utxoset(u), shunspent(s), utxoCtr{uc} {}
};

Storage::UTXOBatch::UTXOBatch(rocksdb::WriteBatch &b, rocksdb::ColumnFamilyHandle &u, rocksdb::ColumnFamilyHandle &s,
                              std::atomic_int64_t &uc)
    : p{std::make_unique<P>(b, u, s, uc)} {}
Storage::UTXOBatch::UTXOBatch(UTXOBatch &&o) { p.swap(o.p); }

void Storage::UTXOBatch::add(TXO &&txo, TXOInfo &&info, const CompactTXO &ctxo)
{
    const QByteArray shukey = mkShunspentKey(info.hashX, ctxo),
                     shuval = Serialize2(info.amount, info.tokenDataPtr.get());
    // Update db utxoset, keyed off txo -> txoinfo
    static const QString errMsgPrefix("Failed to add a utxo to the utxo batch");
    GenericBatchPut(p->batch, &p->utxoset, txo, info, errMsgPrefix); // may throw on failure

    // Update the scripthash unspent. This is a very simple table which we scan by hashX prefix using
    // an iterator in listUnspent.  Each entry's key is prefixed with the HashX bytes (32) but suffixed with the
    // serialized CompactTXO bytes (8 or 9). Each entry's data is a 8-byte int64_t of the amount of the utxo to save
    // on lookup cost for getBalance().
    static const QString errMsgPrefix2("Failed to add an entry to the scripthash_unspent batch");
    GenericBatchPut(p->batch, &p->shunspent, shukey, shuval, errMsgPrefix2); // may throw, which is what we want

    ++p->utxoCtr; // tally utxo counts
}

void Storage::UTXOBatch::remove(const TXO &txo, const HashX &hashX, const CompactTXO &ctxo)
{
    // enqueue delete from utxoset db -- may throw.
    static const QString errMsgPrefix("Failed to issue a batch delete for a utxo");
    GenericBatchDelete(p->batch, &p->utxoset, txo, errMsgPrefix);

    // enqueue delete from scripthash_unspent db
    static const QString errMsgPrefix2("Failed to issue a batch delete for a utxo to the scripthash_unspent db");
    GenericBatchDelete(p->batch, &p->shunspent, mkShunspentKey(hashX, ctxo), errMsgPrefix2);

    --p->utxoCtr; // tally utxo counts
}


/// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
std::optional<TXOInfo> Storage::utxoGetFromDB(const TXO &txo, bool throwIfMissing)
{
    assert(bool(p->db.utxoset));
    static const QString errMsgPrefix("Failed to read a utxo from the utxo db");
    return GenericDBGet<TXOInfo>(p->db, p->db.utxoset, txo, !throwIfMissing, errMsgPrefix, false, p->db.defReadOpts);
}

int64_t Storage::utxoSetSize() const { return p->utxoCt; }
double Storage::utxoSetSizeMB() const {
    // TODO: the below is inaccurate because it does not account for any bitcoin::token::OutputDataPtr that may be in TXOInfo
    constexpr int64_t elemSize = TXOInfo::minSerSize() + TXO::minSize() /*<-- assumption is most utxos use 16-bit IONums */;
    return (utxoSetSize()*elemSize) / 1e6;
}

/// Thread-safe. Query the mempool and the DB for a TXO. If the TXO is unspent, will return a valid
/// optional.  If the TXO is spent or non-existant, will return an invalid optional.
std::optional<TXOInfo> Storage::utxoGet(const TXO &txo)
{
    std::optional<TXOInfo> ret;
    bool mempoolHit = false;

    // take shared lock (ensure mempool doesn't mutate from underneath our feet)
    // note that this lock is also taken by addBlock (so this is atomic w.r.t new blocks arriving).
    auto [mempool, lock] = this->mempool(); // shared (read only) lock is held until scope end

    // first, check mempool
    if (auto txsIt = mempool.txs.find(txo.txHash); txsIt != mempool.txs.end()) {
        mempoolHit = true; // flag mempool hit so that we don't redundantly check db at end of this function
        const auto & tx = txsIt->second;
        if (UNLIKELY(!tx)) {
            // Paranoia to detect bugs. This will never happen.
            throw InternalError(QString("TxRef for %1 is null! FIXME!").arg(QString(txo.txHash.toHex())));
        }
        if (txo.outN < tx->txos.size()) {
            const TXOInfo & info = tx->txos[txo.outN];
            if (auto hxIt = tx->hashXs.find(info.hashX); LIKELY(hxIt != tx->hashXs.end())) {
                const auto & ioinfo = hxIt->second;
                if (ioinfo.utxo.count(txo.outN)) {
                    // found! It's unspent!
                    ret = info;
                }
            } else {
                // This happens for OP_RETURN outputs -- they aren't indexed so we can end up here.
                // Silently ignore...
            }
        }
    }
    // next check DB if no mempool hit
    if (!mempoolHit) {
        // it's ok to call this with the mempool lock held (Controller also does this)
        ret = utxoGetFromDB(txo, false);
        if (ret.has_value()) {
            // DB hit; but we need to check the mempool now to ensure TXO wasn't spent.
            if (auto hxTxIt = mempool.hashXTxs.find(ret->hashX); hxTxIt != mempool.hashXTxs.end()) {
                // slow-ish -- linear scan through all mempool tx's pertaining to this scripthash
                // in practice this shouldn't be too bad since it's not often that a particular scripthash
                // has more than a few mempool tx's.
                for (const auto & tx : hxTxIt->second) {
                    if (auto hxInfoIt = tx->hashXs.find(hxTxIt->first); LIKELY(hxInfoIt != tx->hashXs.end())) {
                        const auto & ioinfo = hxInfoIt->second;
                        if (ioinfo.confirmedSpends.count(txo)) {
                            //Debug() << "TXO: " << txo.toString() << " was in DB but is spent in mempool";
                            // DB hit, but was spent in mempool, reset ret so that caller knows it was spent.
                            ret.reset();
                            break; // enclosing ranged for()
                        }
                    } else {
                        // should never happen
                        throw InternalError(QString("scripthash %1 has inconsistent mempool state for tx %2! FIXME!")
                                            .arg(QString(hxTxIt->first.toHex()), QString(tx->hash.toHex())));
                    }
                }
            }
        }
    }
    return ret;
}

void Storage::addBlock(PreProcessedBlockPtr ppb, bool saveUndo, unsigned nReserve, bool notifySubs, const bool trackRecentBlockTxHashes)
{
    assert(bool(ppb) && bool(p));

    std::unique_ptr<UndoInfo> undo;

    if (saveUndo) {
        undo = std::make_unique<UndoInfo>();
        undo->height = ppb->height;
    }

    struct NotifyData {
        using NotifySet = std::unordered_set<HashX, HashHasher>;
        NotifySet scriptHashesAffected, dspTxsAffected, txidsAffected;
    };
    std::unique_ptr<NotifyData> notify;

    if (notifySubs) {
        notify = std::make_unique<NotifyData>(); // note we don't reserve here -- we will reserve at the end when we run through the hashXAggregated set one final time...
    }

    {
        // take all locks now.. since this is a Big Deal. TODO: add more locks here?
        std::scoped_lock guard(p->blocksLock, p->headerVerifierLock, p->blkInfoLock, p->mempoolLock);

        rocksdb::WriteBatch batch; // all writes to DB go through this batch in order to ensure atomicity

        const auto blockTxNum0 = p->txNumNext.load();

        p->recentBlockTxHashes.clear();
        if (notify) {
            // Txs in block can never be in mempool. Ensure they are gone from mempool right away so that notifications
            // to clients are as accurate as possible (notifications may happen after this function returns).
            const auto sz = ppb->txInfos.size();
            const auto rsvsz = static_cast<Mempool::TxHashNumMap::size_type>(sz > 0 ? sz-1 : 0);
            Mempool::TxHashNumMap txidMap(/* bucket_count: */ rsvsz);
            notify->txidsAffected.reserve(rsvsz);
            if (trackRecentBlockTxHashes) {
                p->recentBlockTxHashes.reserve(sz);
                if (sz > 0u) [[likely]]
                    p->recentBlockTxHashes.insert(ppb->txInfos[0].hash); // add coinbase txhash to recent set
            }
            for (std::size_t i = 1 /* skip coinbase */; i < sz; ++i) {
                const auto & txHash = ppb->txInfos[i].hash;
                txidMap.emplace(txHash, blockTxNum0 + i);
                notify->txidsAffected.insert(txHash); // add to notify set for txSubsMgr
                if (trackRecentBlockTxHashes)
                    // add to "recently seen" set for the hashtx zmq notifier spam suppressor
                    p->recentBlockTxHashes.insert(txHash);
            }
            Mempool::ScriptHashesAffectedSet affected;
            // Pre-reserve some capacity for the tmp affected set to avoid much rehashing.
            // Use the heuristic 3 x numtxs capped at the SubsMgr::kRecommendedPendingNotificationsReserveSize (2048).
            affected.reserve(std::min(txidMap.size()*3, SubsMgr::kRecommendedPendingNotificationsReserveSize));
            auto res = p->mempool.confirmedInBlock(affected, txidMap, ppb->height,
                                                   Trace::isEnabled(), 0.5f /* shrink to fit load_factor threshold */);
            if (const auto diff = res.oldSize - res.newSize; (diff || res.elapsedMsec > 5.) && Debug::isEnabled()) {
                Debug d;
                d << "addBlock: removed " << diff << " txs from mempool involving "
                  << affected.size() << " addresses";
                if (res.dspRmCt || res.dspTxRmCt)
                    d << " (also removed dsps: " << res.dspRmCt << ", dspTxs: " << res.dspTxRmCt << ")";
                if (res.rpaRmCt)
                    d << " (also removed rpa entries: " << res.rpaRmCt << ")";
                d << " in " << QString::number(res.elapsedMsec, 'f', 3) << " msec";
            }
            notify->scriptHashesAffected.merge(std::move(affected));
            notify->dspTxsAffected.merge(std::move(res.dspTxsAffected));
            // ^^ notify->txidsAffected is updated in the above loop
        }

        const auto verifUndo = p->headerVerifier; // keep a copy of verifier state for undo purposes in case this fails
        // This object ensures that if an exception is thrown while we are in the below code, we undo the header verifier
        // and return it to its previous state.  Note the defer'd functor is called with the above scoped_lock held.
        Defer undoVerifierOnScopeEnd([&verifUndo, this] { p->headerVerifier = verifUndo; });

        // code in the below block may throw -- exceptions are propagated out to caller.
        {
            // Verify header chain makes sense (by checking hashes, using the shared header verifier)
            QByteArray rawHeader;
            {
                QString errMsg;
                if (!p->headerVerifier(ppb->header, &errMsg) ) {
                    // XXX possible reorg point. Caller will/should roll back the db state via issuing calls to undoLatestBlock()
                    throw HeaderVerificationFailure(errMsg);
                }
                // save raw header back to our buffer -- this will be used at the end of this function to add it to the db
                // after everything completes successfully.
                rawHeader = p->headerVerifier.lastHeaderProcessed().second;
            }

            setDirty(batch, true); // <--  no turning back. we set it dirty in case rocksdb atomicity fails here; if the app crashes unexpectedly while this is set, on next restart it will refuse to run and insist on a clean resynch if this is true.

            {  // add txnum -> txhash association to the TxNumsFile...
                auto ctx = p->db.txNumsDRA->beginBatchWrite(batch); // may throw if io error in c'tor here.
                QString errStr;
                for (const auto & txInfo : ppb->txInfos) {
                    if (!ctx.append(txInfo.hash, &errStr)) // does not throw here, but we do.
                        throw InternalError(QString("Batch append for txNums failed: %1.").arg(errStr));
                }
                // <-- The `ctx` d'tor may throw here if a low-level DB error occurs (see: DBRecordArray.cpp, ~BatchWriteContext()).
            }

            p->txNumNext += ppb->txInfos.size(); // update internal counter

            if (p->txNumNext != p->db.txNumsDRA->numRecords())
                throw InternalError("TxNum file and internal txNumNext counter disagree! FIXME!");

            // Asynch task -- the future will automatically be awaited on scope end (even if we throw here!)
            // NOTE: The assumption here is that ppb->txInfos is ok to share amongst threads -- that is, the assumption
            // is that nothing mutates it.  If that changes, please re-examine this code.
            CoTask::Future fut; // if valid, will auto-wait for us on scope end
            TxHash2TxNumMgr::PhasedOp txhash2txnumPhases;
            if (ppb->txInfos.size() > 1000) {
                // submit this to the co-task for blocks with enough txs
                fut = p->blocksWorker->submitWork([&]{
                    txhash2txnumPhases = p->db.txhash2txnumMgr->insertForBlockPhased(batch, blockTxNum0, ppb->txInfos);
                    txhash2txnumPhases->doAsyncPhase1(); // do this CPU-bound part on another core
                });
            } else {
                // otherwise just do the work ourselves immediately here since this is likely faster (less overhead)
                p->db.txhash2txnumMgr->insertForBlock(batch, blockTxNum0, ppb->txInfos);
            }

            constexpr bool debugPrt = false;

            // update utxoSet & scritphash history
            {
                std::unordered_set<HashX, HashHasher> newHashXInputsResolved;
                newHashXInputsResolved.reserve(1024); ///< todo: tune this magic number?

                {
                    // utxo batch block (updtes utxoset & scripthash_unspent tables)
                    UTXOBatch utxoBatch{batch, *p->db.utxoset, *p->db.shunspent, p->utxoCt};

                    // reserve space in undo, if in saveUndo mode
                    if (undo) {
                        undo->addUndos.reserve(ppb->outputs.size());
                        undo->delUndos.reserve(ppb->inputs.size());
                    }

                    // add outputs
                    for (const auto & [hashX, ag] : std::as_const(ppb->hashXAggregated)) {
                        for (const auto oidx : ag.outs) {
                            const auto & out = ppb->outputs[oidx];
                            if (out.spentInInputIndex.has_value()) {
                                if constexpr (debugPrt)
                                    Debug() << "Skipping output #: " << oidx << " for " << ppb->txInfos[out.txIdx].hash.toHex() << " (was spent in same block tx: " << ppb->txInfos[ppb->inputs[*out.spentInInputIndex].txIdx].hash.toHex() << ")";
                                continue;
                            }
                            const TxHash & hash = ppb->txInfos[out.txIdx].hash;
                            TXO txo{.txHash = hash, .outN = out.outN};
                            TXOInfo info{
                                .amount = out.amount,
                                .hashX = hashX,
                                .confirmedHeight = ppb->height,
                                .txNum = blockTxNum0 + out.txIdx,
                                .tokenDataPtr = out.tokenDataPtr,
                            };
                            const CompactTXO ctxo(info.txNum, txo.outN);
                            if (undo) { // save undo info if we are in saveUndo mode
                                undo->addUndos.emplace_back(txo, info.hashX, ctxo);
                            }
                            if constexpr (debugPrt)
                                Debug() << "Added txo: " << txo.toString()
                                        << " (txid: " << hash.toHex() << " height: " << ppb->height << ") "
                                        << " amount: " << info.amount.ToString() << " for HashX: " << info.hashX.toHex();
                            utxoBatch.add(std::move(txo), std::move(info), ctxo); // add to db
                        }
                    }

                    // add spends (process inputs)
                    unsigned inum = 0;
                    for (auto & in : ppb->inputs) {
                        const TXO txo{.txHash = in.prevoutHash, .outN = in.prevoutN};
                        if (!inum) {
                            // coinbase.. skip
                        } else if (in.parentTxOutIdx.has_value()) {
                            // was an input that was spent in this block so it's ok to skip.. we never added it to utxo set
                            if constexpr (debugPrt)
                                Debug() << "Skipping input " << txo.toString() << ", spent in this block (output # " << *in.parentTxOutIdx << ")";
                        } else if (std::optional<TXOInfo> opt = utxoGetFromDB(txo)) {
                            const TXOInfo & info = *opt;
                            if (info.confirmedHeight.has_value() && *info.confirmedHeight != ppb->height) {
                                // was a prevout from a previos block.. so the ppb didn't have it in the 'involving hashx' set..
                                // mark the spend as having involved this hashX for this ppb now.
                                auto & ag = ppb->hashXAggregated[info.hashX];
                                ag.ins.emplace_back(inum);
                                newHashXInputsResolved.insert(info.hashX);
                                // mark its txidx
                                if (auto & vec = ag.txNumsInvolvingHashX; vec.empty() || vec.back() != in.txIdx)
                                    vec.emplace_back(in.txIdx);

                            }
                            if constexpr (debugPrt) {
                                const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                                Debug() << "Spent " << txo.toString() << " amount: " << info.amount.ToString()
                                        << " in txid: "  << dbgTxIdHex << " height: " << ppb->height
                                        << " input number: " << ppb->numForInputIdx(inum).value_or(0xffff)
                                        << " HashX: " << info.hashX.toHex();
                            }
                            if (undo) { // save undo info, if we are in saveUndo mode
                                undo->delUndos.emplace_back(txo, info);
                            }
                            // Enqueue deletion from db
                            utxoBatch.remove(txo, info.hashX, CompactTXO(info.txNum, txo.outN)); // enqueue deletion
                        } else {
                            QString s;
                            {
                                const auto dbgTxIdHex = ppb->txHashForInputIdx(inum).toHex();
                                QTextStream ts(&s);
                                ts << "Failed to spend: " << in.prevoutHash.toHex() << ":" << in.prevoutN << " (spending txid: " << dbgTxIdHex << ")";
                            }
                            throw InternalError(s);
                        }
                        ++inum;
                    }
                }

                // sort and shrink_to_fit new hashX inputs added
                for (const auto & hashX : newHashXInputsResolved) {
                    auto & ag = ppb->hashXAggregated[hashX];
                    std::sort(ag.ins.begin(), ag.ins.end()); // make sure they are sorted
                    std::sort(ag.txNumsInvolvingHashX.begin(), ag.txNumsInvolvingHashX.end());
                    auto last = std::unique(ag.txNumsInvolvingHashX.begin(), ag.txNumsInvolvingHashX.end());
                    ag.txNumsInvolvingHashX.erase(last, ag.txNumsInvolvingHashX.end());
                    ag.ins.shrink_to_fit();
                    ag.txNumsInvolvingHashX.shrink_to_fit();
                }

                if constexpr (debugPrt)
                    Debug() << "utxoset size: " << utxoSetSize() << " block: " << ppb->height;
            }

            {
                // now.. update the txNumsInvolvingHashX to be offset from txNum0 for this block, and save history to db table
                // history is hashX -> TxNumVec (serialized) as a serities of 6-bytes txNums in blockchain order as they appeared.
                if (notify)
                    // first, reserve space for notifications
                    notify->scriptHashesAffected.reserve(notify->scriptHashesAffected.size() + ppb->hashXAggregated.size());
                for (auto & [hashX, ag] : ppb->hashXAggregated) {
                    if (notify) notify->scriptHashesAffected.insert(hashX); // fast O(1) insertion because we reserved the right size above.
                    for (auto & txNum : ag.txNumsInvolvingHashX) {
                        txNum += blockTxNum0; // transform local txIdx to -> txNum (global mapping)
                    }
                    // save scripthash history for this hashX, by appending to existing history. Note that this uses
                    // the 'ConcatOperator' class we defined in this file, which requires rocksdb be compiled with RTTI.
                    if (auto st = batch.Merge(p->db.shist, ToSlice(hashX), ToSlice(Serialize(ag.txNumsInvolvingHashX))); !st.ok())
                        throw DatabaseError(QString("batch merge fail for hashX %1, block height %2: %3")
                                            .arg(QString(hashX.toHex())).arg(ppb->height).arg(StatusString(st)));
                }
            }


            {
                // update BlkInfo
                if (nReserve) {
                    if (const auto size = p->blkInfos.size(); size + 1 > p->blkInfos.capacity())
                        p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
                }

                const auto & blkInfo = p->blkInfos.emplace_back(
                    blockTxNum0, // .txNum0
                    unsigned(ppb->txInfos.size())
                );

                p->blkInfosByTxNum[blkInfo.txNum0] = unsigned(p->blkInfos.size()-1);

                // save BlkInfo to db
                static const QString blkInfoErrMsg("Error writing BlkInfo to db");
                GenericBatchPut(batch, p->db.blkinfo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(ppb->height)),
                                blkInfo.toBytes(), blkInfoErrMsg);

                if (undo) {
                    // save blkInfo to undo information, if in saveUndo mode
                    undo->blkInfo = p->blkInfos.back();
                }
            }

            // Save RPA PrefixTable record (appends a single row to DB), if RPA is enabled for this block
            if (ppb->serializedRpaPrefixTable) {
                addRpaDataForHeight_nolock(batch, ppb->height, ppb->hash, *ppb->serializedRpaPrefixTable); // may throw theoretically if GenericBatchPut threw
            }

            // save the last of the undo info, if in saveUndo mode
            if (undo) {
                const Tic t0;
                undo->hash = BTC::HashRev(rawHeader);
                undo->scriptHashes = Util::keySet<decltype (undo->scriptHashes)>(ppb->hashXAggregated);
                static const QString errPrefix("Error saving undo info to undo db");

                GenericBatchPut(batch, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(ppb->height)),
                                *undo, errPrefix); // save undo to db
                if (ppb->height < p->earliestUndoHeight) {
                    // remember earliest for delete clause below...
                    p->earliestUndoHeight = ppb->height;
                }

                if constexpr (debugPrt) {
                    // testing undo ser/deser
                    Debug() << "Undo info 1: " << undo->toDebugString();
                    QByteArray ba = Serialize(*undo);
                    Debug() << "Undo info 1 serSize: " << ba.length();
                    bool ok;
                    auto undo2 = Deserialize<UndoInfo>(ba, &ok);
                    ba.fill('z'); // ensure no shallow copies of buffer exist in deserialized object. if they do below tests will fail
                    FatalAssert(ok && undo2.isValid(), "Deser of undo info failed!");
                    Debug() << "Undo info 2: " << undo2.toDebugString();
                    Debug() << "Undo info 1 == undo info 2: " << (*undo == undo2);
                } else {
                    const auto elapsedms = t0.msecStr(2);
                    const size_t nTx = undo->blkInfo.nTx, nSH = undo->scriptHashes.size();
                    Debug() << "Saved V3 undo for block " << undo->height << ", "
                            << nTx << " " << Util::Pluralize("transaction", nTx)
                            << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
                            << ", in " << elapsedms << " msec.";
                }
            }
            // Expire old undos >configuredUndoDepth() blocks ago to keep the db tidy.
            // We only do this if we know there is an old undo for said height in db.
            // Note that the assumption here is that no holes exist, and that we always walk
            // forward with addBlock() 1 block at a time (which is a valid assumption in this codebase).
            if (const auto expireUndoHeight = int(ppb->height) - int(configuredUndoDepth());
                    expireUndoHeight >= 0 && unsigned(expireUndoHeight) >= p->earliestUndoHeight) {
                // FIXME -- this runs for every block in between the last undo save and current tip.
                // If the node was off for a while then restarted this just hits the db with useless deletes for non-existant
                // keys as we catch up.  It's not the end of the world, as each call here is on the order of microseconds..
                // but perhaps we need to see about fixing this to not do that.
                static const QString errPrefix("Error deleting old/stale undo info from undo db");
                GenericBatchDelete(batch, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(expireUndoHeight)), errPrefix);
                p->earliestUndoHeight = unsigned(expireUndoHeight + 1);
                if constexpr (debugPrt) DebugM("Deleted undo for block ", expireUndoHeight, ", earliest now ", p->earliestUndoHeight.load());
            }

            appendHeader(batch, rawHeader, ppb->height);

            if (ppb->height == 0) [[unlikely]] {
                // update genesis hash now if block 0 -- this info is used by rpc method server.features
                p->genesisHash = BTC::HashRev(rawHeader); // this variable is guarded by p->headerVerifierLock
            }

            saveUtxoCt(batch);

            // Wait for the txhash2txnum asyncPhase1 to finish before we proceed.
            if (fut.future.valid()) {
                fut.future.get(); // wait for completion; this may throw if task threw
                if (txhash2txnumPhases) txhash2txnumPhases->doSyncPhase2(); // issue write batch; may throw
            }

            setDirty(batch, false);

            if (auto st = p->db->Write(p->db.defWriteOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("Batch write fail for block height %1: %2").arg(ppb->height).arg(StatusString(st)));

            undoVerifierOnScopeEnd.disable(); // indicate to the "Defer" object declared at the top of this function that it shouldn't undo anything anymore as we are happy now with the db state now.
        }

        // If we are in "notify" mode then it's after initial synch, so be cautious and do SyncWAL for each block for
        // safety despite the potential tiny performance hit here.
        if (notify)
            p->db->SyncWAL();

    } /// release locks

    // now, do notifications with locks NOT held (we are being defensive: in the future we may modify below to take e.g. mempool lock)
    if (notify) {
        if (subsmgr && !notify->scriptHashesAffected.empty())
            subsmgr->enqueueNotifications(std::move(notify->scriptHashesAffected));
        if (dspsubsmgr && !notify->dspTxsAffected.empty())
            dspsubsmgr->enqueueNotifications(std::move(notify->dspTxsAffected));
        if (txsubsmgr && !notify->txidsAffected.empty())
            txsubsmgr->enqueueNotifications(std::move(notify->txidsAffected));
    }
}

/// NB: Caller should probably hold some locks to avoid consistency issues... even though this function is inherently thread-safe.
void Storage::addRpaDataForHeight_nolock(rocksdb::WriteBatch &batch, const BlockHeight height, const BlockHash &bhash, const QByteArray &ser)
{
    Tic t0;

    static const QString rpaErrMsg("Error writing block RPA data to db");
    QByteArray shortBHash;
    if (bhash.size() != HashLen) [[unlikely]]
        throw InternalError(QString("%1: bhash.size() != HashLen! This should never happen! FIXME!").arg(__func__));
    shortBHash = bhash.right(kRpaShortBlockHashLen);
    GenericBatchPut(batch, p->db.rpa, RpaDBKey(height), shortBHash + ser, rpaErrMsg);
    // Update RpaInfo stats: latest height, etc.
    if (const int lh = p->rpaInfo.lastHeight; UNLIKELY(lh > -1 && lh != int(height) - 1)) {
        // This should never happen. Warn if this invariant is violated to detect bugs.
        Warning() << "RPA index lastHeight (" << lh << ") not as expected (" << (int(height) - 1) << ")."
                  << " Flagging DB as needing a full check.";
        setRpaNeedsFullCheck(true); // flag the RPA db for a full check on next run
    }
    if (const int fh = p->rpaInfo.firstHeight; UNLIKELY(fh > -1 && fh > int(height))) {
        // This should never happen. Warn if this invariant is violated to detect bugs.
        Warning() << "RPA index firstHeight (" << fh << ") not as expected (should be <= " << int(height) << ")."
                  << " Flagging DB as needing a full check.";
        p->rpaInfo.firstHeight = height;
        setRpaNeedsFullCheck(true); // flag the RPA db for a full check on next run
    }
    p->rpaInfo.lastHeight = height;
    if (p->rpaInfo.firstHeight < 0) p->rpaInfo.firstHeight = height;
    ++p->rpaInfo.nWrites;
    p->rpaInfo.nBytesWritten += sizeof(uint32_t) + ser.size();

    if (Debug::isEnabled() && (ser.size() >= 200'000 || t0.msec() >= 20))
        Debug() << "Saved RPA height: " << height << ", size: " << ser.size() << ", elapsed: " << t0.msecStr() << " msec";
}

void Storage::addRpaDataForHeight(BlockHeight height, const BlockHash &bhash, const QByteArray &serializedRpaPrefixTable)
{
    ExclusiveLockGuard g(p->blocksLock);
    rocksdb::WriteBatch batch;
    addRpaDataForHeight_nolock(batch, height, bhash, serializedRpaPrefixTable);
    auto s = p->db->Write(p->db.defWriteOpts, &batch);
    if (!s.ok()) Warning() << __func__ << ": failed in batch write for height " << height << ": " << StatusString(s);
}

BlockHeight Storage::undoLatestBlock(bool notifySubs)
{
    BlockHeight prevHeight{0};
    size_t nSH = 0; // for stats printing
    using NotifySet = std::unordered_set<HashX, HashHasher>;
    struct NotifyData {
        using NotifySet = std::unordered_set<HashX, HashHasher>;
        NotifySet scriptHashesAffected, dspTxsAffected, txidsAffected;
    };
    std::unique_ptr<NotifyData> notify;

    if (notifySubs) {
        notify = std::make_unique<NotifyData>(); // note we don't reserve here -- we will reserve at the end when we run through the hashXAggregated set one final time...
    }

    {
        // take all locks now.. since this is a Big Deal. TODO: add more locks here?
        std::scoped_lock guard(p->blocksLock, p->headerVerifierLock, p->blkInfoLock, p->mempoolLock);

        const Tic t0;

        // NOTE: For very full mempools, this clear has the potential to stall the app after the reorg
        // completes since the app will have to re-download the whole mempool state again.
        //
        // However, since reorging is (hopefully) a rare event -- the potential performance hit here
        // in doing a mempool clear (and subsequent redownload) is hopefully acceptable. We have to
        // pick the lesser of two evils here.
        //
        // We decided to clear on reorg because reorging takes a few seconds (or more) and may end up
        // walking back more than 1 block.. so if we didn't clear here, clients migh get a *very*
        // inconsistent view of their tx histories -- with potential spends in mempool for tx's that
        // don't exist or are double-spent, etc.  The safer option here is to clear, despite the
        // performance hit.
        //
        if (notify) {
            // mark ALL of mempool for notify so we can detect drops that weren't in block but also disappeared from mempool properly
            notify->scriptHashesAffected.merge(Util::keySet<NotifySet>(p->mempool.hashXTxs));
            if (!p->mempool.dsps.empty())
                // since we will be clearing, just flag all in-mempool dspTxs as affected
                notify->dspTxsAffected.merge(Util::keySet<NotifySet>(p->mempool.dsps.getTxDspsMap()));
            notify->txidsAffected.merge(Util::keySet<NotifySet>(p->mempool.txs)); // for txSubsMgr
        }
        p->mempool.clear(); // make sure mempool is clean (see note above as to why)
        p->recentBlockTxHashes.clear(); // these are no longer relevant if undoing

        const auto [tip, header] = p->headerVerifier.lastHeaderProcessed();
        if (tip <= 0 || header.length() != p->blockHeaderSize()) throw UndoInfoMissing("No header to undo");
        prevHeight = unsigned(tip-1);
        Header prevHeader;
        {
            // grab previous header now
            QString err;
            auto opt = headerForHeight_nolock(prevHeight, &err);
            if (!opt.has_value()) throw UndoInfoMissing(err);
            prevHeader = *opt;
        }
        const QString errMsg1 = QStringLiteral("Unable to retrieve undo info for %1").arg(tip);
        auto undoOpt = GenericDBGet<UndoInfo>(p->db, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(tip)),
                                              true, errMsg1, false, p->db.defReadOpts);
        if (!undoOpt.has_value())
            throw UndoInfoMissing(errMsg1);
        auto & undo = *undoOpt; // non-const because we swap out its scripthashes potentially below if notifySubs == true

        // ensure undo info sanity
        if (!undo.isValid() || undo.height != unsigned(tip) || undo.hash != BTC::HashRev(header)
            || prevHeight+1 >= p->blkInfos.size() || p->blkInfos.empty() || p->blkInfos.back() != undo.blkInfo)
            throw DatabaseFormatError(QString("The undo information for height %1 was successfully retrieved from the "
                                              "database, but it failed an internal consistency check.").arg(tip));
        {
            // all sanity check passed. Now, undo things in reverse order of what we did in addBlock above, rougly speaking

            rocksdb::WriteBatch batch; // all writes to DB go through this batch in order to ensure atomicity

            // first, undo the header
            p->headerVerifier.reset(prevHeight+1, prevHeader);
            setDirty(batch, true); // <-- no turning back. we clear this flag at the end
            deleteHeadersPastHeight(batch, prevHeight);
            p->merkleCache->truncate(prevHeight+1); // this takes a length, not a height, which is always +1 the height

            // undo the blkInfo from the back
            p->blkInfos.pop_back();
            p->blkInfosByTxNum.erase(undo.blkInfo.txNum0);
            GenericBatchDelete(batch, p->db.blkinfo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(undo.height)),
                               "Failed to delete blkInfo in undoLatestBlock");
            deleteRpaEntriesFromHeight(&batch, undo.height); // delete RPA >= undo.height (iff index is enabled)

            // clear num2hash cache
            p->lruNum2Hash.clear();
            // remove block from txHashes cache
            p->lruHeight2Hashes_BitcoindMemOrder.remove(undo.height);

            const auto txNum0 = undo.blkInfo.txNum0;

            // Asynch task -- the future will automatically be awaited on scope end (even if we throw here!)
            // Note: we await the result later down in this function before we truncate the txNumsFile. (Assumption
            // here is that the txNumsFile has all the hashes we want to delete until the below operation is done).
            TxHash2TxNumMgr::PhasedOp txhash2txnumPhases;
            CoTask::Future fut = p->blocksWorker->submitWork([&]{
                txhash2txnumPhases = p->db.txhash2txnumMgr->truncateForUndoPhased(batch, txNum0);
                txhash2txnumPhases->doAsyncPhase1();
            });

            // undo the scripthash histories
            for (const auto & sh : undo.scriptHashes) {
                const QString shHex = Util::ToHexFast(sh);
                const auto vec = GenericDBGetFailIfMissing<TxNumVec>(p->db, p->db.shist, sh, QStringLiteral("Undo failed because we failed to retrieve the scripthash history for %1").arg(shHex), false, p->db.defReadOpts);
                TxNumVec newVec;
                newVec.reserve(vec.size());
                for (const auto txNum : vec) {
                    if (txNum < txNum0) {
                        // accept only stuff in history that's before txNum0 for this block, filter out everything else
                        newVec.push_back(txNum);
                    }
                }
                const QString errMsg = QStringLiteral("Undo failed because we failed to write the new scripthash history for %1").arg(shHex);
                if (!newVec.empty()) {
                    // The below is entirely unnecessary as the txnums should be already sorted and unique in the db data.
                    // We are doing this here to illustrate that this invariant in the data is very important.
                    // Block undo is intended to be an infrequent process (and thus not especially performance-critical),
                    // so this does no harm.
                    std::sort(newVec.begin(), newVec.end());
                    auto last = std::unique(newVec.begin(), newVec.end());
                    newVec.erase(last, newVec.end());
                }
                if (!newVec.empty()) {
                    // the sh still has some history, write it to db
                    GenericBatchPut(batch, p->db.shist, sh, newVec, errMsg);
                } else {
                    // the sh in question lost all its history as a result of undo, just delete it from db to save space
                    GenericBatchDelete(batch, p->db.shist, sh, errMsg);
                }
            }

            {
                // UTXO set update
                UTXOBatch utxoBatch{batch, *p->db.utxoset, *p->db.shunspent, p->utxoCt};

                // now, undo the utxo deletions by re-adding them
                for (auto & [txo, info] : undo.delUndos) {
                    // note that deletions may have an info with a txnum before this block, for obvious reasons
                    utxoBatch.add(std::move(txo), std::move(info), CompactTXO(info.txNum, txo.outN)); // may throw
                }

                // now, undo the utxo additions by deleting them
                for (const auto & [txo, hashx, ctxo] : undo.addUndos) {
                    assert(ctxo.txNum() >= txNum0); // all of the additions must have been in this block or newer
                    utxoBatch.remove(txo, hashx, ctxo); // may throw
                }
            }

            if (p->earliestUndoHeight >= undo.height)
                // oops, we're out of undos now!
                p->earliestUndoHeight = p->InvalidUndoHeight;
            GenericBatchDelete(batch, p->db.undo, SerializeScalarEphemeral</*BigEndian=*/true>(uint32_t(undo.height))); // make sure to delete this undo info since it was just applied.

            // add all tx hashes that we are rolling back to the notify set for the txSubsMgr
            if (notify) {
                const auto txHashes = p->db.txNumsDRA->readRecords(txNum0, undo.blkInfo.nTx);
                notify->txidsAffected.insert(txHashes.begin(), txHashes.end());
            }

            // Wait for the txhash2txnum truncate to finish before we proceed, since that co-task assumes the txNumsFile
            // won't change.
            if (fut.future.valid()) {
                fut.future.get(); // this may throw if task threw
                if (txhash2txnumPhases) txhash2txnumPhases->doSyncPhase2(); // may throw (unlikely)
            }

            // lastly, truncate the tx num file and re-set txNumNext to point to this block's txNum0 (thereby recycling it)
            assert(long(p->txNumNext) - long(txNum0) == long(undo.blkInfo.nTx));
            p->txNumNext = txNum0;
            {
                auto ctx = p->db.txNumsDRA->beginBatchWrite(batch);
                QString err;
                if (ctx.truncate(txNum0, &err) != txNum0 || !err.isEmpty()) {
                    throw InternalError(QString("Failed to truncate txNumsFile to %1: %2").arg(txNum0).arg(err));
                }
            }

            saveUtxoCt(batch);
            setDirty(batch, false); // phew. done.

            if (auto st = p->db->Write(p->db.defWriteOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("Batch write fail for undo of block height %1: %2")
                                        .arg(tip).arg(StatusString(st)));

            p->db->SyncWAL();

            nSH = undo.scriptHashes.size();

            if (notify) {
                if (notify->scriptHashesAffected.empty())
                    notify->scriptHashesAffected.swap(undo.scriptHashes);
                else
                    notify->scriptHashesAffected.merge(std::move(undo.scriptHashes));
            }
        }

        const size_t nTx = undo.blkInfo.nTx;
        const auto elapsedms = t0.msecStr(2);
        Log() << "Applied undo for block " << undo.height << " hash " << Util::ToHexFast(undo.hash) << ", "
              << nTx << " " << Util::Pluralize("transaction", nTx)
              << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
              << ", in " << elapsedms << " msec, new height now: " << prevHeight;

        // If we are in "notify" mode then it's after initial synch, so be cautious and do SyncWAL for each block undo
        // for safety despite the potential tiny performance hit here.
        if (notify) p->db->SyncWAL();

    } // release locks

    // now, do notifications
    if (notify) {
        if (subsmgr && !notify->scriptHashesAffected.empty())
            subsmgr->enqueueNotifications(std::move(notify->scriptHashesAffected));
        if (dspsubsmgr && !notify->dspTxsAffected.empty())
            dspsubsmgr->enqueueNotifications(std::move(notify->dspTxsAffected));
        if (txsubsmgr && !notify->txidsAffected.empty())
            txsubsmgr->enqueueNotifications(std::move(notify->txidsAffected));
    }

    return prevHeight;
}


void Storage::setDirty(rocksdb::WriteBatch &batch, bool dirtyFlag)
{
    static const QString errPrefix("Error saving dirty flag to the meta db");
    const auto & val = dirtyFlag ? kTrue : kFalse;
    GenericBatchPut(batch, p->db.meta, kDirty, val, errPrefix);
}

bool Storage::isDirty_impl(rocksdb::DB *db, rocksdb::ColumnFamilyHandle *cf) const
{
    static const QString errPrefix("Error reading dirty flag from the meta db");
    return GenericDBGet<bool>(db, cf, kDirty, true, errPrefix, false, p->db.defReadOpts).value_or(false);
}

bool Storage::isDirty() const { return isDirty_impl(p->db, p->db.meta); }

void Storage::setRpaNeedsFullCheck(const bool val)
{
    if (!p->db.meta) return;
    static const QString errPrefix("Error saving rpa_needs_full_check flag to the meta db");
    const auto & slice = val ? kTrue : kFalse;
    GenericDBPut(p->db, p->db.meta, kRpaNeedsFullCheck, slice, errPrefix, p->db.defWriteOpts);
    p->rpaInfo.rpaNeedsFullCheckCachedVal = int(val);
    DebugM("Wrote rpa_needs_full_check = ", val, " to db");
}

bool Storage::isRpaNeedsFullCheck() const
{
    if (!p->db.meta) return false;
    const int cachedVal = p->rpaInfo.rpaNeedsFullCheckCachedVal.load();
    if (cachedVal > -1) return cachedVal;
    static const QString errPrefix("Error reading rpa_needs_full_check flag from the meta db");
    const int dbVal = /* 0 or 1 */ GenericDBGet<bool>(p->db, p->db.meta, kRpaNeedsFullCheck, true, errPrefix, false,
                                                      p->db.defReadOpts).value_or(false);
    p->rpaInfo.rpaNeedsFullCheckCachedVal = dbVal;
    return dbVal;
}

// public version of above, always latches to true
void Storage::flagRpaIndexAsPotentiallyInconsistent()
{
    ExclusiveLockGuard g(p->blocksLock);
    setRpaNeedsFullCheck(true);
}

bool Storage::runRpaSlowCheckIfDBIsPotentiallyInconsistent(BlockHeight configuredStartHeight, BlockHeight tipHeight)
{
    ExclusiveLockGuard g(p->blocksLock);
    if (isRpaNeedsFullCheck()) {
        try {
            // To avoid infinite consistency-check-loops if there is a gap at the beginning before our configured height
            // we must clamp the DB to the height range we know we need now, before proceeding.
            clampRpaEntries_nolock(nullptr, configuredStartHeight, tipHeight);
            loadCheckRpaDB();
        } catch (const std::exception &e) { Fatal() << "Caught exception: " << e.what(); }
        return true;
    }
    return false;
}


void Storage::saveUtxoCt(rocksdb::WriteBatch &batch)
{
    static const QString errPrefix("Error writing the utxo count to the meta db");
    const int64_t ct = p->utxoCt.load();
    GenericBatchPut(batch, p->db.meta, kUtxoCount, ct, errPrefix);
}
int64_t Storage::readUtxoCtFromDB() const
{
    static const QString errPrefix("Error reading the utxo count from the meta db");
    return GenericDBGet<int64_t>(p->db, p->db.meta, kUtxoCount, true, errPrefix, false, p->db.defReadOpts).value_or(0LL);
}


std::optional<TxHash> Storage::hashForTxNum(TxNum n, bool throwIfMissing, bool *wasCached, bool skipCache) const
{
    std::optional<TxHash> ret;
    if (!skipCache) ret = p->lruNum2Hash.object(n);
    if (ret.has_value()) {
        if (wasCached) *wasCached = true;
        ++p->lruCacheStats.num2HashHits;
        return ret;
    } else if (wasCached) *wasCached = false;
    if (!skipCache) ++p->lruCacheStats.num2HashMisses;

    static const QString kErrMsg ("Error reading TxHash for TxNum %1: %2");
    QString errStr;
    const auto bytes = p->db.txNumsDRA->readRecord(n, &errStr);
    if (bytes.isEmpty()) {
        errStr = kErrMsg.arg(n).arg(errStr);
        if (throwIfMissing)
            throw DatabaseError(errStr);
        Warning() << errStr;
    } else {
        ret.emplace(bytes);
    }
    if (!skipCache && ret.has_value()) {
        // save in cache
        p->lruNum2Hash.insert(n, *ret, p->lruNum2HashSizeCalc());
    }
    return ret;
}

std::optional<unsigned> Storage::heightForTxNum(TxNum n) const
{
    SharedLockGuard g(p->blkInfoLock);
    return heightForTxNum_nolock(n);
}

std::optional<unsigned> Storage::heightForTxNum_nolock(TxNum n) const
{
    std::optional<unsigned> ret;
    auto it = p->blkInfosByTxNum.upper_bound(n);  // O(logN) search; find the block *AFTER* n, then go back one to find the block in range
    if (it != p->blkInfosByTxNum.begin()) {
        --it;
        const auto & bi = p->blkInfos[it->second];
        if (n >= bi.txNum0 && n < bi.txNum0+bi.nTx)
            ret = it->second;
    }
    return ret;
}

std::optional<TxHash> Storage::hashForHeightAndPos(BlockHeight height, uint32_t posInBlock,
                                                   const SharedLockGuard *existingBlocksLock) const
{
    std::optional<TxHash> ret;
    Span<const uint32_t> singleItem{&posInBlock, size_t{1u}};
    auto vec = hashesForHeightAndPosVec(height, singleItem, existingBlocksLock);
    if (vec.empty()) return ret; // bad height
    ret = std::move(vec.front());
    return ret;
}

std::vector<std::optional<TxHash>> Storage::hashesForHeightAndPosVec(BlockHeight height, Span<const uint32_t> positionsInBlock,
                                                                     const SharedLockGuard *existingBlocksLock) const
{
    std::vector<std::optional<TxHash>> ret;
    if (positionsInBlock.empty()) return ret; // unlikely fast path
    ret.reserve(positionsInBlock.size());
    BlkInfo bi;

    // Below is to implement optionally locking with: SharedLockGuard(p->blocksLock), if existingBlocksLock is nullptr
    SharedLockGuard maybeLockedByUs;
    if (existingBlocksLock == nullptr) {
        maybeLockedByUs = SharedLockGuard(p->blocksLock);
    } else if (UNLIKELY(existingBlocksLock->mutex() != &p->blocksLock)) {
        Error() << "Internal Error: expected the `existingBlocksLock` to be holding `p->blocksLock` (but it is not) in "
                << __func__ << ". FIXME!";
        return ret;
    }

    // At this point p->blocksLock is held for the rest of the function (either by caller or by us).
    // We need to hold p->blocksLock here to get a consistent view (so that data doesn't mutate from beneath us).

    {
        SharedLockGuard g(p->blkInfoLock);
        if (height >= p->blkInfos.size())
            return ret; // empty vector for bad height
        bi = p->blkInfos[height];
    }
    for (const uint32_t posInBlock : positionsInBlock) {
        if (posInBlock >= bi.nTx)
            ret.emplace_back(std::nullopt); // indicate this position is bad with a nullopt
        else {
            const TxNum txNum = bi.txNum0 + posInBlock;
            ret.push_back(hashForTxNum(txNum));
        }
    }

    return ret;
}


// NOTE: the returned vector has hashes in bitcoind memory order (little endian -- unlike every other function in this file!)
std::vector<TxHash> Storage::txHashesForBlockInBitcoindMemoryOrder(BlockHeight height) const
{
    std::vector<TxHash> ret;
    std::pair<TxNum, size_t> startCount{0,0};
    SharedLockGuard(p->blocksLock); // guarantee a consistent view (so that data doesn't mutate from underneath us)
    {
        // check cache
        auto opt = p->lruHeight2Hashes_BitcoindMemOrder.object(height);
        if (opt.has_value()) {
            // cache hit! return the cached item
            auto & vec = *opt;
            // convert from QVector to std::vector -- TODO: see if we can make the whole call path use QVector to avoid
            // these copies.
            ret.reserve(size_t(vec.size()));
            ret.insert(ret.end(), vec.begin(), vec.end()); // We do it this way because QVector::toStdVector() doesn't reserve() first :/
            ++p->lruCacheStats.height2HashesHits;
            return ret;
        }
    }
    ++p->lruCacheStats.height2HashesMisses;
    {
        SharedLockGuard g(p->blkInfoLock);
        if (height >= p->blkInfos.size())
            return ret;
        const BlkInfo & bi = p->blkInfos[height];
        startCount = { bi.txNum0, bi.nTx };
    }
    QString err;
    auto vec = p->db.txNumsDRA->readRecords(startCount.first, startCount.second, &err);
    if (vec.size() != startCount.second || !err.isEmpty()) {
        Warning() << "Failed to read " << startCount.second << " txNums for height " << height << ". " << err;
        return ret;
    }
    Util::reverseEachItem(vec); // reverse each hash to make them all be in bitcoind memory order.
    ret.swap(vec);
    {
        // put result in cache
        p->lruHeight2Hashes_BitcoindMemOrder.insert(height,
#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
                                                    QVector<TxHash>::fromStdVector(ret),
#else
                                                    Util::toVec<QVector<TxHash>>(ret),
#endif
                                                    p->lruHeight2HashSizeCalc(ret.size()));
    }
    return ret;
}

/// Returns a lambda that can be called to increment the counter. If the counter exceeds maxHistory, lambda will throw.
/// Used below in getHistory(), listUnspent(), getBalance()
static auto GetMaxHistoryCtrFunc(const QString &name, const QString &itemName, size_t maxHistory)
{
    return [name, itemName, maxHistory, ctr = size_t{0u}](size_t incr = 1u) mutable {
        if (UNLIKELY((ctr += incr) > maxHistory)) {
            throw HistoryTooLarge(QString("%1 for %2 exceeds max history %3 with %4 items!")
                                  .arg(name, itemName).arg(maxHistory).arg(ctr));
        }
    };
}

auto Storage::getHistory(const HashX & hashX, bool conf, bool unconf, BlockHeight fromHeight,
                         std::optional<BlockHeight> optToHeight) const -> History
{
    History ret;
    if (hashX.length() != HashLen)
        return ret;
    auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("History", QString("scripthash %1").arg(QString(hashX.toHex())),
                                                                        options->maxHistory);
    try {
        SharedLockGuard g(p->blocksLock);  // makes sure history doesn't mutate from underneath our feet
        if (conf) {
            static const QString err("Error retrieving history for a script hash");
            auto nums_opt = GenericDBGet<TxNumVec>(p->db, p->db.shist, hashX, true, err, false, p->db.defReadOpts);
            if (nums_opt.has_value()) {
                const auto & nums = *nums_opt;
                IncrementCtrAndThrowIfExceedsMaxHistory(nums.size());
                ret.reserve(nums.size());
                // TODO: The below could use some optimization.  A batched version of both hashForTxNum and
                // heightForTxNum are low-hanging fruit for optimization.  Each call to the below takes a shared lock
                // then releases it, for each item.  I imagine batched versions would have significantly less overhead
                // per item, which could add up to huge performance savings on large histories.  This is a very
                // low hanging fruit for optimization -- thus I am leaving this comment here so I can remember to come
                // back and optmize the below.  /TODO
                for (auto num : nums) {
                    const BlockHeight height = heightForTxNum(num).value(); // may throw, same deal

                    // Assumption for this loop: the nums are in order!
                    if (optToHeight && height >= *optToHeight) break; // threshold of "to height" reached
                    else if (height < fromHeight) continue; // keep looping until we hit a height that at least "from height"

                    const auto hash = hashForTxNum(num).value(); // may throw, but that indicates some database inconsistency. we catch below
                    ret.emplace_back(/* HistoryItem: */ hash, int(height));
                }
            }
        }
        if (unconf) {
            auto [mempool, lock] = this->mempool();
            if (auto it = mempool.hashXTxs.find(hashX); it != mempool.hashXTxs.end()) {
                const auto & txvec = it->second;
                IncrementCtrAndThrowIfExceedsMaxHistory(txvec.size());
                ret.reserve(ret.size() + txvec.size());
                for (const auto & tx : txvec)
                    ret.emplace_back(/* HistoryItem: */ tx->hash, tx->hasUnconfirmedParents() ? -1 : 0, tx->fee);
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

auto Storage::getRpaHistory(const Rpa::Prefix &prefix, bool includeConfirmed, bool includeMempool,
                            BlockHeight fromHeight, std::optional<BlockHeight> endHeight) const-> History
{
    History ret;
    auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("RPA History", QString("prefix '%1'").arg(QString(prefix.toHex())),
                                                                        options->rpa.maxHistory);
    double tReadDb = 0., tPfxSearch = 0., tResolveTxIdx = 0., tWaitForLock = 0., tBuildRes = 0.;

    Tic t0;
    SharedLockGuard g(p->blocksLock);  // makes sure history doesn't mutate from underneath our feet
    tWaitForLock += t0.msec<double>();

    const int rpaStartHeight = getConfiguredRpaStartHeight();
    if (UNLIKELY(rpaStartHeight < 0)) {
        // This should have been caught by the caller. Warn to log here since we don't want to do this filtering of
        // requests here in this asynch-called function since it wastes resources to do it this late in the pipeline.
        Warning() << "getRpaHistory() called but RPA appears to be disabled. FIXME!";
        throw InternalError("RPA is disabled");
    }

    const auto tipHeight = latestHeight();
    if (UNLIKELY( ! tipHeight)) throw InternalError("No blockchain");
    if (unsigned(rpaStartHeight) > *tipHeight) {
        // Nothing to do! Index not yet enabled! Warn here since likely the admin has misconfigured his server.
        Warning() << "getRpaHistory called but rpa_start_height is " << rpaStartHeight << ", which is greater than the"
                  << " block chain height of " << *tipHeight << ".\n\nIf you wish to enable RPA indexing, set the RPA"
                  << " start height to below the blockchain height using the `rpa_start_height` configuration"
                  << " variable. If, on the other hand, you wish to disable RPA indexing, set `rpa = false` in the"
                  << " configuration file.\n\n";
        return ret;
    }

    try {
        if (includeConfirmed) {
            // sanitize `fromHeight` and `endHeight`; restrict to range: [rpaStartHeight, tipHeight + 1)
            fromHeight = std::max<unsigned>(rpaStartHeight, fromHeight); // restrict `from` to be >= configured height
            endHeight = std::min(endHeight.value_or(*tipHeight + 1u), *tipHeight + 1u); // define and restrict `end` to be <= tip height + 1

            // We use an iterator and seek forward each time because this is far faster since our table rows are in order
            // of height (serialized as big endian). Note that the assumption here is that the rpa table contains
            // *only* records of the form: Key = 4-byte big endian height, Value = serialized Rpa::PrefixTable.
            // If this assumption changes, update this code to not use this assumption as an optimization.
            std::unique_ptr<rocksdb::Iterator> iter{p->db->NewIterator(p->db.defReadOpts, p->db.rpa)};
            if (UNLIKELY(!iter)) throw DatabaseError("Unable to obtain an iterator to the rpa db");

            BlockHeight height = fromHeight;
            size_t blockScansRemaining = std::max(options->rpa.historyBlockLimit, 1u); // use configured limit (default: 60)
            for ( /* */; blockScansRemaining && height < *endHeight; ++height, --blockScansRemaining) {
                Tic t1;
                const RpaDBKey dbKey(height);
                if (height == fromHeight)
                    iter->Seek(ToSlice(dbKey));
                else
                    iter->Next(); // bump iterator one item... this is the secret sauce to make this fast.
                bool ok{};
                rocksdb::Slice valueSlice; // NB: slice is invalidated when iter is modified
                if (!iter->Valid() || RpaDBKey::fromBytes(FromSlice(iter->key()), &ok, true) != dbKey || !ok
                        || (valueSlice = iter->value()).size() < kRpaShortBlockHashLen) [[unlikely]] {
                    // This should never happen -- error to console just in case we have bugs and/or missing data.
                    Error() << "Missing or malformed RPA PrefixTable for height: " << height << "."
                            << " This should never happen. Report this to situation to the developers.";
                    break;
                }
                // skip the first kRpaShortBlockHashLen bytes of `valueSlice` to get to the compressed serialized data
                valueSlice.remove_prefix(kRpaShortBlockHashLen);
                // Note: This read-only Rpa::PrefixTable is "lazy loaded" and populated only for records we access on-demand
                const auto prefixTable = Deserialize<Rpa::PrefixTable>(FromSlice(valueSlice)); // Throws on failure to deserialize.
                tReadDb += t1.msec<double>();
                // Update RpaInfo stats
                p->rpaInfo.nReads.fetch_add(1, std::memory_order_relaxed);
                p->rpaInfo.nBytesRead.fetch_add(sizeof(uint32_t) + valueSlice.size(), std::memory_order_relaxed);

                t1 = Tic();
                const bool needSort = prefix.range().size() > 1u; // if prefix spans multiple rows of table, sort and uniqueify
                auto txIdxVec = prefixTable.searchPrefix(prefix, needSort);
                tPfxSearch += t1.msec<double>();
                if (txIdxVec.empty()) continue; // no match for this prefix at this height, keep going

                IncrementCtrAndThrowIfExceedsMaxHistory(txIdxVec.size());

                t1 = Tic();
                const auto vecOfOptHashes = hashesForHeightAndPosVec(height, txIdxVec, &g /* <-- tell callee not to re-lock blocksLock */);
                tResolveTxIdx += t1.msec<double>();
                t1 = Tic();
                for (const auto & optHash : vecOfOptHashes) {
                    if (LIKELY(optHash)) ret.emplace_back(*optHash, int(height));
                }
                tBuildRes += t1.msec<double>();
            }

            // Special behavior: disable mempool append if we didn't reach past tipHeight
            if (includeMempool && height <= *tipHeight)
                includeMempool = false;
        }
        if (includeMempool) {
            auto [mempool, lock] = this->mempool();
            if (LIKELY(mempool.optPrefixTable)) {
                const auto origSize = ret.size();
                const bool needSort = prefix.range().size() > 1u; // if prefix spans multiple rows of mempool table, sort and uniqueify
                Tic t1;
                const auto txHashes = mempool.optPrefixTable->searchPrefix(prefix, needSort /* to get unique hashes */);
                tPfxSearch += t1.msec<double>();

                IncrementCtrAndThrowIfExceedsMaxHistory(txHashes.size());

                t1 = Tic();
                for (const auto & txHash : txHashes) {
                    if (auto it = mempool.txs.find(txHash); LIKELY(it != mempool.txs.end())) {
                        const int height = it->second->hasUnconfirmedParents() ? -1 : 0;
                        ret.emplace_back(txHash, height, it->second->fee);
                    } else {
                        Error() << "Tx: " << Util::ToHexFast(txHash) << " for prefix '" << prefix.toHex() << "'"
                                << " exists in Mempool prefix table but not in Mempool txs! FIXME!";
                    }
                }
                // force unconf parent to sort after conf parent txns
                std::sort(ret.begin() + origSize, ret.end(), [](const HistoryItem &a, const HistoryItem &b){
                    int ha = std::max(a.height, -1), hb = std::max(b.height, -1);
                    if (ha <= 0) ha = 0x7f'ff'ff'fe - ha;  // -1 becomes -> 0x7f'ff'ff'ff, 0 becomes -> 0x7f'ff'ff'fe
                    if (hb <= 0) hb = 0x7f'ff'ff'fe - hb;
                    return std::tie(ha, a.hash) < std::tie(hb, b.hash);
                });
                // uniqueify
                auto last = std::unique(ret.begin() + origSize, ret.end());
                ret.erase(last, ret.end());
                tBuildRes += t1.msec<double>();
            } else {
                // This should never happen for mempool.
                Warning() << "Missing RPA PrefixTable for mempool. This should never happen. Contact the developers to report this.";
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    Debug() << "getRpaHistory returned " << ret.size() << " items"
            << ", readDb: " << QString::number(tReadDb, 'f', 3) << " msec"
            << ", pfxSearch: " << QString::number(tPfxSearch, 'f', 3) << " msec"
            << ", resolveTxIdx: " << QString::number(tResolveTxIdx, 'f', 3) << " msec"
            << ", waitForLock: " << QString::number(tWaitForLock, 'f', 3) << " msec"
            << ", buildResults: " << QString::number(tBuildRes, 'f', 3) << " msec"
            << ", total: " << t0.msecStr() << " msec";
    return ret;
}

static bool ShouldTokenFilter(const Storage::TokenFilterOption tokenFilter, const bitcoin::token::OutputDataPtr & p)
{
    switch (tokenFilter) {
    case Storage::TokenFilterOption::ExcludeTokens:
        return bool(p);
    case Storage::TokenFilterOption::IncludeTokens:
        return false;
    case Storage::TokenFilterOption::OnlyTokens:
        return !p;
    }
    // not normally reached unless there's a programming error of some sort
    throw InternalError(QString("Invalid TokenFilterOption encountered: %1. This shouldn't happen! FIXME!")
                        .arg(int(tokenFilter)));
}

auto Storage::listUnspent(const HashX & hashX, const TokenFilterOption tokenFilter) const -> UnspentItems
{
    UnspentItems ret;
    if (hashX.length() != HashLen)
        return ret;
    try {
        auto ShouldFilter = [tokenFilter](const bitcoin::token::OutputDataPtr & p) { return ShouldTokenFilter(tokenFilter, p); };
        auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("Unspent UTXOs",
                                                                            QString("scripthash %1").arg(QString(hashX.toHex())),
                                                                            options->maxHistory);
        constexpr size_t iota = 10; // we initially reserve this many items in the returned array in order to prevent redundant allocations in the common case.
        std::unordered_set<TXO> mempoolConfirmedSpends;
        mempoolConfirmedSpends.reserve(iota);
        ret.reserve(iota);
        {
            // take shared lock (ensure history doesn't mutate from underneath our feet)
            SharedLockGuard g(p->blocksLock);
            const TxNum veryHighTxNum = getTxNum() + 100000000;  // pick an absurdly high TxNum that is 100 million past current. This is a fudge so sorting works ok for unconfirmed tx's so that they appear at the end.
            {
                // grab mempool utxos for scripthash -- we do mempool first so as to build the "mempoolConfirmedSpends" set as we iterate.
                auto [mempool, lock] = this->mempool(); // shared lock
                if (auto it = mempool.hashXTxs.find(hashX); it != mempool.hashXTxs.end()) {
                    const auto & txvec = it->second;
                    for (const auto & tx : txvec) {
                        if (!tx) {
                            // defensive programming. should never happen
                            Warning() << "Cannot find tx for sh " << hashX.toHex() << ". FIXME!!";
                            continue;
                        }
                        if (auto it2 = tx->hashXs.find(hashX); LIKELY(it2 != tx->hashXs.end())) {
                            const auto & ioinfo = it2->second;
                            // make sure to put any confirmed spends we see now in the "mempool confirmed spends" set
                            // so we know not to include them in the list of utxos from the DB later in this function!
                            for (const auto & [txo, txoinfo] : ioinfo.confirmedSpends) {
                                mempoolConfirmedSpends.insert(txo);
                            }

                            // throw if we would iterate too much below
                            IncrementCtrAndThrowIfExceedsMaxHistory(ioinfo.utxo.size());

                            for (const auto ionum : ioinfo.utxo) {
                                if (decltype(tx->txos.cbegin()) it3;
                                        LIKELY( ionum < tx->txos.size() && (it3 = tx->txos.cbegin() + ionum)->isValid() ))
                                {
                                    if (ShouldFilter(it3->tokenDataPtr))
                                        continue;
                                    ret.push_back(UnspentItem{
                                        { tx->hash, 0 /* always put 0 for height here */, tx->fee }, // base HistoryItem
                                        ionum, // .tx_pos
                                        it3->amount,  // .value
                                        TxNum(1) + veryHighTxNum + TxNum(tx->hasUnconfirmedParents() ? 1 : 0), // .txNum (this is fudged for sorting at the end properly)
                                        it3->tokenDataPtr, // .token_data
                                    });
                                } else {
                                    // this should never happen!
                                    Warning() << "Cannot find txo " << ionum << " for sh " << hashX.toHex() << " in tx " << tx->hash.toHex();
                                    continue;
                                }
                            }
                        } else {
                            // defensive programming. should never happen
                            Warning() << "Cannot find scripthash " << hashX.toHex() << " in tx 'hashX -> IOInfo' map for tx " << tx->hash.toHex() << ". FIXME!";
                        }
                    }
                }
            } // release mempool lock
            { // begin confirmed/db search
                std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.shunspent));
                if (UNLIKELY(!iter)) throw DatabaseError("Unable to obtain an iterator to the shunspent db"); // should never happen
                const rocksdb::Slice prefix = ToSlice(hashX); // points to data in hashX

                // Search table for all keys that start with hashx's bytes. Note: the loop end-condition is strange.
                // See: https://github.com/facebook/rocksdb/wiki/Prefix-Seek-API-Changes#transition-to-the-new-usage
                rocksdb::Slice key;
                using CTXOVec = std::vector<std::pair<CompactTXO, SHUnspentValue>>;
                CTXOVec ctxoVec;
                constexpr size_t reserveBytes = 256u;
                static_assert(sizeof(CTXOVec::value_type) < reserveBytes);
                ctxoVec.reserve(reserveBytes / sizeof(CTXOVec::value_type)); // rough guess -- pre-allocate ~256 bytes
                // we do it this way as two separate loops in order to avoid the expensive heightForTxNum lookups below in
                // the case where the history is huge.
                for (iter->Seek(prefix); iter->Valid() && (key = iter->key()).starts_with(prefix); iter->Next()) {
                    IncrementCtrAndThrowIfExceedsMaxHistory();
                    bool ok;
                    auto shval = Deserialize<SHUnspentValue>(FromSlice(iter->value()), &ok);
                    if (UNLIKELY(!ok || !shval.valid)) {
                        auto ctxo = extractCompactTXOFromShunspentKey(key, false); /* may throw if size is bad, etc */
                        throw InternalError(QString("Bad SHUnspentValue in db for ctxo %1, script_hash: %2")
                                            .arg(ctxo.toString(), QString(hashX.toHex())));
                    }
                    if (UNLIKELY(!bitcoin::MoneyRange(shval.amount))) {
                        auto ctxo = extractCompactTXOFromShunspentKey(key, false); /* may throw if size is bad, etc */
                        throw InternalError(QString("Out-of-range amount in db for ctxo %1, script_hash %2: %3")
                                            .arg(ctxo.toString(), QString(hashX.toHex())).arg(shval.amount / shval.amount.satoshi()));
                    }
                    if (ShouldFilter(shval.tokenDataPtr))
                        continue;
                    auto ctxo = extractCompactTXOFromShunspentKey(key, false); /* may throw if size is bad, etc */
                    ctxoVec.emplace_back(std::move(ctxo), std::move(shval));
                }
                for (auto & [ctxo, shval] : ctxoVec) {
                    const auto hash = hashForTxNum(ctxo.txNum()).value(); // may throw, but that indicates some database inconsistency. we catch below
                    const auto height = heightForTxNum(ctxo.txNum()).value(); // may throw, same deal
                    const TXO txo{ hash, ctxo.N() };
                    if (mempoolConfirmedSpends.count(txo))
                        // Skip items that are spent in mempool. This fixes a bug in Fulcrum 1.0.2 or earlier where the
                        // confirmed spends in the mempool were still appearing in the listunspent utxos.
                        continue;
                    ret.push_back(UnspentItem{
                        { hash, int(height), {} }, // base HistoryItem
                        txo.outN, // .tx_pos
                        shval.amount, // .value
                        ctxo.txNum(), // .txNum
                        std::move(shval.tokenDataPtr), // .token_data
                    });
                }
            } // end confirmed/db search
        } // release blocks lock
        std::sort(ret.begin(), ret.end());
        if (const auto sz = ret.size(), cap = ret.capacity(); cap - sz > iota && sz > 0 && double(cap)/double(sz) > 1.20)
            // we only do this if we're wasting enough space (at least iota, and at least 20% space wasted),
            // otherwise we don't bother since this returned object is fairly ephemeral and for smallish disparities
            // between capacity and size, it's fine.
            ret.shrink_to_fit();
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

auto Storage::getBalance(const HashX &hashX, TokenFilterOption tokenFilter) const -> std::pair<bitcoin::Amount, bitcoin::Amount>
{
    std::pair<bitcoin::Amount, bitcoin::Amount> ret;
    if (hashX.length() != HashLen)
        return ret;
    auto ShouldFilter = [tokenFilter](const bitcoin::token::OutputDataPtr & p) { return ShouldTokenFilter(tokenFilter, p); };
    auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("GetBalance UTXOs",
                                                                        QString("scripthash %1").arg(QString(hashX.toHex())),
                                                                        options->maxHistory);
    try {
        // take shared lock (ensure history doesn't mutate from underneath our feet)
        SharedLockGuard g(p->blocksLock);
        {
            // confirmed -- read from db using an iterator
            std::unique_ptr<rocksdb::Iterator> iter(p->db->NewIterator(p->db.defReadOpts, p->db.shunspent));
            if (UNLIKELY(!iter)) throw DatabaseError("Unable to obtain an iterator to the shunspent db"); // should never happen
            const rocksdb::Slice prefix = ToSlice(hashX); // points to data in hashX

            // Search table for all keys that start with hashx's bytes. Note: the loop end-condition is strange.
            // See: https://github.com/facebook/rocksdb/wiki/Prefix-Seek-API-Changes#transition-to-the-new-usage
            rocksdb::Slice key;
            for (iter->Seek(prefix); iter->Valid() && (key = iter->key()).starts_with(prefix); iter->Next()) {
                IncrementCtrAndThrowIfExceedsMaxHistory(); // throw if we are iterating too much
                const CompactTXO ctxo = extractCompactTXOFromShunspentKey(key, false); // may throw if key has the wrong size, etc
                bool ok;
                const auto & [valid, amount, tokenDataPtr] = Deserialize<SHUnspentValue>(FromSlice(iter->value()), &ok);
                if (UNLIKELY(!ok || !valid))
                    throw InternalError(QString("Bad SHUnspentValue in db for ctxo %1 (%2)").arg(ctxo.toString(), QString(hashX.toHex())));
                if (UNLIKELY(!bitcoin::MoneyRange(amount)))
                    throw InternalError(QString("Out-of-range amount in db for ctxo %1: %2").arg(ctxo.toString()).arg(amount / amount.satoshi()));
                if ( ! ShouldFilter(tokenDataPtr)) {
                    ret.first += amount; // tally the result
                }
            }
            if (UNLIKELY(!bitcoin::MoneyRange(ret.first))) {
                ret.first = bitcoin::Amount::zero();
                throw InternalError(QString("Out-of-range total in db for getBalance on scripthash: %1").arg(QString(hashX.toHex())));
            }
        }
        {
            // unconfirmed -- check mempool
            auto [mempool, lock] = this->mempool(); // shared (read only) lock is held until scope end
            if (auto it = mempool.hashXTxs.find(hashX); it != mempool.hashXTxs.end()) {
                // for all tx's involving scripthash
                bitcoin::Amount utxos, spends;
                for (const auto & tx : it->second) {
                    assert(bool(tx));
                    auto it2 = tx->hashXs.find(hashX);
                    if (UNLIKELY(it2 == tx->hashXs.end())) {
                        throw InternalError(QString("scripthash %1 lists tx %2, which then lacks the IOInfo for said hashX! FIXME!")
                                            .arg(QString(hashX.toHex()), QString(tx->hash.toHex())));
                    }
                    auto & info = it2->second;
                    IncrementCtrAndThrowIfExceedsMaxHistory(info.confirmedSpends.size() + info.utxo.size()); // throw if >maxHistory
                    for (const auto & [txo, txoinfo] : info.confirmedSpends) {
                        if ( ! ShouldFilter(txoinfo.tokenDataPtr))
                            spends += txoinfo.amount;
                    }
                    for (const auto ionum : info.utxo) {
                        if (decltype(tx->txos.cbegin()) it3; UNLIKELY( ionum >= tx->txos.size()
                                                                       || !(it3 = tx->txos.cbegin() + ionum)->isValid()) )
                        {
                            throw InternalError(QString("scripthash %1 lists tx %2, which then lacks a valid TXO IONum %3 for said hashX! FIXME!")
                                                .arg(QString(hashX.toHex()), QString(tx->hash.toHex())).arg(ionum));
                        } else if ( ! ShouldFilter(it3->tokenDataPtr)) {
                            utxos += it3->amount;
                        }
                    }
                }
                ret.second = utxos - spends; // note this may not be MoneyRange (may be negative), which is ok.
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return ret;
}

auto Storage::getFirstUse(const HashX & hashX) const -> std::optional<FirstUse>
{
    static const QString err("Database error retrieving history for a script hash");
    try {
        SharedLockGuard g(p->blocksLock);  // makes sure history doesn't mutate from underneath our feet

        // try confirmed txns from db
        if (const auto optba = GenericDBGet<QByteArray>(p->db, p->db.shist, hashX, true, err, true, p->db.defReadOpts)) {
            // the history is a bunch of CompactTXO TxNums concatenated, grab the first one
            if (size_t(optba->size()) < CompactTXO::compactTxNumSize()) {
                throw DatabaseSerializationError(QString("Scripthash %1 has a db entry in scripthash_history that is too short: %2")
                                                     .arg(QString::fromLatin1(hashX.toHex()), QString::fromLatin1(optba->toHex())));
            }
            const TxNum txNum = CompactTXO::txNumFromCompactBytes(reinterpret_cast<const std::byte *>(optba->constData()), /*bigEndian:*/false);
            // NB: Below opt.value() calls may throw, which is what we want.
            const BlockHeight blockHeight = heightForTxNum(txNum).value(); // may throw
            return FirstUse(hashForTxNum(txNum).value(), /* .txHash */
                            blockHeight, /* .height */
                            BTC::HashRev(headerForHeight(blockHeight).value()) /* .blockHash */);
        } else {
            // try unconfirmed (mempool)
            auto [mempool, lock] = this->mempool();
            if (auto it = mempool.hashXTxs.find(hashX); it != mempool.hashXTxs.end()) {
                for (const auto & tx : it->second) { // Note: txs are sorted by (hasUnfonfirmedParentTx, hash)
                    for (const auto & txoinfo : tx->txos) {
                        if (txoinfo.hashX == hashX) {
                            // found a mempool tx that sends an output to `hashX`
                            static const QByteArray zeroes32(QByteArray::size_type(HashLen), char(0));
                            return FirstUse(tx->hash, tx->hasUnconfirmedParents() ? -1 : 0, zeroes32);
                        }
                    }
                }
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
    return std::nullopt;
}

std::vector<QByteArray> Storage::merkleCacheHelperFunc(unsigned int start, unsigned int count, QString *err)
{
    auto vec = headersFromHeight_nolock_nocheck(start, count, err); // despite the name of this function, it does take a small lock internally and is thread-safe. we cannot use the public one as that would potentially cause a deadlock here
    for (auto & ba : vec)
        ba = BTC::Hash(ba);
    return vec;
}

void Storage::updateMerkleCache(unsigned int height)
{
    if (!p->merkleCache->isInitialized() && height) {
        try {
            p->merkleCache->initialize(height+1); // this may take a few seconds
        } catch (const std::exception & e) {
            Error() << e.what();
        }
    }
}

Merkle::BranchAndRootPair Storage::headerBranchAndRoot(unsigned height, unsigned cp_height)
{
    // TODO: there is a potential, non-fatal race condition here where the caller tried to verify that cp_height is
    // above chainTip height, but it's possible for a reorg to happen and for that to no longer be valid by the time
    // the call path gets to this point.  That's fine -- an exception will be thrown. This is only ever called by
    // code that catches exceptions.
    assert(p->merkleCache);
    return p->merkleCache->branchAndRoot(cp_height+1, height);
}

auto Storage::genesisHash() const -> HeaderHash
{
    SharedLockGuard g(p->headerVerifierLock);
    return p->genesisHash;
}

// HistoryItem & UnspentItem -- operator< and operator== -- for sort.
bool Storage::HistoryItem::operator<(const HistoryItem &o) const noexcept {
    return std::tie(height, hash) < std::tie(o.height, o.hash);
}
bool Storage::HistoryItem::operator==(const HistoryItem &o) const noexcept {
    return std::tie(height, hash) == std::tie(o.height, o.hash);
}
bool Storage::UnspentItem::operator<(const UnspentItem &o) const noexcept {
    return    std::tie(  txNum,   tx_pos,   value,   tokenDataPtr,   height,   hash)
            < std::tie(o.txNum, o.tx_pos, o.value, o.tokenDataPtr, o.height, o.hash);
}
bool Storage::UnspentItem::operator==(const UnspentItem &o) const noexcept {
    return    std::tie(  txNum,   tx_pos,   value,   tokenDataPtr,   height,   hash)
           == std::tie(o.txNum, o.tx_pos, o.value, o.tokenDataPtr, o.height, o.hash);
}

auto Storage::mempool() const -> std::pair<const Mempool &, SharedLockGuard>
{
    return {p->mempool, SharedLockGuard{p->mempoolLock}};
}
auto Storage::mutableMempool() -> std::pair<Mempool &, ExclusiveLockGuard>
{
    return {p->mempool, ExclusiveLockGuard{p->mempoolLock}};
}

bool Storage::isMaybeRecentlySeenTx(const TxHash &txhash) const
{
    if (mempool().first.txs.contains(txhash)) return true;
    SharedLockGuard g{p->blocksLock};
    return p->recentBlockTxHashes.contains(txhash);
}

void Storage::refreshMempoolHistogram()
{
    Tic t0;
    Mempool::FeeHistogramVec hist;
    // shared lock
    {
        auto [mempool, lock] = this->mempool();
        hist = mempool.calcCompactFeeHistogram();
    }
    // lock exclusively to do the final swap
    {
        ExclusiveLockGuard g(p->mempoolLock);
        p->mempoolFeeHistogram.swap(hist);
    }
    if (t0.msec() >= 10) DebugM("Storage::refreshMempoolHistogram took ", t0.msecStr(), " msec");
}

auto Storage::mempoolHistogram() const -> Mempool::FeeHistogramVec
{
    SharedLockGuard g(p->mempoolLock);
    return p->mempoolFeeHistogram;
}


auto Storage::getTxHeights(const std::vector<TxHash> &txHashes) const -> TxHeightsResult
{
    TxHeightsResult ret;
    ret.reserve(txHashes.size());

    SharedLockGuard g(p->blocksLock);
    auto txNums = p->db.txhash2txnumMgr->findMany(txHashes);
    if (UNLIKELY(txNums.size() != txHashes.size()))
        // this should never happen
        throw InternalError("findMany() returned an unexpected number of elements! FIXME!");

    // missing txNums need a mempool check; check in mempool
    {
        auto [mempool, lock] =  this->mempool(); // mempool lock is ok to take with blocksLock held
        for (size_t i = 0; i < txHashes.size(); ++i) {
            if (!txNums[i] && mempool.txs.count(txHashes[i]))
                txNums[i] = 0; // 0 = mempool tx
        }
    }

    // next, transform all non-0 valid txNums to a height (below takes blkInfoLock which is ok to take after blocksLock)
    SharedLockGuard g2(p->blkInfoLock);
    for (const auto & txNum : txNums) {
        ret.emplace_back();
        auto &optHeight = ret.back();
        if (txNum)
            optHeight = *txNum ? heightForTxNum_nolock(*txNum) : 0; // transform to txNum -> height .. note that 0 already indicates mempool
    }
    return ret;
}

auto Storage::getTxHeight(const TxHash &h) const -> std::optional<BlockHeight>
{
    // We could have just called the above function but the below is a bit faster since it calls TxHash2TxNumMgr::find()
    // rather than findMany(), which is slightly faster.
    std::optional<BlockHeight> ret;
    SharedLockGuard g(p->blocksLock);
    const auto optTxNum = p->db.txhash2txnumMgr->find(h);
    if (optTxNum) {
        // resolve txNum -> height; this ends up taking blkInfoLock (shared mode)
        ret = heightForTxNum(*optTxNum);
    } else {
        // check mempool, this ends up taking the mempool lock (shared mode)
        if (mempool().first.txs.count(h)) // lock held until statement end
            ret = 0; // 0 = mempool tx
    }
    return ret;
}

auto Storage::getConfirmedTxBlockHeightAndHeader(const TxHash &h) const -> std::optional<std::pair<BlockHeight, Header>>
{
    std::optional<std::pair<BlockHeight, Header>> ret;
    SharedLockGuard g(p->blocksLock); // Take the blocksLock to make this operation atomic and guaranteed consistent
    if (const auto optTxNum = p->db.txhash2txnumMgr->find(h))
        // resolve txNum -> height; this ends up taking blkInfoLock (shared mode)
        if (const auto optHeight = heightForTxNum(*optTxNum))
            // resolve blockHeight -> blockHeader; this ends up taking headerVerifierLock (shared mode)
            if (const auto optHeader = headerForHeight(*optHeight))
                ret.emplace(*optHeight, *optHeader);
    return ret;
}

size_t Storage::dumpAllScriptHashes(QIODevice *outDev, unsigned int indent, unsigned int ilvl,
                                    const DumpProgressFunc &progFunc, size_t progInterval) const
{
    if (!outDev || !outDev->isWritable())
        return 0;
    SharedLockGuard g{p->blocksLock};
    std::unique_ptr<rocksdb::Iterator> it {p->db->NewIterator(p->db.defReadOpts, p->db.shist)};
    if (!it) return 0;

    const auto INDENT = [outDev, &ilvl, spaces = QByteArray(int(indent), ' ')] {
        for (size_t i = 0; i < ilvl; ++i)
            outDev->write(spaces);
    };
    const Util::VoidFunc NL = indent ? Util::VoidFunc([outDev, &INDENT] {
        outDev->putChar('\n');
        INDENT();
    }) : Util::VoidFunc([]{});
    size_t ctr = 0;
    progInterval = std::max(size_t(1), progInterval);

    if (indent) INDENT();
    outDev->putChar('[');
    ++ilvl;
    NL();
    if (progFunc) progFunc(0); // 0 = indicate operator began
    qint64 lastWriteCt = 0;
    for (it->SeekToFirst(); it->Valid() && outDev && lastWriteCt > -1; it->Next()) {
        const auto sh = it->key();
        if (sh.size() == HashLen) {
            if (LIKELY(ctr)) {
                outDev->putChar(',');
                NL();
            }
            outDev->putChar('"');
            lastWriteCt = outDev->write(Util::ToHexFast(FromSlice(sh)));
            outDev->putChar('"');
            if (UNLIKELY(!(++ctr % progInterval) && progFunc))
                progFunc(ctr);
        }
    }
    --ilvl;
    if (ctr) NL();
    outDev->putChar(']');

    if (progFunc && ctr % progInterval)
        progFunc(ctr); // always called for last item to indicate operation ended
    return ctr;
}

auto Storage::calcUTXOSetStats(const DumpProgressFunc & progFunc, size_t progInterval) const -> UTXOSetStats
{
    UTXOSetStats ret;
    if (!p->db.utxoset || !p->db.shunspent) return ret;
    auto readOpts = p->db.defReadOpts;
    const auto [ss, bheight, bhash] = [&] {
        SharedLockGuard g{p->blocksLock};
        using CSnapshot = const rocksdb::Snapshot;
        auto snap = std::shared_ptr<CSnapshot>(p->db->GetSnapshot(), [this](CSnapshot *ss){ p->db->ReleaseSnapshot(ss); });
        const auto & [height, hash] = latestTip(); // takes a subordinate lock to blocksLock
        return std::tuple(snap, height, hash);
    }();
    readOpts.snapshot = ss.get();
    std::unique_ptr<rocksdb::Iterator> it_utxo {p->db->NewIterator(readOpts, p->db.utxoset)};
    std::unique_ptr<rocksdb::Iterator> it_shu {p->db->NewIterator(readOpts, p->db.shunspent)};
    if (!it_utxo || !it_shu) return ret;

    ret.block_height = bheight >= 0 ? BlockHeight(bheight) : 0;
    ret.block_hash = bhash;

    // Handle app shutdown by aborting this operation asap if we get a quit signal
    std::atomic_bool quitting = false;
    QMetaObject::Connection conn;
    Defer d([&conn]{ if (conn && ::app()) { ::app()->disconnect(conn); conn = QMetaObject::Connection{}; } });
    if (auto *a = ::app())
        conn = a->connect(a, &App::requestQuit, this, [&quitting] { quitting = true; }, Qt::DirectConnection);

    auto UpdateProgress = [&, ctr = size_t{0u}]() mutable {
        if (progInterval && (++ctr % progInterval == 0u) && progFunc) progFunc(ctr);
        return !quitting;
    };
    {
        bitcoin::CHash256 hasher;
        for (it_utxo->SeekToFirst(); it_utxo->Valid(); it_utxo->Next()) {
            auto const k = it_utxo->key();
            auto const v = it_utxo->value();
            hasher.Write(reinterpret_cast<const uint8_t *>(k.data()), k.size());
            hasher.Write(reinterpret_cast<const uint8_t *>(v.data()), v.size());
            ++ret.utxo_db_ct;
            ret.utxo_db_size_bytes += k.size() + v.size();
            if (UNLIKELY(!UpdateProgress())) { ret = UTXOSetStats{}; return ret; }
        }
        ret.utxo_db_shasum.resize(HashLen);
        hasher.Finalize(reinterpret_cast<uint8_t *>(ret.utxo_db_shasum.data()));
    }

    {
        bitcoin::CHash256 hasher;
        for (it_shu->SeekToFirst(); it_shu->Valid(); it_shu->Next()) {
            auto const k = it_shu->key();
            auto const v = it_shu->value();
            hasher.Write(reinterpret_cast<const uint8_t *>(k.data()), k.size());
            hasher.Write(reinterpret_cast<const uint8_t *>(v.data()), v.size());
            ++ret.shunspent_db_ct;
            ret.shunspent_db_size_bytes += k.size() + v.size();
            if (UNLIKELY(!UpdateProgress())) { ret = UTXOSetStats{}; return ret; }
        }
        ret.shunspent_db_shasum.resize(HashLen);
        hasher.Finalize(reinterpret_cast<uint8_t *>(ret.shunspent_db_shasum.data()));
    }

    return ret;
}

namespace {
    // specializations of Serialize/Deserialize
    template <> QByteArray Serialize(const Meta &m)
    {
        QByteArray ba;
        {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            ds << m.magic << m.version << m.chain << m.platformBits << m.coin;
            if (m.isMinimumExtraPlatformInfoVersion()) {
                ds << m.appName << m.appVersion << m.rocksDBVersion << m.buildABI << m.osName << m.cpuArch;
            }
        }
        return ba;
    }
    template <bool legacy> Meta Deserialize_Meta(const QByteArray &ba, bool *ok_ptr)
    {
        bool dummy;
        bool &ok (ok_ptr ? *ok_ptr : dummy);
        ok = false;
        Meta m(Meta::ClearedForUnser);
        QDataStream ds(ba);
        if constexpr (legacy) {
            // Note that Fulcrum 1.x would serialize in host endian order here for magicBytes, as a QByteArray.
            // Ensure that is the case (we will detect endian mismatch later in the 1.x -> 2.x upgrade codepath).
            QByteArray magicBytes;
            ds >> magicBytes; // read magic as raw bytes.
            ok = ds.status() == QDataStream::Status::Ok;
            if (ok) {
                m.magic = DeserializeScalar<decltype (m.magic)>(magicBytes, &ok);
            }
        } else {
            // Fulcrum 2.x (non-legacy) serializes as default QDataStream byte order (which is big endian)
            ds >> m.magic;
            ok = ds.status() == QDataStream::Status::Ok;
        }
        if (!ok) return m;
        ds >> m.version >> m.chain;
        ok = ds.status() == QDataStream::Status::Ok;
        if (ok && !ds.atEnd()) {
            // TODO: make this field non-optional. For now we tolerate it missing since we added this field
            // later and we want to be able to still use our existing db's.
            ds >> m.platformBits;
        }
        ok = ds.status() == QDataStream::Status::Ok;
        if (ok) {
            if (!ds.atEnd()) {
                // Newer db's will always either have an empty string "", "BCH", or "BTC" here.
                // Read the db value now. Client code gets this value via Storage::getCoin().
                ds >> m.coin;

                // If version >= 3, and magic ok, and no errors, proceed to read the extra platform info
                // which is new in db's with version 3 or above.
                ok = ds.status() == QDataStream::Status::Ok;
                if (ok && m.isMagicOk() && m.isMinimumExtraPlatformInfoVersion()) {
                    ds >> m.appName >> m.appVersion >> m.rocksDBVersion >> m.buildABI >> m.osName >> m.cpuArch;
                }
            } else {
                // Older db's pre-1.3.0 lacked this field -- but now we interpret missing data here as
                // "BCH" (since all older db's were always BCH only).
                m.coin = BTC::coinToName(BTC::Coin::BCH);
                Debug() << "Missing coin info from Meta table, defaulting coin to: \"" << m.coin << "\"";
            }
        }
        ok = ds.status() == QDataStream::Status::Ok;
        return m;
    }

    template <> Meta Deserialize(const QByteArray &ba, bool *ok_ptr) { return Deserialize_Meta<false>(ba, ok_ptr); }

    template <> MetaLegacy Deserialize(const QByteArray &ba, bool *ok_ptr) { return Deserialize_Meta<true>(ba, ok_ptr); }


    template <> QByteArray Serialize(const TXO &txo) { return txo.toBytes(false); }
    template <> TXO Deserialize(const QByteArray &ba, bool *ok) {
        TXO ret = TXO::fromBytes(ba); // requires 34 or 35 byte size
        if (ok) *ok = ret.isValid();
        return ret;
    }

    template <> QByteArray Serialize(const TXOInfo &inf) { return inf.toBytes(); }
    template <> TXOInfo Deserialize(const QByteArray &ba, bool *ok)
    {
        TXOInfo ret = TXOInfo::fromBytes(ba); // will fail if extra bytes at the end
        if (ok) *ok = ret.isValid();
        return ret;
    }

    template <> Rpa::PrefixTable Deserialize(const QByteArray &ba, bool *ok) {
        Rpa::PrefixTable ret(ba); // Note: PrefixTable does not keep a copy of `ba`, so it's ok if `ba` is a view into a temporary Slice
        if (ok) *ok = true;
        return ret;
    }

    // essentially takes a byte copy of the data of BlkInfo; note that we waste some space at the end for legacy compat.
    // New in Fulcrum 2.x: we enforce endian-neutrality (little endian ints, etc)
    QByteArray BlkInfo::toBytes(QByteArray *bufAppend) const {
        static_assert(sizeof(BlkInfo) == 16 && sizeof(txNum0) == 8 && sizeof(nTx) == 4,
                      "Serialization of BlkInfo assumes 64-bit txNum0 and 32-bit nTx members");
        // This used to be written as a raw struct (not endian safe). Now we do it this way as little endian to
        // be backward compatible with little endian platforms that did it the old way in Fulcrum 1.x.
        // NOTE: Be sure to maintain the order of these fields for the struct else you will need to write update
        // code.
        QByteArray tmp;
        QByteArray &buf = bufAppend ? *bufAppend : tmp;
        if (!bufAppend) buf.reserve(sizeof(BlkInfo));
        const auto origSize [[maybe_unused]] = buf.size();
        buf.append(SerializeScalarEphemeral</*bigEndian=*/false>(txNum0));
        buf.append(SerializeScalarEphemeral</*bigEndian=*/false>(nTx));
        // The end is padded with 4 bytes because in previous versions of this code we wrote the raw
        // BlkInfo struct to the byte array (which had padding for alignment). We don't do this anymore
        // for privacy/security reasons, but we emulate the old behavior and pad with zeroes at the end.
        buf.append(QByteArray::size_type(4), char{0});
        assert(buf.size() - origSize == 16);
        return buf;
    }

    // will fail if the size doesn't match size of BlkInfo exactly
    template <> BlkInfo Deserialize(const QByteArray &ba, bool *ok_) {
        BlkInfo ret;
        bool tmp;
        bool & ok = ok_ ? *ok_ : tmp;
        if (ba.length() != sizeof(ret)) {
            ok = false;
        } else {
            ok = true;
            auto *cur = ba.constData();
            ret.txNum0 = DeserializeScalar<decltype(ret.txNum0)>(ShallowTmp(cur, sizeof(ret.txNum0)), &ok);
            cur += sizeof(ret.txNum0);
            ret.nTx = DeserializeScalar<decltype(ret.nTx)>(ShallowTmp(cur, sizeof(ret.nTx)), &ok);
            cur += sizeof(ret.nTx);
            assert(cur <= ba.constData() + ba.size());
            if (!ok) ret = BlkInfo{}; // clear
        }
        return ret;
    }

    struct UndoInfoSerHeader {
        static constexpr uint16_t defMagic = 0xf12cu, v1Ver = 0x1u, v2Ver = 0x2u, v3Ver = 0x3u;
        static constexpr auto defVer = v3Ver;
        uint16_t magic = defMagic; ///< sanity check
        uint16_t ver = defVer; ///< sanity check
        uint32_t len = 0; ///< the length of the entire buffer, including this struct and all data to follow. A sanity check.
        uint32_t nScriptHashes = 0, nAddUndos = 0, nDelUndos = 0; ///< the number of elements in each of the 3 arrays in question.

        /* ----------- V1 format (back when we had 2 byte IONums) */
        static constexpr size_t addUndoItemSerSize_V1 = TXO::minSize() + HashLen + CompactTXO::minSize();
        static constexpr size_t delUndoItemSerSize_V1 = TXO::minSize() + TXOInfo::minSerSize();

        /// computes the total size given the ser size of the blkInfo struct.
        /// Requires that nScriptHashes, nAddUndos, and nDelUndos be already filled-in.
        size_t computeTotalSize_V1() const {
            const auto shSize = nScriptHashes * HashLen;
            const auto addsSize = nAddUndos * addUndoItemSerSize_V1;
            const auto delsSize = nDelUndos * delUndoItemSerSize_V1;
            return sizeof(*this) + sizeof(UndoInfo::height) + HashLen + sizeof(BlkInfo) + shSize + addsSize + delsSize;
        }
        bool isLenSane_V1() const { return size_t(len) == computeTotalSize_V1(); }


        /* ----------- V2 format (3-byte IONums) */
        static constexpr size_t addUndoItemSerSize_V2 = TXO::maxSize() + HashLen + CompactTXO::maxSize();
        static constexpr size_t delUndoItemSerSize_V2 = TXO::maxSize() + TXOInfo::minSerSize();

        /// computes the total size given the ser size of the blkInfo struct. Requires that nScriptHashes, nAddUndos, and nDelUndos be already filled-in.
        size_t computeTotalSize_V2() const {
            const auto shSize = nScriptHashes * HashLen;
            const auto addsSize = nAddUndos * addUndoItemSerSize_V2;
            const auto delsSize = nDelUndos * delUndoItemSerSize_V2;
            return sizeof(*this) + sizeof(UndoInfo::height) + HashLen + sizeof(BlkInfo) + shSize + addsSize + delsSize;
        }
        bool isLenSane_V2() const { return size_t(len) == computeTotalSize_V2(); }

        /* ----------- V3 format (same as V3 but has dynamically-sized TXOInfo objects >= 50 bytes) */
        /// computes the minimum size given the ser size of the blkInfo struct. Requires that nScriptHashes, nAddUndos, and nDelUndos be already filled-in.
        size_t computeMinimumSize_V3() const { return computeTotalSize_V2(); }
        bool isLenMinimallySane_V3() const { return size_t(len) >= computeMinimumSize_V3(); }

        QByteArray toBytes(QByteArray *bufAppend = nullptr) const {
            // This used to be written as a raw struct (not endian safe). Now we do it this way as little endian to
            // be backward compatible with little endian platforms that did it the old way in Fulcrum 1.x.
            // NOTE: Be sure to maintain the order of these fields for the struct else you will need to write update
            // code.
            QByteArray tmp;
            QByteArray &buf = bufAppend ? *bufAppend : tmp;
            if (!bufAppend) buf.reserve(sizeof(*this));
            {
                QDataStream s(&buf, QIODevice::OpenModeFlag::WriteOnly|QIODevice::OpenModeFlag::Append);
                s.setByteOrder(QDataStream::ByteOrder::LittleEndian); // for backward compat with old data
                s << magic << ver << len << nScriptHashes << nAddUndos << nDelUndos;
            }
            return buf;
        }

        static UndoInfoSerHeader fromBytes(ByteView &bv, bool *ok = nullptr) {
            const QByteArray qba = bv.toByteArray(false);
            QDataStream s(qba);
            s.setByteOrder(QDataStream::ByteOrder::LittleEndian); // for backward compat. with old data
            UndoInfoSerHeader h{.magic = 0, .ver = 0};
            s >> h.magic >> h.ver >> h.len >> h.nScriptHashes >> h.nAddUndos >> h.nDelUndos;
            if (ok) *ok = s.status() == QDataStream::Status::Ok;
            bv = bv.substr(sizeof(UndoInfoSerHeader)); // update read pos by modifying bv
            return h;
        }
    };

    static_assert(std::has_unique_object_representations_v<UndoInfoSerHeader> && sizeof(UndoInfoSerHeader) == 20,
                  "This type is used to be serialized as raw bytes to the legacy db, so we need to maintain compat with that!");

    // Deserialize a header from bytes -- no checks are done other than length check.
    template <> UndoInfoSerHeader Deserialize(const QByteArray &ba, bool *ok) {
        if (ba.length() < QByteArray::size_type(sizeof(UndoInfoSerHeader))) {
            if (ok) *ok = false;
            return UndoInfoSerHeader{.magic = 0, .ver = 0};
        } else {
            ByteView bv(ba);
            return UndoInfoSerHeader::fromBytes(bv, ok);
        }
    }

    // UndoInfo -- serialize to V3 format (fixed 3-byte IONums, dynamically-sized TXOInfo objects)
    template <> QByteArray Serialize(const UndoInfo &u) {
        UndoInfoSerHeader hdr;
        // fill these in now so that hdr.computeTotalSize works
        hdr.nScriptHashes = uint32_t(u.scriptHashes.size());
        hdr.nAddUndos = uint32_t(u.addUndos.size());
        hdr.nDelUndos = uint32_t(u.delUndos.size());
        hdr.len = uint32_t(hdr.computeMinimumSize_V3());
        const size_t offset_of_len = offsetof(UndoInfoSerHeader, len);
        QByteArray ret;
        ret.reserve(int(hdr.len));
        // 1. header
        hdr.toBytes(&ret);
        // 2. .height
        ret.append(SerializeScalarEphemeral(u.height));
        // 3. .hash
        const auto chkHashLen = [&ret](const QByteArray & hash) -> bool {
            if (hash.length() != HashLen) {
                Warning() << "hash is not " << HashLen << " bytes. Serialize UndoInfo fail. FIXME!";
                ret.clear();
                return false;
            }
            return true;
        };
        if (!chkHashLen(u.hash)) return ret;
        ret.append(u.hash);
        // 4. .blkInfo
        u.blkInfo.toBytes(&ret);
        // 5. .scriptHashes, 32 bytes each, for all in set
        for (const auto & sh : u.scriptHashes) {
            if (UNLIKELY(!chkHashLen(sh))) return ret;
            ret.append(sh);
        }
        // 6. .addUndos, 76 bytes each * nAddUndos
        for (const auto & [txo, hashX, ctxo] : u.addUndos) {
            if (UNLIKELY(!chkHashLen(hashX))) return ret;
            ret.append(txo.toBytes(/* force wide (3 byte IONum) = */true));
            ret.append(hashX);
            ret.append(ctxo.toBytes(/* force wide (3 byte IONum) = */true, /*bigEndian=*/false));
        }
        // 7. .delUndos, >=85 bytes each * nDelUndos
        for (const auto & [txo, txoInfo] : u.delUndos) {
            ret.append(txo.toBytes(true));
            if (UNLIKELY(!chkHashLen(txoInfo.hashX))) return ret;
            const QByteArray serinfo = Serialize(txoInfo);
            ret.append(VarInt(uint32_t(serinfo.size())).byteArray(false)); // append size as VarInt (our own internal compact int)
            ret.append(serinfo);
        }
        if (UNLIKELY(ret.length() < QByteArray::size_type(hdr.len))) {
            Warning() << "unexpected length when serializing an UndoInfo object: " << ret.length() << ". FIXME!";
            ret.clear();
            return ret;
        }
        // 8. update length since serializing potential token data for each TXOInfo has variable size
        hdr.len = uint32_t(ret.length());
        const uint32_t len_le = Util::hToLe32(hdr.len);
        std::memcpy(ret.data() + offset_of_len, &len_le, sizeof(len_le));

        return ret;
    }

    // UndoInfo -- note this will fail if the byte array has extra bytes at the end
    template <> UndoInfo Deserialize(const QByteArray &ba, bool *ok) {
        UndoInfo ret;
        const auto setOk = [&ok, &ret] (bool b) { if (ok) *ok = b; if (!b) ret.clear(); };
        const auto chkAssertion = [&setOk] (bool assertion, const char *extra = "") {
            if (UNLIKELY(!assertion)) {
                Warning() << "Deserialize UndoInfo called with an invalid byte array! FIXME! " << extra;
                setOk(false);
            }
            return assertion;
        };
        if (!chkAssertion(ba.size() > int(sizeof(UndoInfoSerHeader)), "Short byte count"))
            return ret;

        bool myok = false;
        // 1. .header
        const UndoInfoSerHeader hdr = Deserialize<UndoInfoSerHeader>(ba, &myok);;
        if (!chkAssertion(myok && int(hdr.len) == ba.size() && hdr.magic == hdr.defMagic
                          && ( (hdr.ver == hdr.v3Ver && hdr.isLenMinimallySane_V3())
                               || (hdr.ver == hdr.v2Ver && hdr.isLenSane_V2())
                               || (hdr.ver == hdr.v1Ver && hdr.isLenSane_V1()) ),
                          "Header sanity check fail"))
            return ret;
        ret.deserVersion = hdr.ver;

        // for v1 we deserialize 2-byte fixed-size IONums, for v2 3-byte fixed-size IONums
        const bool isV1 = hdr.ver == hdr.v1Ver;
        // for v2 we assume fixed-size TXOInfo objects (this was before token data existed), so we deserialize them
        // as a flat array without any VarInt info as to the size of each
        const bool isV2 = hdr.ver == hdr.v2Ver;

        // print to debug if encountering V1 vs V2
        DebugM("Deserializing ", isV1 ? "V1" : (isV2 ? "V2" : "V3"), " undo info of length ", hdr.len);

        const size_t TXOSerSize = isV1 ? TXO::minSize() : TXO::maxSize();
        const size_t CompactTXOSerSize = isV1 ? CompactTXO::minSize() : CompactTXO::maxSize();
        //
        // deserialize V1 data -> fixed 2-byte IONums
        // deserialize V2 or V3 data -> fixed 3-byte IONums
        //
        const char *cur = ba.constData() + sizeof(hdr), *const end = ba.constData() + ba.length();
        // 2. .height
        ret.height = DeserializeScalar<decltype(ret.height)>(ShallowTmp(cur, sizeof(ret.height)), &myok);
        if (!chkAssertion(myok && cur < end))
            return ret;
        cur += sizeof(ret.height);
        // 3. .hash
        ret.hash = DeepCpy(cur, HashLen); // deep copy
        if (!chkAssertion(ret.hash.length() == HashLen && cur < end))
            return ret;
        cur += HashLen;
        // 4. .blkInfo
        ret.blkInfo = Deserialize<BlkInfo>(ShallowTmp(cur, sizeof(BlkInfo)), &myok);
        if (!chkAssertion(myok && cur <= end))
            return ret;
        cur += sizeof(BlkInfo);
        // 5. .scriptHashes, 32 bytes each * hdr->nScriptHashes
        ret.scriptHashes.reserve(hdr.nScriptHashes);
        for (unsigned i = 0; i < hdr.nScriptHashes; ++i) {
            if (!chkAssertion(cur+HashLen <= end)) return ret;
            ret.scriptHashes.insert(DeepCpy(cur, HashLen)); // deep copy
            cur += HashLen;
        }
        // 6. .addUndos, 74 (v1) or 76 (v2) bytes each * nAddUndos
        ret.addUndos.reserve(hdr.nAddUndos);
        for (unsigned i = 0; i < hdr.nAddUndos; ++i) {
            if (!chkAssertion(cur+TXOSerSize <= end)) return ret;
            TXO txo = Deserialize<TXO>(ShallowTmp(cur, TXOSerSize), &myok);
            cur += TXOSerSize;
            if (!chkAssertion(myok && cur+HashLen <= end)) return ret;
            QByteArray hashX = DeepCpy(cur, HashLen); // deep copy
            cur += HashLen;
            if (!chkAssertion(cur+CompactTXOSerSize <= end)) return ret;
            CompactTXO ctxo = Deserialize<CompactTXO>(ShallowTmp(cur, CompactTXOSerSize), &myok);
            cur += CompactTXOSerSize;
            if (!chkAssertion(myok)) return ret;
            ret.addUndos.emplace_back(std::move(txo), std::move(hashX), std::move(ctxo));
        }
        // 7. .delUndos, 84 (v1) or 85 (v2) bytes each * nDelUndos, for v3 the size is dynamic but always >= 85
        ret.delUndos.reserve(hdr.nDelUndos);
        for (unsigned i = 0; i < hdr.nDelUndos; ++i) {
            if (!chkAssertion(cur+TXOSerSize <= end)) return ret;
            TXO txo = Deserialize<TXO>(ShallowTmp(cur, TXOSerSize), &myok);
            cur += TXOSerSize;
            if (!chkAssertion(myok && cur + TXOInfo::minSerSize() <= end)) return ret;
            int txoinfo_size{};
            if (isV1 || isV2) {
                txoinfo_size = int(TXOInfo::minSerSize());
            } else {
                // V3 or above: read the byte size as a VarInt.
                Span sp{cur, size_t(end - cur)};
                try {
                    const VarInt vi = VarInt::deserialize(sp); // this may throw
                    cur = sp.data(); // span was updated to point past the varint
                    txoinfo_size = int(vi.value<uint32_t>()); // this may throw
                } catch (const std::exception &e) {
                    chkAssertion(false, e.what());
                    return ret;
                }
            }
            if (!chkAssertion(txoinfo_size >= int(TXOInfo::minSerSize()) && cur + txoinfo_size <= end,
                              "deser of VarInt size for a TXOInfo returned an error"))
                return ret;
            TXOInfo info = Deserialize<TXOInfo>(ShallowTmp(cur, txoinfo_size), &myok);
            if (!chkAssertion(myok, "deser fail on TXOInfo object")) return ret;
            cur += txoinfo_size;
            ret.delUndos.emplace_back(std::move(txo), std::move(info));
        }
        if (!chkAssertion(cur == end, "cur != end")) return ret;
        setOk(true);
        return ret;
    }

    template <> QByteArray Serialize(const TxNumVec &v)
    {
        // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
        constexpr auto compactSize = CompactTXO::compactTxNumSize(); /* 6 */
        const size_t nBytes = v.size() * compactSize;
        QByteArray ret(QByteArray::size_type(nBytes), Qt::Uninitialized);
        if (UNLIKELY(nBytes != size_t(ret.size()))) {
            throw DatabaseSerializationError(QString("Overflow or other error when attempting to serialize a TxNumVec"
                                                     " of %1 bytes").arg(qulonglong(nBytes)));
        }
        std::byte *cur = reinterpret_cast<std::byte *>(ret.data());
        for (const auto num : v) {
            CompactTXO::txNumToCompactBytes(cur, num, /*bigEndian=*/false);
            cur += compactSize;
        }
        return ret;
    }
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize(const QByteArray &ba, bool *ok)
    {
        constexpr auto compactSize = CompactTXO::compactTxNumSize(); /* 6 */
        const size_t blen = size_t(ba.length());
        const size_t N = blen / compactSize;
        TxNumVec ret;
        if (N * compactSize != blen) {
            // wrong size, not multiple of 6; bail
            if (ok) *ok = false;
            return ret;
        }
        if (ok) *ok = true;
        auto * cur = reinterpret_cast<const std::byte *>(ba.constData());
        auto * const end = reinterpret_cast<const std::byte *>(ba.constData() + blen);
        ret.reserve(N);
        for ( ; cur < end; cur += compactSize) {
            ret.push_back( CompactTXO::txNumFromCompactBytes(cur, /*bigEndian=*/false) );
        }
        return ret;
    }

    template <> CompactTXO Deserialize(const QByteArray &b, bool *ok) {
        CompactTXO ret = CompactTXO::fromBytes(b, /*bigEndian=*/false);
        if (ok) *ok = ret.isValid();
        return ret;
    }

    QByteArray Serialize2(const bitcoin::Amount &a, const bitcoin::token::OutputData *ptok) {
        QByteArray ret = SerializeScalar(a / a.satoshi());
        BTC::SerializeTokenDataWithPrefix(ret, ptok); // may be no-op if ptok is nullptr
        return ret;
    }
    template <> SHUnspentValue Deserialize(const QByteArray &ba, bool *pok) {
        QByteArray::size_type pos = 0;
        bool ok;
        const int64_t amt = DeserializeScalar<int64_t>(ba, &ok, &pos);
        SHUnspentValue ret;
        if (ok) {
            ret.amount = amt * bitcoin::Amount::satoshi();
            try {
                ret.tokenDataPtr = BTC::DeserializeTokenDataWithPrefix(ba, pos);
            } catch (const std::exception &e) {
                throw DatabaseSerializationError(
                    QString("Got exception deserializing token data in Storage.cpp::Deserialize(): %1 (from bytes: %2)")
                    .arg(e.what(), ba.mid(pos).toHex().constData()));
            }
        }
        if (pok) *pok = ok;
        ret.valid = ok;
        return ret;
    }

} // end anon namespace

#ifdef ENABLE_TESTS
#include "Storage/RecordFile.h"
#include "robin_hood/robin_hood.h"
namespace {

    template<size_t NB>
    auto DeduceSmallestTypeForNumBytes() {
        if constexpr (NB == 1) return uint8_t{};
        else if constexpr (NB == 2) return uint16_t{};
        else if constexpr (NB <= 4) return uint32_t{};
        else if constexpr (NB <= 8) return uint64_t{};
    #ifdef __SIZEOF_INT128__
        else if constexpr (NB <= 16) return __uint128_t{};
    #endif
        else throw std::domain_error("too big");
    }

    enum class MyPos { Beginning, Middle, End};

    template <size_t NB, MyPos where = MyPos::End>
    ByteView MakeTxHashByteKey(const ByteView &bv) {
        const auto len = bv.size();
        if (UNLIKELY(len != HashLen))
            throw BadArgs(QString("%1... is not %2 bytes").arg(QString(Util::ToHexFast(bv.substr(0, 8).toByteArray(false)))).arg(HashLen));
        static_assert(NB > 0 && NB <= HashLen);
        if constexpr (where == MyPos::End)
            return bv.substr(len - NB, NB);
        else if constexpr (where == MyPos::Middle)
            return bv.substr(len/2 - NB/2, NB);
        else // Beginning
            return bv.substr(0, NB);
    }

    template <size_t NB, MyPos where = MyPos::End, typename KeyType = decltype(DeduceSmallestTypeForNumBytes<NB>())>
    KeyType MakeTxHashNumericKey(const ByteView &bv) {
        static_assert(NB <= sizeof(KeyType));
        static_assert(std::is_standard_layout_v<KeyType> && std::is_trivial_v<KeyType> && !std::is_floating_point_v<KeyType>);
        KeyType ret{};
        std::memcpy(reinterpret_cast<std::byte *>(&ret), MakeTxHashByteKey<NB, where>(bv).data(), NB);
        return ret;
    }

    inline constexpr size_t NB = 6;
    inline constexpr MyPos POS = MyPos::End;

    void findCollisions() {
        Debug::forceEnable = true;
        const QString txnumsFile = std::getenv("TFILE") ? std::getenv("TFILE") : "";
        if (txnumsFile.isEmpty() || !QFile::exists(txnumsFile))
            throw Exception("Please pass the TFILE env var as a path to an existing \"txnum2txhash\" data record file");
        std::unique_ptr<RecordFile> rf;
        rf = std::make_unique<RecordFile>(txnumsFile, HashLen, 0x000012e2); // this may throw
        using KeyType = decltype(DeduceSmallestTypeForNumBytes<NB>());
        using CtrType = decltype(DeduceSmallestTypeForNumBytes<NB <= 2 ? (NB == 1 ? 4 : 2) : 1>());
        const auto nrec = rf->numRecords();
        Log() << "Records: " << nrec;
        robin_hood::unordered_flat_map<KeyType, CtrType> cols;
        Log() << "Reserving table ...";
        size_t nCols = 0, maxCol = 0;
        KeyType maxColVal = 0;
        cols.reserve(std::min<size_t>(nrec, std::numeric_limits<KeyType>::max()));
        constexpr size_t batchSize = 50'000;
        Log() << "Using key bytes: " << NB << ", batchSize: " << batchSize;
        const Tic t0;
        for (size_t i = 0; i < nrec; i += batchSize) {
            if (i && 0 == i % 1'000'000) Debug() << i << "/" << nrec << ", collisions so far: " << nCols << " ...";
            QString err;
            const auto recs = rf->readRecords(i, batchSize, &err);
            for (const auto & rec : recs) {
                const auto key = MakeTxHashNumericKey<NB, POS>(rec);
                const auto val = ++cols[key];
                if (val > 1) {
                    if (val > maxCol) {
                        maxCol = size_t(val);
                        maxColVal = key;
                    }
                    ++nCols;
                    //Log() << "Collision (" << unsigned(val) << ") for bytes: " << rec.toHex().constData() << ", hash value: " << hash;
                }
            }
        }
        Log() << "Collisions total: " << nCols << ", max col: " << maxCol << ", most common key bytes: "
              << QByteArray::fromRawData(reinterpret_cast<const char *>(&maxColVal), NB).toHex()
              << " elapsed: " << t0.secsStr(2) << " sec";
    }
    const auto b1 = App::registerBench("txcol", findCollisions);
} // end anon namespace
#endif
