//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "RecordFile.h"
#include "Span.h"
#include "Storage.h"
#include "SubsMgr.h"
#include "VarInt.h"

#include "bitcoin/hash.h"

#include "robin_hood/robin_hood.h"

#include <rocksdb/cache.h>
#include <rocksdb/db.h>
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
#include <QVector> // we use this for the Height2Hash cache to save on memcopies since it's implicitly shared.

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstddef> // for std::byte, offsetof
#include <cstdlib>
#include <cstring> // for memcpy
#include <functional>
#include <limits>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
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
        static constexpr uint32_t kCurrentVersion = 0x2u;
        static constexpr uint32_t kMinSupportedVersion = 0x1u;
        static constexpr uint32_t kMinBCHUpgrade9Version = 0x2u;

        uint32_t magic = 0xf33db33fu, version = kCurrentVersion;
        QString chain; ///< "test", "main", etc
        uint16_t platformBits = sizeof(long)*8U; ///< we save the platform wordsize to the db

        // -- New in 1.3.0 (this field is not in older db's)
        /// "BCH", "BTC", or "".  May be missing in DB data for older db's, in which case we take the default ("BCH")
        /// when we deserialize, if we detect that it was missing.
        ///
        /// On uninitialized, newly-created DB's this is present but empty "". The fact that it is empty allows us
        /// to auto-detect the Coin in question in Controller.
        QString coin = QString();

        bool isVersionSupported() const { return version >= kMinSupportedVersion && version <= kCurrentVersion; }
    };

    // some database keys we use -- todo: if this grows large, move it elsewhere
    static const bool falseMem = false, trueMem = true;
    static const rocksdb::Slice kMeta{"meta"}, kDirty{"dirty"}, kUtxoCount{"utxo_count"},
                                kTrue(reinterpret_cast<const char *>(&trueMem), sizeof(trueMem)),
                                kFalse(reinterpret_cast<const char *>(&falseMem), sizeof(falseMem));

    // serialize/deser -- for basic types we use QDataStream, but we also have specializations at the end of this file
    template <typename Type>
    QByteArray Serialize(const Type & n) {
        QByteArray ba;
        if constexpr (std::is_base_of_v<QByteArray, Type>) {
            ba = n;
        } else {
            QDataStream ds(&ba, QIODevice::WriteOnly|QIODevice::Truncate);
            ds << n;
        }
        return ba;
    }
    template <typename Type>
    Type Deserialize(const QByteArray &ba, bool *ok = nullptr) {
        Type ret{};
        if constexpr (std::is_base_of_v<QByteArray, Type>) {
            ret = ba;
        } else {
            QDataStream ds(ba);
            ds >> ret;
            if (ok)
                *ok = ds.status() == QDataStream::Status::Ok;
        }
        return ret;
    }

    /// Return a shallow, temporary copy of the memory of an object as a QByteArray. This reduces typing of
    /// the boilerplate: "QByteArray::fromRawData(reinterpret_cast...." etc everywhere in this file.
    /// Note: It is unsafe to use this function for anything other than obtaining a weak reference to the memory of an
    /// object as a QByteArray for temporary purposes. The original object must live at least as long as this returned
    /// QByteArray.  Note that even copy-constructing a new QByteArray from this returned QByteArray will lead to
    /// dangling pointers. See: https://doc.qt.io/qt-5/qbytearray.html#fromRawData.
    template <typename Object,
              std::enable_if_t<!std::is_pointer_v<std::remove_cv_t<Object>>, int> = 0>
    QByteArray ShallowTmp(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(mem), int(size));
    }

    /// Construct a QByteArray from a deep copy of any object's memory area. Slower than ShallowTmp above but 100% safe
    /// to use after the original object expires since the returned QByteArray takes ownership of its private copy of
    /// the memory it allocated.
    template <typename Object,
              std::enable_if_t<!std::is_pointer_v<std::remove_cv_t<Object>>, int> = 0>
    QByteArray DeepCpy(const Object *mem, size_t size = sizeof(Object)) {
        return QByteArray(reinterpret_cast<const char *>(mem), int(size));
    }

    /// Serialize a simple value such as an int directly, without using the space overhead that QDataStream imposes.
    /// This is less safe but is more compact since the bytes of the passed-in value are written directly to the
    /// returned QByteArray, without any encapsulation.  Note that use of this mechanism makes all data in the database
    /// no longer platform-neutral, which is ok. The presumption is users can re-synch their DB if switching
    /// architectures.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalar (const Scalar & s) { return DeepCpy(&s); }
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    QByteArray SerializeScalarNoCopy (const Scalar &s) { return ShallowTmp(&s);  }
    /// Inverse of above.  Pass in an optional 'pos' pointer if you wish to continue reading raw scalars from the same
    /// QByteArray during subsequent calls to this template function.  *ok, if specified, is set to false if we ran off
    /// the QByteArray's bounds, and a default-constructed value of 'Scalar' is returned.  No other safety checking is
    /// done.  On successful deserialization of the scalar, *pos (if specified) is updated to point just past the
    /// last byte of the successuflly converted item.  On failure, *pos is always set to point past the end of the
    /// QByteArray.
    template <typename Scalar,
              std::enable_if_t<std::is_scalar_v<Scalar> && !std::is_pointer_v<Scalar>, int> = 0>
    Scalar DeserializeScalar(const QByteArray &ba, bool *ok = nullptr, int *pos_out = nullptr) {
        Scalar ret{};
        int dummy = 0;
        int & pos = pos_out ? *pos_out : dummy;
        if (pos >= 0 && pos + int(sizeof(ret)) <= ba.size()) {
            if (ok) *ok = true;
            std::memcpy(reinterpret_cast<std::byte *>(&ret), ba.constData() + pos, sizeof(ret));
            pos += sizeof(ret);
        } else {
            if (ok) *ok = false;
            pos = ba.size();
        }
        return ret;
    }

    struct SHUnspentValue {
        bool valid = false;
        bitcoin::Amount amount;
        bitcoin::token::OutputDataPtr tokenDataPtr;
    };

    // specializations
    template <> QByteArray Serialize(const Meta &);
    template <> Meta Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXO &);
    template <> TXO Deserialize(const QByteArray &, bool *);
    template <> QByteArray Serialize(const TXOInfo &);
    template <> TXOInfo Deserialize(const QByteArray &, bool *);
    QByteArray Serialize(const bitcoin::Amount &, const bitcoin::token::OutputData *);
    template <> SHUnspentValue Deserialize(const QByteArray &, bool *);
    // TxNumVec
    using TxNumVec = std::vector<TxNum>;
    // this serializes a vector of TxNums to a compact representation (6 bytes, eg 48 bits per TxNum), in little endian byte order
    template <> QByteArray Serialize(const TxNumVec &);
    // this deserializes a vector of TxNums from a compact representation (6 bytes, eg 48 bits per TxNum), assuming little endian byte order
    template <> TxNumVec Deserialize(const QByteArray &, bool *);

    // CompactTXO -- not currently used since we prefer toBytes() directly (TODO: remove if we end up never using this)
    //template <> QByteArray Serialize(const CompactTXO &);
    template <> CompactTXO Deserialize(const QByteArray &, bool *);


    /// NOTE: The slice should live as long as the returned QByteArray does.  The QByteArray is a weak pointer into the slice!
    inline QByteArray FromSlice(const rocksdb::Slice &s) { return ShallowTmp(s.data(), s.size()); }

    /// Generic conversion from any type we operate on to a rocksdb::Slice. Note that the type in question should have
    /// a conversion function written (eg Serialize) if it is anything other than a QByteArray or a scalar.
    template<bool safeScalar=false, typename Thing>
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
        } else if constexpr (!safeScalar && std::is_scalar_v<Thing> && !std::is_pointer_v<Thing>) {
            return rocksdb::Slice(reinterpret_cast<const char *>(&thing), sizeof(thing)); // returned slice points to raw scalar memory itself
        } else {
            // the purpose of this holder is to keep the temporary QByteArray alive for as long as the slice itself is alive
            struct BagOfHolding {
                QByteArray bytes;
                rocksdb::Slice slice;
                operator const rocksdb::Slice &() const { return slice; }
            } h { Serialize(thing), ToSlice(h.bytes) };
            return h; // this holder type "acts like" a Slice due to its operator const Slice &()
        }
    };

    /// Helper to get db name (basename of path)
    QString DBName(const rocksdb::DB *db) { return QFileInfo(QString::fromStdString(db->GetName())).baseName(); }
    /// Helper to just get the status error string as a QString
    QString StatusString(const rocksdb::Status & status) { return QString::fromStdString(status.ToString()); }

    /// DB read/write helpers
    /// NOTE: these may throw DatabaseError
    /// If missingOk=false, then the returned optional is guaranteed to have a value if this function returns without throwing.
    /// If missingOk=true, then if there was no other database error and the key was not found, the returned optional !has_value()
    ///
    /// Template arg "safeScalar", if true, will deserialize scalar int, float, etc data using the Deserialize<>
    /// function (uses QDataStream, is platform neutral, but is slightly slower).  If false, we will use the
    /// DeserializeScalar<> fast function for scalars such as ints. It's important to read from the DB in the same
    /// 'safeScalar' mode as was written!
    template <typename RetType, bool safeScalar = false, typename KeyType>
    std::optional<RetType> GenericDBGet(rocksdb::DB *db, const KeyType & keyIn, bool missingOk = false,
                                        const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                                        bool acceptExtraBytesAtEndOfData = false,
                                        const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions()) ///< if true, we are ok with extra unparsed bytes in data. otherwise we throw. (this check is only done for !safeScalar mode on basic types)
    {
        rocksdb::PinnableSlice datum;
        std::optional<RetType> ret;
        if (UNLIKELY(!db)) throw InternalError("GenericDBGet was passed a null pointer!");
        const auto status = db->Get(ropts, db->DefaultColumnFamily(), ToSlice<safeScalar>(keyIn), &datum);
        if (status.IsNotFound()) {
            if (missingOk)
                return ret; // optional will not has_value() to indicate missing key
            throw DatabaseKeyNotFound(QString("%1: %2")
                                      .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Key not found in db %1").arg(DBName(db)))
                                      .arg(StatusString(status)));
        } else if (!status.ok()) {
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error reading a key from db %1").arg(DBName(db)))
                                .arg(StatusString(status)));
        } else {
            // ok status
            if constexpr (std::is_base_of_v<QByteArray, std::remove_cv_t<RetType> >) {
                static_assert (!safeScalar, "safeScalar=true mode is not supported for QByteArrays (it only is useful for scalar types)" );
                // special compile-time case for QByteArray subclasses -- return a deep copy of the data bytes directly.
                // TODO: figure out a way to do this without the 1 extra copy! (PinnableSlice -> ret).
                ret.emplace( reinterpret_cast<const char *>(datum.data()), QByteArray::size_type(datum.size()) );
            } else if constexpr (std::is_same_v<rocksdb::PinnableSlice, std::remove_cv_t<RetType>>) {
                static_assert (!std::is_same_v<rocksdb::PinnableSlice, std::remove_cv_t<RetType>>,
                               "FIXME: rocksdb C++ is broken. This doesn't actually work.");
                ret.emplace(std::move(datum)); // avoids an extra copy -- but it doesn't work because Facebook doesn't get how C++ works.
            } else if constexpr (!safeScalar && std::is_scalar_v<RetType> && !std::is_pointer_v<RetType>) {
                if (!acceptExtraBytesAtEndOfData && datum.size() > sizeof(RetType)) {
                    // reject extra stuff at end of data stream
                    throw DatabaseFormatError(QString("%1: Extra bytes at the end of data")
                                              .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Database format error in db %1").arg(DBName(db))));
                }
                bool ok;
                ret.emplace( DeserializeScalar<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized as a scalar '%2'")
                                .arg((!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing a scalar from db %1").arg(DBName(db))),
                                     QString(typeid (RetType).name())));
                }
            } else {
                if (UNLIKELY(acceptExtraBytesAtEndOfData))
                    Debug() << "Warning:  Caller misuse of function '" << __func__
                            << "'. 'acceptExtraBytesAtEndOfData=true' is ignored when deserializing using QDataStream.";
                bool ok;
                ret.emplace( Deserialize<RetType>(FromSlice(datum), &ok) );
                if (!ok) {
                    throw DatabaseSerializationError(
                                QString("%1: Key was retrieved ok, but data could not be deserialized")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deserializing an object from db %1").arg(DBName(db))));
                }
            }
        }
        return ret;
    }

    /// Conveneience for above with the missingOk flag set to false. Will always throw or return a real value.
    template <typename RetType, bool safeScalar = false, typename KeyType>
    RetType GenericDBGetFailIfMissing(rocksdb::DB * db, const KeyType &k, const QString &errMsgPrefix = QString(), bool extraDataOk = false,
                                      const rocksdb::ReadOptions & ropts = rocksdb::ReadOptions())
    {
        return GenericDBGet<RetType, safeScalar>(db, k, false, errMsgPrefix, extraDataOk, ropts).value();
    }

    /// Throws on all errors. Otherwise writes to db.
    template <bool safeScalar = false, typename KeyType, typename ValueType>
    void GenericDBPut
                (rocksdb::DB *db, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                 const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Put(opts, ToSlice<safeScalar>(key), ToSlice<safeScalar>(value));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error writing to db %1").arg(DBName(db)))
                                .arg(StatusString(st)));
    }
    /// Throws on all errors. Otherwise enqueues a write to the batch.
    template <bool safeScalar = false, typename KeyType, typename ValueType>
    void GenericBatchPut
                (rocksdb::WriteBatch & batch, const KeyType & key, const ValueType & value,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Put(ToSlice<safeScalar>(key), ToSlice<safeScalar>(value));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Put")
                                .arg(StatusString(st)));
    }
    /// Throws on all errors. Otherwise enqueues a delete to the batch.
    template <bool safeScalar = false, typename KeyType>
    void GenericBatchDelete
                (rocksdb::WriteBatch & batch, const KeyType & key,
                 const QString & errorMsgPrefix = QString())  ///< used to specify a custom error message in the thrown exception
    {
        auto st = batch.Delete(ToSlice<safeScalar>(key));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : "Error from WriteBatch::Delete")
                                .arg(StatusString(st)));
    }
    /// A convenient wrapper to db->Write(batch...) which throws on all errors.
    void GenericBatchWrite(rocksdb::DB *db, rocksdb::WriteBatch & batch,
                        const QString & errorMsgPrefix = QString(),
                        const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Write(opts, &batch);
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg((!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error writing batch to db %1").arg(DBName(db))),
                                     StatusString(st)));
    }
    /// Throws on all errors. Otherwise deletes a key from db. It is not an error to delete a non-existing key.
    template <bool safeScalar = false, typename KeyType>
    void GenericDBDelete
                (rocksdb::DB *db, const KeyType & key,
                 const QString & errorMsgPrefix = QString(),  ///< used to specify a custom error message in the thrown exception
                 const rocksdb::WriteOptions & opts = rocksdb::WriteOptions())
    {
        auto st = db->Delete(opts, ToSlice<safeScalar>(key));
        if (!st.ok())
            throw DatabaseError(QString("%1: %2")
                                .arg(!errorMsgPrefix.isEmpty() ? errorMsgPrefix : QString("Error deleting a key from db %1").arg(DBName(db)))
                                .arg(StatusString(st)));
    }

    //// A helper data struct -- written to the blkinfo table. This helps localize a txnum to a specific position in
    /// a block.  The table is keyed off of block_height(uint32_t) -> serialized BlkInfo (raw bytes)
    struct BlkInfo {
        TxNum txNum0 = 0;
        unsigned nTx = 0;
        BlkInfo() = default;
        BlkInfo(const BlkInfo &) = default;
        [[maybe_unused]] BlkInfo (TxNum txn, unsigned ntx) : txNum0(txn), nTx(ntx) {}
        bool operator==(const BlkInfo &o) const { return txNum0 == o.txNum0 && nTx == o.nTx; }
        bool operator!=(const BlkInfo &o) const { return !(*this == o); }
        [[maybe_unused]] bool operator<(const BlkInfo &o) const { return txNum0 == o.txNum0 ? nTx < o.nTx : txNum0 < o.txNum0; }
        BlkInfo &operator=(const BlkInfo &) = default;
    };
    // serializes as raw bytes from struct
    template <> QByteArray Serialize(const BlkInfo &);
    // deserializes as raw bytes from struct
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


    /// Associative merge operator used for scripthash history concatenation
    /// TODO: this needs to be made more efficient by implementing the real MergeOperator interface and combining
    /// appends efficiently to reduce allocations.  Right now it's called for each append.
    class ConcatOperator : public rocksdb::AssociativeMergeOperator {
    public:
        ~ConcatOperator() override;

        mutable std::atomic<unsigned> merges = 0;

        // Gives the client a way to express the read -> modify -> write semantics
        // key:           (IN) The key that's associated with this merge operation.
        // existing_value:(IN) null indicates the key does not exist before this op
        // value:         (IN) the value to update/merge the existing_value with
        // new_value:    (OUT) Client is responsible for filling the merge result
        // here. The string that new_value is pointing to will be empty.
        // logger:        (IN) Client could use this to log errors during merge.
        //
        // Return true on success.
        // All values passed in will be client-specific values. So if this method
        // returns false, it is because client specified bad data or there was
        // internal corruption. The client should assume that this will be treated
        // as an error by the library.
        bool Merge(const rocksdb::Slice& key, const rocksdb::Slice* existing_value,
                   const rocksdb::Slice& value, std::string* new_value,
                   rocksdb::Logger* logger) const override;
        const char* Name() const override { return "ConcatOperator"; /* NOTE: this must be the same for the same db each time it is opened! */ }
    };

    ConcatOperator::~ConcatOperator() {} // weak vtable warning prevention

    bool ConcatOperator::Merge(const rocksdb::Slice& key, const rocksdb::Slice* existing_value,
                               const rocksdb::Slice& value, std::string* new_value, rocksdb::Logger* logger) const
    {
        (void)key; (void)logger;
        ++merges;
        new_value->resize( (existing_value ? existing_value->size() : 0) + value.size() );
        char *cur = new_value->data();
        if (existing_value) {
            std::memcpy(cur, existing_value->data(), existing_value->size());
            cur += existing_value->size();
        }
        std::memcpy(cur, value.data(), value.size());
        return true;
    }

    /// Thrown if user hits Ctrl-C / app gets a signal while we run the slow db checks
    struct UserInterrupted : public Exception { using Exception::Exception; ~UserInterrupted() override; };
    UserInterrupted::~UserInterrupted() {} // weak vtable warning suppression

    /// Manages the txhash2txnum rocksdb table.  The schema is:
    /// Key: N bytes from POS position from the big-endian ordered (JSON ordered) txhash (default 6 from the End)
    /// Value: One or more serialized VarInts. Each VarInt represents a "TxNum" (which tells us where the actual hash
    ///     lives in the txnum2txhash flat file).
    ///
    /// This class is mainly a thin wrapper around the rocksdb and RecordFile facilities and they are both
    /// thread-safe and reentrant. It takes no locks itself.
    class TxHash2TxNumMgr {
        rocksdb::DB * const db;
        const rocksdb::ReadOptions & rdOpts; // references into Storage::Pvt
        const rocksdb::WriteOptions & wrOpts;
        RecordFile * const rf;
        std::shared_ptr<rocksdb::MergeOperator> mergeOp;
        ConcatOperator * concatOp;  // this is a "weak" pointer into above, dynamic casted down. always valid.
        Tic lastWarnTime; ///< this is not guarded by any locks. Assumption is calling code always holds an exclusive lock when calling truncateForUndo()
        int64_t largestTxNumSeen = -1;
    public:
        const size_t keyBytes;

        enum KeyPos : uint8_t { Beginning=0, Middle=1, End=2, KP_Invalid=3 };
        const KeyPos keyPos;

        TxHash2TxNumMgr(rocksdb::DB *db, const rocksdb::ReadOptions & rdOpts, const rocksdb::WriteOptions &wrOpts,
                     RecordFile *txnum2txhash, size_t keyBytes /*= 6*/, KeyPos keyPos /*= End*/)
            : db(db), rdOpts(rdOpts), wrOpts(wrOpts), rf(txnum2txhash), keyBytes(keyBytes), keyPos(keyPos)
        {
            if (!this->db || !rf || !this->keyBytes || this->keyBytes > HashLen || this->keyPos >= KP_Invalid)
                throw BadArgs("Bad argumnets supplied to TxHash2TxNumMgr constructor");
            mergeOp = db->GetOptions().merge_operator;
            if (!mergeOp || ! (concatOp = dynamic_cast<ConcatOperator *>(mergeOp.get())))
                throw BadArgs("This db lacks a merge operator of type `ConcatOperator`");
            loadLargestTxNumSeen();
            Debug() << "TxHash2TxNumMgr: largestTxNumSeen = " << largestTxNumSeen;
        }

        unsigned mergeCount() const { return concatOp->merges.load(); }

        QString dbName() const { return QString::fromStdString(db->GetName()); }

        /// Returns the largest tx num we have ever inserted into the db, or -1 if no txnums were inserted
        int64_t maxTxNumSeenInDB() const { return largestTxNumSeen; }

        void insertForBlock(TxNum blockTxNum0, const std::vector<PreProcessedBlock::TxInfo> &txInfos) {
            const Tic t0;
            rocksdb::WriteBatch batch;
            for (TxNum i = 0; i < txInfos.size(); ++i) {
                const ByteView key = makeKeyFromHash(txInfos[i].hash);
                const VarInt val(blockTxNum0 + i);
                // save by appending VarInt. Note that this uses the 'ConcatOperator' class we defined in this file,
                // which requires rocksdb be compiled with RTTI.
                if (auto st = batch.Merge(ToSlice(key), ToSlice(val.byteView())); !st.ok())
                    throw DatabaseError(QString("%1: batch merge fail for txHash %2: %3")
                                        .arg(dbName(), QString(txInfos[i].hash.toHex()), QString::fromStdString(st.ToString())));
            }
            if (auto st = db->Write(wrOpts, &batch) ; !st.ok())
                throw DatabaseError(QString("%1: batch merge fail: %2").arg(dbName(), QString::fromStdString(st.ToString())));
            if (!txInfos.empty()) {
                largestTxNumSeen = blockTxNum0 + txInfos.size() - 1;
                saveLargestTxNumSeen();
            }
            if (t0.msec() >= 50)
                DebugM(__func__, ": inserted ", txInfos.size(), Util::Pluralize(" hash", txInfos.size()),
                       " in ", t0.msecStr(), " msec");
        }

        /// This is called during blockundo. Deletes records from the db having their TxNum >= `txNum`. Requires that
        /// rf not yet be truncated. This is slow so don't call it with huge numbers of records beyond what fits into a block.
        void truncateForUndo(const TxNum txNum) {
            const auto rfNR = rf->numRecords();
            if (rfNR < txNum) throw DatabaseError(dbName() + ": RecordFile does not have the hashes required for the specified truncation");
            else if (rfNR == txNum) {
                // defensive programming warning -- this should never happen
                Warning() << __func__ << ": called with txNum == RecordFile->numRecords -- FIXME!";
                return;
            }
            const Tic t0;
            QString err;
            const auto recs = rf->readRecords(txNum, rfNR - txNum, &err);
            if (recs.size() != rfNR - txNum || !err.isEmpty())
                throw DatabaseError(QString("%1: short read count or error reading record file: %2").arg(dbName(), err));

            DebugM(__func__, ": read ", recs.size(), " record(s) from txNums file, elapsed: ", t0.msecStr(), " msec");

            // first read all existing entries from the db -- we must delete the VarInts in their data blobs that
            // have TxNums > txNum
            std::vector<rocksdb::Slice> keySlices; keySlices.reserve(recs.size());
            std::vector<std::string> dbValues;
            for (size_t i = 0; i < recs.size(); ++i) {
                const auto bv = makeKeyFromHash(recs[i]);
                keySlices.emplace_back(bv.charData(), bv.size());
            }
            std::vector<rocksdb::Status> statuses = db->MultiGet(rdOpts, keySlices, &dbValues);
            DebugM(__func__, ": MultiGet on ", statuses.size(), " key(s), elapsed: ", t0.msecStr(), " msec");
            if (statuses.size() != recs.size() || dbValues.size() != recs.size())
                throw DatabaseError(dbName() + ": RocksDB MultiGet did not return the proper number of records");

            // next filter out all VarInts >= txNum, deleting records that have no more VarInts left and writing
            // back records that still have VarInts in them
            rocksdb::WriteBatch batch;
            int dels{}, keeps{}, filts{}; // for DEBUG print
            for (size_t i = 0; i < dbValues.size(); ++i) {
                if (!statuses[i].ok()) {
                    if (lastWarnTime.secs() >= 1.0) {
                        lastWarnTime = Tic();
                        // not sure what to do here... this should never happen. But warn anyway.
                        Warning() << __func__ << ": " << dbName() << ", got a non-ok status when reading a key for txhash "
                                  << recs[i].toHex() << ". Proceeding anyway but there may be DB corruption. "
                                  << "Start " << APPNAME << " again with -C -C to check the database for consistency.";
                    }
                    continue;
                }
                auto span = Span<const char>{dbValues[i]};
                std::string valBackToDb;
                while (!span.empty()) {
                    try {
                        const VarInt val = VarInt::deserialize(span); // this may throw
                        if (val.value<TxNum>() >= txNum) {
                            // skip, filter out...
                            ++filts;
                        } else {
                            // was a collision, keep
                            valBackToDb.append(val.byteView().charData(), val.size());
                            ++keeps;
                        }
                    } catch (const std::exception &e) {
                        throw DatabaseFormatError(QString("%1: caught exception in %2: %3").arg(dbName(), __func__, e.what()));
                    }
                }
                if (valBackToDb.empty()) {
                    // delete, key now has no VarInts
                    if (auto st = batch.Delete(keySlices[i]); !st.ok()) {
                        if (lastWarnTime.secs() >= 1.0) {
                            lastWarnTime = Tic();
                            Warning() << __func__ << ": " << dbName() << " failed to delete a key from db: "
                                      << QString::fromStdString(st.ToString()) << ". Continuing anyway ...";
                        }
                    }
                    ++dels;
                } else {
                    // keep key, key has some VarInts left
                    if (auto st = batch.Put(keySlices[i], valBackToDb); !st.ok())
                        throw DatabaseError(dbName() + ": failed to write back a key to the db: " + QString::fromStdString(st.ToString()));
                }
            }

            // and, finally, commit the updates to the DB
            if (auto st = db->Write(wrOpts, &batch) ; !st.ok())
                throw DatabaseError(dbName() + ": batch write fail: " + QString::fromStdString(st.ToString()));

            const int64_t txNumI = int64_t(txNum);
             // we always add at the end and truncare at the end; this invariant should always hold
            largestTxNumSeen = std::max(txNumI - 1, int64_t{-1});
            saveLargestTxNumSeen();

            DebugM(__func__, ": txNum: ", txNum, ", nrecs: ", recs.size(), ", dels: ", dels, ", keeps: ", keeps, ", filts: ", filts,
                   ", elapsed: ", t0.msecStr(), " msec");
        }

        /// Returns a valid optional containing the TxNum of txHash if txHash is found in the db. A nullopt otherwise.
        /// May throw DatabaseError if there is a low-level deserialization error.
        std::optional<TxNum> find(const TxHash &txHash) const {
            std::optional<TxNum> ret;
            const auto key = makeKeyFromHash(txHash);
            auto optBytes = GenericDBGet<QByteArray>(db, key, true, dbName(), true, rdOpts);
            if (!optBytes) return ret; // missing
            auto span = Span<const char>{*optBytes};
            std::vector<uint64_t> txNums;
            txNums.reserve(1 + span.size() / 5); // rough heuristic
            try {
                while (!span.empty())
                    txNums.push_back(VarInt::deserialize(span).value<uint64_t>()); // this may throw
                if (UNLIKELY(txNums.empty())) throw DatabaseFormatError(QString("Missing data for txHash: ") + QString(txHash.toHex()));
                QString errStr;
                // we may get more than 1 txNum for a particular key, so examine them all
                const auto recs = rf->readRandomRecords(txNums, &errStr, true);
                if (UNLIKELY(recs.size() != txNums.size())) throw DatabaseError("Expected recs.size() == txNums.size()!");
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
            std::vector<std::string> dbResults;
            keySlices.reserve(hashes.size());
            // build keys
            for (const auto & hash : hashes)
                keySlices.push_back(ToSlice(makeKeyFromHash(hash))); // shallow view into bytes in hashes
            auto statuses = db->MultiGet(rdOpts, keySlices, &dbResults); // this should be faster than single gets..?
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
                if (!st.ok()) throw DatabaseError(dbName() + ": got a status that is not ok in findMany: "
                                                  + QString::fromStdString(st.ToString()));
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
            const auto recs = rf->readRandomRecords(recNums, &errStr, true);
            if (!errStr.isEmpty()) DebugM(__func__, ": ", errStr); // DEBUG TODO: Remove me
            if (UNLIKELY(recs.size() != recNums.size())) throw DatabaseError("Expected recs.size() == recNums.size()!");
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
            if (UNLIKELY(len != HashLen))
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
            auto opt = GenericDBGet<int64_t>(db, makeLargestTxNumSeenKey(), true, QString{}, false, rdOpts);
            if (opt && *opt >= 0) largestTxNumSeen = *opt;
            else largestTxNumSeen = -1;
        }
        void saveLargestTxNumSeen() const {
            const auto key = makeLargestTxNumSeenKey();
            if (largestTxNumSeen > -1)
                GenericDBPut(db, key, largestTxNumSeen, QString{}, wrOpts);
            else
                GenericDBDelete(db, key, QString{}, wrOpts);
        }
        // Deletes *all* keys from db! May throw.
        void deleteAllEntries() {
            std::string firstKey, endKey;
            {
                std::unique_ptr<rocksdb::Iterator> iter(db->NewIterator(rdOpts));
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
            rocksdb::FlushOptions fopts;
            fopts.wait = true; fopts.allow_write_stall = true;
            if (auto st = db->DeleteRange(wrOpts, db->DefaultColumnFamily(), firstKey, endKey);
                    !st.ok() || !(st = db->Flush(fopts)).ok())
                throw DatabaseError(dbName() + ": failed to delete all keys: " + QString::fromStdString(st.ToString()));
            std::unique_ptr<rocksdb::Iterator> iter(db->NewIterator(rdOpts));
            iter->SeekToFirst();
            if (iter->Valid())
                throw InternalError(dbName() + ": delete all keys failed -- iterator still points to a row! FIXME!");
            largestTxNumSeen = -1;
            saveLargestTxNumSeen();
        }

    public:
        // -- Utility / consistency check, etc ..

        void consistencyCheck() { // this throws if the checks fail
            const Tic t0;
            Log() << "CheckDB: Verifying txhash index (this may take some time) ...";
            std::unique_ptr<rocksdb::Iterator> iter(db->NewIterator(rdOpts));
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
                const auto recs = rf->readRandomRecords(batchNums, &err);
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
            const auto nrec = rf->numRecords();
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
            const auto nrec = rf->numRecords();
            std::vector<PreProcessedBlock::TxInfo> fakeInfos;
            for (size_t i = 0; i < nrec; /*i += batchSize*/) {
                if (UNLIKELY(0 == i % 100 && ourApp && ourApp->signalsCaught()))
                    throw UserInterrupted("User interrupted, aborting check"); // if the user hits Ctrl-C, stop the operation
                if (i && 0 == i % 1'000'000) {
                    const double pct = double(i) * 100. / nrec;
                    Log() << "Progress: " << QString::number(pct, 'f', 1) << "%, merge ops so far: " << mergeCount();
                }
                QString err;
                const auto recs = rf->readRecords(i, std::min<size_t>(batchSize, rf->numRecords() - i), &err);
                if (!err.isEmpty()) throw InternalError(QString("Got error from RecordFile: ") + err);
                // fake it
                fakeInfos.resize(recs.size());
                for (size_t j = 0; j < recs.size(); ++j)
                    fakeInfos[j].hash = recs[j];
                insertForBlock(i, fakeInfos); // this throws on error
                i += fakeInfos.size();
            }
            fakeInfos.clear();
            rocksdb::FlushOptions fopts;
            fopts.wait = true; fopts.allow_write_stall = true;
            if (auto st = db->Flush(fopts); !st.ok())
                Warning() << "DB Flush error: " << QString::fromStdString(st.ToString());
            Log() << "Indexed " << nrec << " txhash entries, elapsed: " << t0.secsStr(2) << " sec";
        }

        void consistencyCheckSlowRev() {
            Log() << "CheckDB: Verifying txhash index using the thorough reverse-check (this may take a long time) ...";
            const Tic t0;
            size_t i = 0, verified = 0;
            const auto nrec = rf->numRecords();
            constexpr size_t batchSize = 50'000;
            App *ourApp = app();
            for (i = 0; i < nrec; /*i += batchSize*/) {
                if (i && 0 == i % 100'000)
                    Log() << "Verified: " << verified << "/" << nrec << ", merge ops so far: " << mergeCount() << " ...";
                QString err;
                auto recs = rf->readRecords(i, batchSize, &err);
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
                    if (UNLIKELY(0 == i % 10 && ourApp && ourApp->signalsCaught()))
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

    constexpr int blockHeaderSize() { return BTC::GetBlockHeaderSize(); }

    /* NOTE: If taking multiple locks, all locks should be taken in the order they are declared, to avoid deadlocks. */

    Meta meta;
    RWLock metaLock;

    std::atomic<std::underlying_type_t<SaveItem>> pendingSaves{0};

    struct RocksDBs {
        const rocksdb::ReadOptions defReadOpts; ///< avoid creating this each time
        const rocksdb::WriteOptions defWriteOpts; ///< avoid creating this each time

        rocksdb::Options opts, shistOpts, txhash2txnumOpts;
        std::weak_ptr<rocksdb::Cache> blockCache; ///< shared across all dbs, caps total block cache size across all db instances
        std::weak_ptr<rocksdb::WriteBufferManager> writeBufferManager; ///< shared across all dbs, caps total memtable buffer size across all db instances

        std::shared_ptr<ConcatOperator> concatOperator, concatOperatorTxHash2TxNum;

        std::unique_ptr<rocksdb::DB> meta, blkinfo, utxoset,
                                     shist, shunspent, // scripthash_history and scripthash_unspent
                                     undo, // undo (reorg rewind)
                                     txhash2txnum; // new: index of txhash -> txNumsFile
        using DBPtrRef = std::tuple<std::unique_ptr<rocksdb::DB> &>;
        std::list<DBPtrRef> openDBs; ///< a bit of introspection to track which dbs are currently open (used by gentlyCloseAllDBs())

        std::unique_ptr<TxHash2TxNumMgr> txhash2txnumMgr; ///< provides a bit of a higher-level interface into the db

        /// One of these is alive if we are in an initial sync and user specified --fast-sync
        /// It caches UTXOs in memory and delays UTXO writes to DB so we don't have to do so much back-and-forth to
        /// rocksdb.
        std::unique_ptr<UTXOCache> utxoCache;
    };
    RocksDBs db;

    std::unique_ptr<RecordFile> txNumsFile;
    std::unique_ptr<RecordFile> headersFile;

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

    std::atomic<int64_t> utxoCt = 0;

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
};

namespace {
    /// returns a key that is hashX concatenated with the serializd ctxo -> size 40 or 41 byte vector
    /// Note hashX must be valid and sized HashLen otherwise this throws.
    QByteArray mkShunspentKey(const QByteArray & hashX, const CompactTXO &ctxo) {
        // we do it this way for performance:
        const int hxlen = hashX.length();
        if (UNLIKELY(hxlen != HashLen))
            throw InternalError(QString("mkShunspentKey -- scripthash is not exactly %1 bytes: %2").arg(HashLen).arg(QString(hashX.toHex())));
        QByteArray key(hxlen + int(ctxo.serializedSize(false /* no force wide */)), Qt::Uninitialized);
        std::memcpy(key.data(), hashX.constData(), size_t(hxlen));
        ctxo.toBytesInPlace(reinterpret_cast<std::byte *>(key.data()+hxlen), ctxo.serializedSize(false), false /* no force wide */);
        return key;
    }
    /// throws if key is not the correct size (must be exactly 40 or 41 bytes)
    CompactTXO extractCompactTXOFromShunspentKey(const rocksdb::Slice &key) {
        static const auto ExtractHashXHex = [](const rocksdb::Slice &key) -> QString {
            if (key.size() >= HashLen)
                return QString(FromSlice(key).left(HashLen).toHex());
            else
                return "<undecipherable scripthash>";
        };
        if (const auto ksz = key.size();
                UNLIKELY(ksz != HashLen + CompactTXO::minSize() && ksz != HashLen + CompactTXO::maxSize()))
            // should never happen, indicates db corruption
            throw InternalError(QString("Key size for scripthash %1 is invalid").arg(ExtractHashXHex(key)));
        static_assert (sizeof(*key.data()) == 1, "Assumption is rocksdb::Slice is basically a byte vector");
        const CompactTXO ctxo =
            CompactTXO::fromBytesInPlaceExactSizeRequired(reinterpret_cast<const std::byte *>(key.data()) + HashLen,
                                                          key.size() - HashLen);
        if (UNLIKELY(!ctxo.isValid()))
            // should never happen, indicates db corruption
            throw InternalError(QString("Deserialized CompactTXO is invalid for scripthash %1").arg(ExtractHashXHex(key)));
        return ctxo;
    }
    std::pair<HashX, CompactTXO> extractShunspentKey(const rocksdb::Slice & key) {
        const CompactTXO ctxo = extractCompactTXOFromShunspentKey(key); // throws if wrong size
        return {DeepCpy(key.data(), HashLen), ctxo}; // if we get here size ok, can extract HashX
    }
} // namespace

class Storage::UTXOCache
{
    using Node = std::pair<TXO, TXOInfo>;
    using NodeList = std::list<Node>;
    using TXORef = std::reference_wrapper<const TXO>; /* ref always to a Node in NodeList */
    struct TableHasherAndEq {
        bool operator()(const TXO &a, const TXO &b) const noexcept { return a == b; }
        size_t operator()(const TXO &t) const noexcept { return std::hash<TXO>{}(t); }
    };
    using Table = robin_hood::unordered_flat_map<TXORef, NodeList::iterator, TableHasherAndEq, TableHasherAndEq>;
    struct ItSetHasher {
        size_t operator()(NodeList::iterator it) const noexcept { return std::hash<TXO>{}(it->first); }
    };
    using ItSet = robin_hood::unordered_flat_set<NodeList::iterator, ItSetHasher>;
    using RmVec = std::vector<TXO>;

    NodeList ordering;
    Table utxos; //< points to Nodes in `ordering`
    ItSet adds; ///< entries in above NodeList that are new and are not in the DB yet
    RmVec rms; ///< queued deletions, not yet deleted from DB

    static_assert (std::is_same_v<decltype(std::declval<TXO>().txHash), QByteArray>
                   && std::is_same_v<decltype(std::declval<TXOInfo>().hashX), QByteArray>,
                   "Below assumes we are using QByteArray");
    static constexpr size_t EntrySize = sizeof(NodeList::value_type) + sizeof(Table::value_type)
                                        + (HashLen + Util::qByteArrayPvtDataSize()) * size_t{2U} // account for txHash and hashX
                                        + sizeof(void *) * size_t{2U} /* account for list node next/prev ptrs */;
    static constexpr size_t ItSetItemSize = sizeof(ItSet::value_type);
    static constexpr size_t RmVecItemSize = sizeof(RmVec::value_type) + HashLen + Util::qByteArrayPvtDataSize();

    using ShunspentKey = QByteArray;
    using ShunspentValue = QByteArray;
    struct ShunspentKeyHasher {
        size_t operator()(const ShunspentKey & k) const noexcept { return Util::hashForStd(static_cast<ByteView>(k)); }
    };
    using ShunspentTable = robin_hood::unordered_flat_map<ShunspentKey, ShunspentValue, ShunspentKeyHasher>;
    using ShunspentRmVec = std::vector<ShunspentKey>;

    ShunspentTable shunspentAdds; ///< queued additions, not yet added to DB
    ShunspentRmVec shunspentRms; ///< queued deletions, not yet deleted from DB

    static constexpr size_t ShunspentTableNodeSize = sizeof(ShunspentTable::value_type) + HashLen + CompactTXO::minSize()
                                                     + Util::qByteArrayPvtDataSize()*size_t{2u} + sizeof(int64_t); // not guaranteed accurate: doesn't take possible tokenData serialization into account
    static constexpr size_t ShunspentRmVecNodeSize = sizeof(ShunspentRmVec::value_type) + HashLen + CompactTXO::minSize()
                                                     + Util::qByteArrayPvtDataSize();

    static constexpr size_t memUsageForSizes(size_t utxosSize, size_t addsSize, size_t rmsSize,
                                             size_t shunspentAddsSize,size_t  shunspentRmsSize) noexcept {
        return utxosSize * EntrySize + addsSize * ItSetItemSize + rmsSize * RmVecItemSize
                + shunspentAddsSize * ShunspentTableNodeSize + shunspentRmsSize * ShunspentRmVecNodeSize;
    }

    static constexpr bool CHECK_SANITY = false; ///< enable this for extra sanity checks (slightly slows down the cache)

    /// When put() is called but the prefetcher is active, the put() calls are deferred here and the actual add()s will
    /// happen when the prefetcher is done. This is a NodeList so it can be quickly spliced into the `ordering` list.
    NodeList deferredAdds;

    void do_flush(const size_t memUsageTarget = 0, std::vector<NodeList::iterator> * const optAddsOrder = nullptr) {
        if (UNLIKELY(prefetcherFut.future.valid())) {
            // paranoia: wait for prefetcher to end if it was running
            // this branch can only be taken in stack-unwinding and/or "exception"-al circumstances
            Warning() << name << ": Prefetcher was active when " << __func__ << " was called. Waiting for prefetch to complete ...";
            prefetcherFut.future.wait();
        }
        const size_t us = utxos.size(), as = adds.size(), rs = rms.size(), sas = shunspentAdds.size(), srs = shunspentRms.size();
        if (memUsageForSizes(us, as, rs, sas, srs) < memUsageTarget)
             return;  // nothing to do!
        Log() << name <<  ": Flushing to DB ...";
        if (as + rs == 0u || (memUsageTarget && memUsageForSizes(us, as, rs, 0, 0) <= memUsageTarget)) {
            // flush to the shunspents since we prefer to evict those over the utxos
            const bool doAdds = !memUsageTarget || memUsageForSizes(us, as, rs, sas, 0) > memUsageTarget; // we prefer rms over adds
            do_shunspent_flush(doAdds, memUsageTarget, [this]{ return memUsage(); });
        } else {
            bool doAdds = true, doShAdds = true;
            // we prefer rms over adds, so try to optimize to do rms only if we can
            if (memUsageTarget) {
                if (memUsageForSizes(us, as, 0, sas, 0) <= memUsageTarget) {
                    doAdds = doShAdds = false;
                } else if (memUsageForSizes(us, 0, 0, sas, 0) <= memUsageTarget) {
                    doShAdds = false;
                } else if (memUsageForSizes(us, as, 0, 0, 0) <= memUsageTarget) {
                    doAdds = false;
                }
            }
            do_parallel_flush(doAdds, doShAdds, memUsageTarget, optAddsOrder);
        }
    }
    static constexpr size_t batchSize = 100'000;  // to limit the memory used for batching, we limit the batch size
    static void commitBatch(rocksdb::DB *db, rocksdb::WriteBatch &batch, const QString &errMsg,
                            const rocksdb::WriteOptions &writeOpts, size_t &batchCount) {
        const Tic t;
        GenericBatchWrite(db, batch, errMsg, writeOpts); // may throw
        batch.Clear();
        if (t.msec<int>() >= 200) {
            const auto ct = batchCount;
            DebugM("batch write of ", ct, " ", DBName(db), Util::Pluralize(" item", ct), " took ", t.msecStr(), " msec");
        }
        batchCount = 0;
    }
    void do_parallel_flush(bool doAdds, bool doShunspentAdds, const size_t memUsageTarget,
                           std::vector<NodeList::iterator> * const optAddsOrder) {
        const Tic t0;
        size_t addCt = 0, rmCt = 0;
        rocksdb::WriteBatch batch;

        const size_t utxosSize = utxos.size();
        std::atomic_size_t addsSize = adds.size(), rmsSize = rms.size(),
                           shunspentAddsSize = shunspentAdds.size(), shunspentRmsSize = shunspentRms.size();
        auto threadSafeMemUsage = [&] {
            return memUsageForSizes(utxosSize, addsSize, rmsSize, shunspentAddsSize, shunspentRmsSize);
        };

        // do scripthash_unspent first in a CoTask thread, since those are "cheaper" and don't require us to read them
        // back from DB, so they can be evicted first
        std::optional<Defer<>> d1;
        if ((doShunspentAdds && !shunspentAdds.empty()) || !shunspentRms.empty()) {
            flusherShunspentFut = flusherShunspent.submitWork([&]{
                do_shunspent_flush(doShunspentAdds, memUsageTarget, threadSafeMemUsage, &shunspentRmsSize, &shunspentAddsSize);
            });
            // This is here if an exception was thrown, to properly clean up the parallel task that is pointing
            // to variables on the stack frame.
            d1.emplace([this]{
                if (flusherShunspentFut.future.valid()) {
                    // Catch all exceptions here to avoid double-exceptions on stack unwinding
                    QString what;
                    try {
                        flusherShunspentFut.future.get();
                        return;
                    } catch (const std::exception & e) { what = e.what(); } catch (...) { what = "Unknown exception"; }
                    Error() << "Exception caught waiting for future for task: " << flusherShunspent.name << ": " << what;
                }
            });
        }

        // do utxos in this thread since it's otherwise going to block anyway
        if ((doAdds && !adds.empty()) || !rms.empty()) {
            static const QString errMsgBatchWrite("Error issuing batch write to utxoset db for a utxo update");
            if (!db) throw InternalError("utxoset db is nullptr! FIXME!");
            size_t batchCount = 0;
            // rms first (loop in reverse to shrink vector as we loop)
            for (size_t i = rms.size(); i-- > 0; /**/) {
                if (memUsageTarget && threadSafeMemUsage() <= memUsageTarget)
                    break; // abort loop early
                // enqueue delete from utxoset db -- may throw.
                static const QString errMsgPrefix("Failed to issue a batch delete for a utxo");
                const auto & txo = rms[i];
                GenericBatchDelete(batch, txo, errMsgPrefix); // may throw on failure
                rms.resize(i);
                --rmsSize;
                ++rmCt;
                if (++batchCount >= batchSize)
                    commitBatch(db.get(), batch, errMsgBatchWrite, writeOpts, batchCount);
            }

            // next, adds
            if (doAdds) {
                if (optAddsOrder) {
                    // caller specified an order for adds that they prefer for deletion
                    auto & order = *optAddsOrder;
                    for (const auto oit : order) {
                        if (memUsageTarget && threadSafeMemUsage() <= memUsageTarget)
                            break; // abort loop early
                        if (auto it = adds.find(oit); it != adds.end()) {
                            // Update db utxoset, keyed off txo -> txoinfo
                            {
                                static const QString errMsgPrefix("Failed to add a utxo to the utxo batch");
                                const auto & [txo, info] = **it;
                                GenericBatchPut(batch, txo, info, errMsgPrefix); // may throw on failure
                            }
                            it = adds.erase(it);
                            --addsSize;
                            ++addCt;
                            if (++batchCount >= batchSize)
                                commitBatch(db.get(), batch, errMsgBatchWrite, writeOpts, batchCount);
                        }
                    }
                    order.clear(); order.shrink_to_fit();
                } else {
                    // no order specified, just iterate in "random" order of the hash set
                    for (auto it = adds.begin(); it != adds.end(); /**/) {
                        if (memUsageTarget && threadSafeMemUsage() <= memUsageTarget)
                            break; // abort loop early
                        // Update db utxoset, keyed off txo -> txoinfo
                        {
                            static const QString errMsgPrefix("Failed to add a utxo to the utxo batch");
                            const auto & [txo, info] = **it;
                            GenericBatchPut(batch, txo, info, errMsgPrefix); // may throw on failure
                        }
                        it = adds.erase(it);
                        --addsSize;
                        ++addCt;
                        if (++batchCount >= batchSize)
                            commitBatch(db.get(), batch, errMsgBatchWrite, writeOpts, batchCount);
                    }
                }
            }
            if (batchCount) commitBatch(db.get(), batch, errMsgBatchWrite, writeOpts, batchCount);
        } else {
            if (optAddsOrder) { optAddsOrder->clear(); optAddsOrder->shrink_to_fit(); }
        }

        if (flusherShunspentFut.future.valid()) flusherShunspentFut.future.get(); // may throw it task threw

        if (t0.msec<int>() >= 50)
            DebugM(__func__, ": added ", addCt, " and deleted ", rmCt, Util::Pluralize(" utxo", addCt + rmCt),
                   " in ", t0.msecStr(3), " msec");
    }
    template <typename Func>
    void do_shunspent_flush(bool doAdds, const size_t memUsageTarget, const Func &getMemUsage,
                            std::atomic_size_t * shunspentRmsSize = nullptr,
                            std::atomic_size_t * shunspentAddsSize = nullptr) {
        const Tic t0;
        size_t shunspentAddCt = 0, shunspentRmCt = 0;
        rocksdb::WriteBatch shunspentBatch;

        static const QString errMsgBatchWrite("Error issuing batch write to scripthash_unspent db for a shunspent update");
        if (!shunspentdb) throw InternalError("scripthash_unspent db is nullptr! FIXME!");
        size_t batchCount = 0;

        // shunspentRms first (loop in reverse so we can shrink vector as we loop)
        for (size_t i = shunspentRms.size(); i-- > 0; /**/) {
            if (memUsageTarget && getMemUsage() <= memUsageTarget)
                break; // abort loop early
            const auto & dbKey = shunspentRms[i];
            // enqueue delete from scripthash_unspent db -- may throw.
            static const QString errMsgPrefix("Failed to issue a batch delete for a shunspent item");
            GenericBatchDelete(shunspentBatch, dbKey, errMsgPrefix);
            shunspentRms.resize(i);
            ++shunspentRmCt;
            if (shunspentRmsSize) --*shunspentRmsSize;
            if (++batchCount >= batchSize)
                commitBatch(shunspentdb.get(), shunspentBatch, errMsgBatchWrite, writeOpts, batchCount);
        }

        // next, shunspentAdds
        if (doAdds) {
            for (auto it = shunspentAdds.begin(); it != shunspentAdds.end(); /**/) {
                if (memUsageTarget && getMemUsage() <= memUsageTarget)
                    break; // abort loop early
                // Update db scripthash_unspent, keyed off hashX|ctxo
                {
                    static const QString errMsgPrefix("Failed to add an item to the shunspent batch");
                    const auto & [dbkey, dbvalue] = *it;
                    GenericBatchPut(shunspentBatch, dbkey, dbvalue, errMsgPrefix); // may throw on failure
                }
                it = shunspentAdds.erase(it);
                ++shunspentAddCt;
                if (shunspentAddsSize) --*shunspentAddsSize;
                if (++batchCount >= batchSize)
                    commitBatch(shunspentdb.get(), shunspentBatch, errMsgBatchWrite, writeOpts, batchCount);
            }
        }

        if (batchCount) commitBatch(shunspentdb.get(), shunspentBatch, errMsgBatchWrite, writeOpts, batchCount);
        if (t0.msec<int>() >= 50)
            DebugM(__func__, ": added ", shunspentAddCt, " and deleted ", shunspentRmCt,
                   Util::Pluralize(" shunspent", shunspentAddCt + shunspentRmCt), " in ", t0.msecStr(3), " msec");
    }

    void do_limitSize(const size_t bytes, const unsigned tryCt = 0) {
        // prune oldest first that are not in `adds`, then flush if still over limit
        // hopefully this reduces disk I/O for recent short-lived UTXOs over the above approach.
        size_t m = memUsage();
        if (m <= bytes) return;
        const Tic t0;
        DebugM(name, ": limiting size to ", bytes, ", current size: ", m);
        size_t iters = 0, deletions = 0;
        std::vector<NodeList::iterator> addsOrder;
        addsOrder.reserve(adds.size());
        const bool definitelyNotInAdds = adds.empty(), definitelyInAdds = ordering.size() == adds.size();
        for (auto oit = ordering.begin(); m > bytes && oit != ordering.end(); ++iters) {
            if (!definitelyInAdds && (definitelyNotInAdds || adds.count(oit) == 0)) {
                // only erase cached UTXOs that exist in DB and are not in "add" set
                utxos.erase(oit->first);
                oit = ordering.erase(oit);
                ++deletions;
                m = memUsage();
            } else {
                // remember the ordering encountered since do_flush will use this information to save "oldest first" to DB
                addsOrder.push_back(oit++);
            }
        }
        auto PrintStats = [&] {
            DebugM(name, ": (", tryCt , ") iters: ", iters, ", deletions: ", deletions, ", utxos left: ", utxos.size(),
                   ", elapsed: ", t0.msecStr(), " msec",
                   "; sizes - adds: ", adds.size(), ", rms: ", rms.size(), ", shunspentAdds: ", shunspentAdds.size(),
                   ", shunspentRms: ", shunspentRms.size(), ", memUsage: ", QString::number(memUsage()/1000.0/1000.0, 'f', 3), " MB");
        };
        if (m > bytes) {
            DebugM(name, ": after ", iters, " iters and ", deletions, " deletions, size is still over limit (",
                   m, " > ", bytes, "), doing limited flush now ...");
            do_flush(bytes, &addsOrder);
            m = memUsage();
            if (m > bytes) {
                // memusage still high, try again, this time do_flush should reap more
                DebugM(name, ": memUsage (", m, ") is still above threshold, calling ", __func__, " again ...");
                PrintStats();
                do_limitSize(bytes, tryCt + 1U);
                return;
            }
        }
        PrintStats();
    }

    /// Used to splice in the previously-populated `deferredAdds`, called by `waitForPrefetchToComplete()`
    void addAllDeferred() {
        if (deferredAdds.empty()) return;
        const Tic t0;
        const size_t n = deferredAdds.size();
        ordering.splice(ordering.end(), deferredAdds);
        auto it = ordering.end();
        for (size_t i = 0; i < n; ++i)
            link_node(--it, true /* isNotInDbYet - always `true` otherwise we wouldn't be here! */);
        if (t0.msec<int>() >= 50 || n >= 20000)
            DebugM(__func__, ": added ", n, Util::Pluralize(" UTXO", n), " to hashmap in ", t0.msecStr(), " msec");
    }

    template<typename ...Args>
    void add(bool isNotInDBYet, Args && ...args) {
        // to prevent UB, should add in this order
        // 1. add to `ordering` list first
        // 2. then add to `utxos` and possibly `adds`
        ordering.emplace_back(std::forward<Args>(args)...);
        auto it = ordering.end();
        link_node(--it, isNotInDBYet);
    }

    /// Associates a freshly created `ordering` item with the `utxos` table and possibly the `adds` set.
    /// Precondition: `it` must be a valid iterator in the `ordering` NodeList
    void link_node(const NodeList::iterator it, bool isNotInDBYet) {
        const auto & txo = it->first; // `txo` here must be a reference to the above-inserted node
        {
            const auto & [tit, inserted] = utxos.try_emplace(txo /* txoref to Node in `ordering` */, it);
            if (UNLIKELY(!inserted)) {
                // already there! this can happen on mainnet due to dupe txos pre-BIP34 (two txos are like this on mainnet only)
                DebugM(__func__, ": WARNING dupe txo encountered: [", it->first.toString(), ", ", it->second.confirmedHeight.value_or(0),
                       "] vs [", tit->second->first.toString(), ", ", tit->second->second.confirmedHeight.value_or(0), "]");
                // we must emulate the behavior of previous code (before UTXOCache) which would overwrite existing
                const auto oit = tit->second;
                adds.erase(oit);
                utxos.erase(tit);
                ordering.erase(oit);
                const auto & [tit2, inserted2] = utxos.try_emplace(txo, it);
                if (UNLIKELY(!inserted2)) /* paranoia */
                    throw InternalError("Tried overwriting existing TXO in cache but failed! THIS SHOULD NEVER HAPPEN!");
            }
        }
        // NOTE: Assumption is that this txo was not in `rms`.  On mainnet the dupe txos are unspent
        //       between the 2 times they appear, so this assumption holds, and since BIP34 has been
        //       activated, it will always hold, since only 1 of them can ever be spent in the future.

        if (isNotInDBYet) {
            adds.insert(it);
        } else {
            // This branch may be taken on prefetch or on cache miss, which can happen if the UTXOCache is too small on
            // a small memory system).
            // Note: It was determined this check is not needed.  Re-enable this check if we modify the code
            //       significantly, as a sanity/testing check.
            if constexpr (CHECK_SANITY) {
                if (const auto ait = adds.find(it); ait != adds.end()) {
                    Warning() << __func__ << ": WARNING added txo " << txo.toString() << " as \"isNotInDbYet = false\","
                              << " but it was already in `adds` (which presumes \"isNotInDbYet = true\"!"
                              << " INVARIANT VIOLATED! FIXME!";
                    adds.erase(ait);
                }
            }
        }
    }

    void addShunspent(const ShunspentKey &k, const ShunspentValue &v) {
        const auto & [it, inserted] = shunspentAdds.emplace(k, v);
        if (UNLIKELY(!inserted)) {
            // Already there! Paranoia check here ... it turns out even in pre-BIP34 txns, this cannot happen
            // because we uniquely identify txns by unique id number, so dupe tx-hash's (as was possible pre-BIP34)
            // cannot trigger this branch.  This branch is here strictly for paranoia.
            Warning() << __func__ << ": WARNING dupe txo encountered with key: \"" << it->first.toHex() << "\" [val1: "
                      << it->second.toHex() << " val2: " << v.toHex() << "], overwriting existing with val2.";
            it->second = v; // overwrite existing to preserve behavior of pre-UTXOCache code.
        }
        // NOTE: Assumption is that an add will never add a shunspent key that is in the shunspentRms vector.
        // (this is not checked for performance.)
    }

    bool rm(const TXO &txo) {
        bool ret = false;
        bool wasInAdds = false;
        if (auto it = utxos.find(txo); it != utxos.end()) {
            if (auto ait = adds.find(it->second); ait != adds.end()) {
                wasInAdds = true;
                utxoDbOpsSaved += 3; // we saved an add, a read, and a delete here!
                adds.erase(ait);
            }
            // to prevent UB, should erase in this order (with `ordering` entries always being erased last!)
            const auto oit = it->second;
            utxos.erase(it);
            ordering.erase(oit);
            ret = true;
        }
        if (!wasInAdds) rms.push_back(txo);
        return ret;
    }

    bool rmShunspent(ShunspentKey && k) {
        if (auto it = shunspentAdds.find(k); it != shunspentAdds.end()) {
            shunspentAdds.erase(it);
            shunspentDbOpsSaved += 2; // we saved an add then a delete here!
            return true;
        } else
            shunspentRms.push_back(std::move(k));
        return false;
    }

    bool contains(const TXO & t) const { return utxos.find(t) != utxos.end(); }

    std::optional<TXOInfo> get_from_cache(const TXO & t) const {
        if (const auto it = utxos.find(t); it != utxos.end())
            return it->second->second;
        return std::nullopt;
    }

    const QString name;
    CoTask prefetcher, flusherShunspent;
    CoTask::Future prefetcherFut, flusherShunspentFut;

    const std::unique_ptr<rocksdb::DB> & db, & shunspentdb;
    const rocksdb::ReadOptions & readOpts;
    const rocksdb::WriteOptions & writeOpts;

    // persistent data structures we use in order to avoid having to continually re-reserve memory
    struct PFData {
        std::vector<rocksdb::Slice> keys;
        std::vector<QByteArray> keyData;
        std::vector<rocksdb::PinnableSlice> values;
        std::vector<rocksdb::Status> statuses;
        robin_hood::unordered_flat_map<unsigned, TXO> index2TXO;
    } pf;

    void do_prefetch(PreProcessedBlockPtr ppb) {
        // Below call to subitWork will throw std::domain_error if we are being called while the prefetcher is still
        // active ... which is what we want here, because it indicates a programming error.
        prefetcherFut = prefetcher.submitWork([this, ppb]{
            const Tic t0;
            size_t num_ok = 0;
            Defer d([&t0, &num_ok]{
                if (t0.msec<int>() >= 50)
                    DebugM("Fetched ", num_ok, " UTXOs from DB in ", t0.msecStr(3), " msec");
            });

            std::vector<rocksdb::Slice> & keys = pf.keys;
            std::vector<QByteArray> & keyData = pf.keyData;
            std::vector<rocksdb::PinnableSlice> & values = pf.values;
            std::vector<rocksdb::Status> & statuses = pf.statuses;
            robin_hood::unordered_flat_map<unsigned, TXO> & index2TXO = pf.index2TXO;
            Defer d2([&]{
                index2TXO.clear();
                keys.clear();
                keyData.clear();
                values.clear();
                statuses.clear();
            });
            {
                unsigned inum = 0;
                for (const auto & in : std::as_const(ppb->inputs)) {
                    if (!inum) { /* coinbase, skip */ }
                    else if (in.parentTxOutIdx.has_value()) { /* spent in this block, skip */ }
                    else if (TXO t{in.prevoutHash, in.prevoutN}; !contains(t)) {
                        ++cacheMisses;
                        const unsigned index = keys.size();
                        const TXO & txo = index2TXO.try_emplace(index, std::move(t)).first->second;
                        keyData.push_back(Serialize(txo));
                        const auto & ser = keyData.back();
                        keys.emplace_back(ser.constData(), size_t(ser.size()));
                        values.emplace_back();
                        statuses.emplace_back();
                    } else
                        ++cacheHits;
                    ++inum;
                }
            }
            if (keys.empty()) return; // nothing to do!
            auto * const colfam = db->DefaultColumnFamily();
            db->MultiGet(readOpts, colfam, keys.size(), keys.data(), values.data(), statuses.data());
            {
                unsigned index = 0;
                for (const auto & s : statuses) {
                    TXO & txo = index2TXO[index];
                    if (s.ok()) {
                        bool ok;
                        TXOInfo info = Deserialize<TXOInfo>(FromSlice(values[index]), &ok);
                        if (!ok) throw DatabaseSerializationError(QString("%1: Failed to deserialize TXOInfo for TXO \"%2\"")
                                                                  .arg(name, txo.toString()));
                        else {
                            add(false, std::move(txo), std::move(info));
                            ++num_ok;
                        }
                    } else {
                        throw DatabaseError(QString("%1: Error reading TXO \"%2\" from %3 db: %4")
                                            .arg(name, txo.toString(), DBName(db.get()), StatusString(s)));
                    }
                    ++index;
                }
            }
        });
    }

public:
    UTXOCache(const QString &name, const std::unique_ptr<rocksdb::DB> & pdb,
              const std::unique_ptr<rocksdb::DB> & pshunspentdb, const rocksdb::ReadOptions & readOpts,
              const rocksdb::WriteOptions & writeOpts)
        : name{name}, prefetcher{name + ".Prefetcher"}, flusherShunspent{name + ".ShunspentFlusher"},
          db{pdb}, shunspentdb{pshunspentdb}, readOpts{readOpts}, writeOpts{writeOpts} {
        DebugM(name, ": created");
    }

    ~UTXOCache() {
        DebugM(name, ": ", __func__, " - stats - cache hits: ", cacheHits, ", cache misses: ", cacheMisses,
               ", utxoDbOpsSaved: ", utxoDbOpsSaved, ", shunspentDbOpsSaved: ", shunspentDbOpsSaved);
        do_flush();
    }

    void reserve(size_t hashMaps, size_t vectors) {
        utxos.reserve(hashMaps);
        adds.reserve(hashMaps);
        rms.reserve(vectors);
        shunspentAdds.reserve(hashMaps);
        shunspentRms.reserve(vectors);
    }

    /// Figures out the best capacity to reserve based on a desired memory size.
    void autoReserve(size_t memoryBytes) {
        constexpr auto perEntryEstimatedCost = EntrySize + ShunspentTableNodeSize + ItSetItemSize; // ~280 on 64 bit
        static_assert (perEntryEstimatedCost > 0);
        reserve(memoryBytes / perEntryEstimatedCost, // about 3.6 million per GB of memory
                1u << 15 /* ~32,000 reserve for vectors */);
    }

    void shrink_to_fit() {
        utxos.rehash(0);
        adds.rehash(0);
        rms.shrink_to_fit();
        shunspentAdds.rehash(0);
        shunspentRms.shrink_to_fit();
    }

    /// Returns the estimated dynamic memory usage, in bytes
    size_t memUsage() const {
        return memUsageForSizes(utxos.size(), adds.size(), rms.size(), shunspentAdds.size(), shunspentRms.size());
    }

    /// NB: no locks on ppb are used for now. While this is alive ppb->inputs must not be mutated
    /// NB2: call waitForPrefetchToComplete() after this is called sometime later.
    /// Precondition: prefetcher must *not* already be running. If it is, this will throw std::domain_error.
    void prefetch(const PreProcessedBlockPtr & ppb) { do_prefetch(ppb); }

    /// May throw if the underlying CoTask work unit threw.
    /// This is called by Storage::addBlock before we need to get and/or add UTXOs to the cache.
    void waitForPrefetchToComplete() {
        if (prefetcherFut.future.valid())
            prefetcherFut.future.get();

        // do any deferred adds now that the prefetcher is done/inactive
        addAllDeferred();
    }

    size_t cacheMisses = 0, cacheHits = 0, utxoDbOpsSaved = 0, shunspentDbOpsSaved = 0;

    /// Get a UTXO from the cache. Will return a null optional if the requested TXO was not in the cache.
    /// Does not fall-back to looking in the DB. Caller should explicitly call utxoGetFromDB() themselves
    /// for that purpose. Note: this currently takes no locks. Assumption is calling code is locking
    /// things correctly. (This function is currently called only inside Storage::addBlock.)
    /// Precondition: prefetcher must not be running.
    std::optional<TXOInfo> get(const TXO & txo) {
        std::optional<TXOInfo> ret = get_from_cache(txo);
        if (!ret)
            ++cacheMisses;
        else
            ++cacheHits;
        return ret;
    }

    /// Add a TXO <-> TXOInfo pair to the cache and enqueue it for writing to DB.  It will be written to the DB the
    /// next time we flush.
    /// Precondition: TXO is not yet in the DB and should be added to the DB.
    bool put(const TXO & txo, const TXOInfo & info) {
        if (prefetcherFut.future.valid()) {
            // Prefetcher is busy, can't touch the data structures it is modifying now. Defer this until later.
            deferredAdds.emplace_back(txo, info);
            return false;
        }
        add(true, txo, info);
        return true;
    }

    bool remove(const TXO & txo) { return rm(txo); }

    void putShunspent(const ShunspentKey &key, const ShunspentValue &val) { addShunspent(key, val); }
    bool removeShunspent(const HashX & hashX, const CompactTXO & ctxo) { return rmShunspent(mkShunspentKey(hashX, ctxo)); }

    void flush() { do_flush(); }

    /// Limit dynamic memory usage to `bytes`. May implicitly write to DB to flush.
    /// Precondition: Prefetcher must not be running (this is not checked)
    void limitSize(size_t bytes) { do_limitSize(bytes); }
}; // class Storage::UTXOCache


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
static const char* rocksdb_build_git_sha = "unk"; // this doesn't exist on rocksdb > 6.17.3
#else
extern const char* rocksdb_build_git_sha; // internal to rocksdb lib -- if this breaks remove me
#endif
/* static */
QString Storage::rocksdbVersion()
{
    QString sha(rocksdb_build_git_sha);
    // rocksdb git commit sha: try and pop off the front part, and keep the rest and take the first 7 characters of that
    if (auto l = sha.split(':'); l.size() == 2) // must match what we expect otherwise don't truncate
        sha = l.back().left(7);
    return QString("%1.%2.%3-%4").arg(ROCKSDB_MAJOR).arg(ROCKSDB_MINOR).arg(ROCKSDB_PATCH).arg(sha);
}

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

    {   // open all db's ...
        p->db.utxoCache.reset(); // this should already be nullptr, but this reset() is just here to be defensive.

        // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
        rocksdb::Options & opts(p->db.opts), &shistOpts(p->db.shistOpts), &txhash2txnumOpts(p->db.txhash2txnumOpts);
        opts.IncreaseParallelism(int(Util::getNPhysicalProcessors()));
        opts.OptimizeLevelStyleCompaction();

        // setup shared block cache
        rocksdb::BlockBasedTableOptions tableOptions;
        tableOptions.block_cache = rocksdb::NewLRUCache(options->db.maxMem /* capacity limit */, -1, false /* strict capacity limit=off, turning it on made db writes sometimes fail */);
        p->db.blockCache = tableOptions.block_cache; // save shared_ptr to weak_ptr
        tableOptions.cache_index_and_filter_blocks = true; // from the docs: this may be a large consumer of memory, cost & cap its memory usage to the cache
        std::shared_ptr<rocksdb::TableFactory> tableFactory{rocksdb::NewBlockBasedTableFactory(tableOptions)};
        // shared TableFactory for all db instances
        opts.table_factory = tableFactory;

        // setup shared write buffer manager (for memtables memory budgeting)
        // - TODO cost this to the cache here? Or not? make sure both together don't exceed db.maxMem?!
        // - TODO right now we fix the cap of the write buffer manager's buffer size at db.maxMem / 2; tweak this.
        auto writeBufferManager = std::make_shared<rocksdb::WriteBufferManager>(options->db.maxMem / 2, tableOptions.block_cache /* cost to block cache: hopefully this caps memory better? it appears to use locks though so many this will be slow?! TODO: experiment with and without this!! */);
        p->db.writeBufferManager = writeBufferManager; // save shared_ptr to weak_ptr
        opts.write_buffer_manager = writeBufferManager; // will be shared across all DB instances

        // create the DB if it's not already present
        opts.create_if_missing = true;
        opts.error_if_exists = false;
        opts.max_open_files = options->db.maxOpenFiles <= 0 ? -1 : options->db.maxOpenFiles; ///< this affects memory usage see: https://github.com/facebook/rocksdb/issues/4112
        opts.keep_log_file_num = options->db.keepLogFileNum;
        opts.compression = rocksdb::CompressionType::kNoCompression; // for now we test without compression. TODO: characterize what is fastest and best..
        opts.use_fsync = options->db.useFsync; // the false default is perfectly safe, but Jt asked for this as an option, so here it is.

        shistOpts = opts; // copy what we just did (will implicitly copy over the shared table_factory and write_buffer_manager)
        shistOpts.merge_operator = p->db.concatOperator = std::make_shared<ConcatOperator>(); // this set of options uses the concat merge operator (we use this to append to history entries in the db)

        txhash2txnumOpts = opts;
        txhash2txnumOpts.merge_operator = p->db.concatOperatorTxHash2TxNum = std::make_shared<ConcatOperator>();


        using DBInfoTup = std::tuple<QString, std::unique_ptr<rocksdb::DB> &, const rocksdb::Options &, double>;
        const std::list<DBInfoTup> dbs2open = {
            { "meta", p->db.meta, opts, 0.0005 },
            { "blkinfo" , p->db.blkinfo , opts, 0.02 },
            { "utxoset", p->db.utxoset, opts, 0.27 },
            { "scripthash_history", p->db.shist, shistOpts, 0.30 },
            { "scripthash_unspent", p->db.shunspent, opts, 0.27 },
            { "undo", p->db.undo, opts, 0.0395 },
            { "txhash2txnum", p->db.txhash2txnum, txhash2txnumOpts, 0.1 },
        };
        std::size_t memTotal = 0;
        const auto OpenDB = [this, &memTotal](const DBInfoTup &tup) {
            auto & [name, uptr, opts_in, memFactor] = tup;
            rocksdb::Options opts = opts_in;
            const size_t mem = std::max(size_t(options->db.maxMem * memFactor), size_t(64*1024));
            Debug() << "DB \"" << name << "\" mem: " << QString::number(mem / 1024. / 1024., 'f', 2) << " MiB";
            opts.OptimizeLevelStyleCompaction(mem);
            for (auto & comp : opts.compression_per_level)
                comp = rocksdb::CompressionType::kNoCompression; // paranoia -- enforce no compression since our data compresses so poorly
            memTotal += mem;
            rocksdb::Status s;
            // try and open database
            const QString path = options->datadir + QDir::separator() + name;
            std::unique_ptr<rocksdb::DB> tmpPtr;
            {
                // open db, immediately placing the new'd pointer (if any) into a unique_ptr
                rocksdb::DB *db = nullptr;
                s = rocksdb::DB::Open( opts, path.toStdString(), &db);
                tmpPtr.reset(db);
            }
            if (!s.ok() || !tmpPtr)
                throw DatabaseError(QString("Error opening %1 database: %2 (path: %3)")
                                    .arg(name, StatusString(s), path));
            uptr = std::move(tmpPtr); // everything ok, move tmpPtr
            p->db.openDBs.emplace_back(uptr); // mark db as open
        };

        // open all db's defined above
        for (auto & tup : dbs2open)
            OpenDB(tup);

        Log() << "DB memory: " << QString::number(memTotal / 1024. / 1024., 'f', 2) << " MiB";
    }  // /open db's

    // load/check meta
    {
        const QString errMsg1{"Incompatible database format -- delete the datadir and resynch."};
        const QString errMsg2{errMsg1 + " RocksDB error"};
        if (const auto opt = GenericDBGet<Meta>(p->db.meta.get(), kMeta, true, errMsg2);
                opt.has_value())
        {
            const Meta &m_db = *opt;
            if (m_db.magic != p->meta.magic || !m_db.isVersionSupported() || m_db.platformBits != p->meta.platformBits) {
                throw DatabaseFormatError(errMsg1);
            }
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
    loadCheckTxNumsFileAndBlkInfo();
    // construct the TxHash2TxNum manager -- depends on the above function having constructed the txNumFile
    loadCheckTxHash2TxNumMgr();
    // count utxos -- note this depends on "blkInfos" being filled in so it much be called after loadCheckTxNumsFileAndBlkInfo()
    loadCheckUTXOsInDB();
    // very slow check, only runs if -C -C (specified twice)
    loadCheckShunspentInDB();
    // load check earliest undo to populate earliestUndoHeight
    loadCheckEarliestUndo();
    // if user specified --compact-dbs on CLI, run the compaction now before returning
    compactAllDBs();

    // start up the co-task we use in addBlock and undoLatestBlock
    p->blocksWorker = std::make_unique<CoTask>("Storage Worker");

    // Detect old DB version and see if upgrade is permitted, and maybe do a DB upgrade...
    checkUpgradeDBVersion();

    start(); // starts our thread
}

void Storage::checkUpgradeDBVersion()
{
    // Note: a precondition for this function is that database, headers, etc are already loaded.

    // Original Fulcrum db version before 1.9.0 was v1, and now we are on v2 which has CashToken data for BCH.
    // Going from v1 on BTC/LTC -> v2 is ok without caveats. For BCH, we must warn the user if their db is v1
    // and it's after the upgrade9 activation time, because then the DB will be missing token data and may have
    // token-containing UTXOs indexed to the wrong script hash.
    Log() << "DB version: v" << p->meta.version;
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
        saveMeta_impl();
    }
}

void Storage::compactAllDBs()
{
    if (!options->compactDBs)
        return;
    size_t ctr = 0;
    App *ourApp = app();
    Tic t0;
    Log() << "Compacting DBs, please wait ...";
    for (const auto & [db] : p->db.openDBs) {
        if (ourApp->signalsCaught())
            break;
        if (!db) continue;
        const auto name = DBName(db.get());
        Log() << "Compacting " << name << " ...";
        rocksdb::CompactRangeOptions opts;
        opts.allow_write_stall = true;
        opts.exclusive_manual_compaction = true;
        opts.change_level = true;
        auto s = db->CompactRange(opts, nullptr, nullptr);
        if (!s.ok()) {
            throw DatabaseError(QString("Error compacting %1 database: %2")
                                .arg(name, StatusString(s)));
        }
        ++ctr;
    }
    Log() << "Compacted " << ctr << " databases in " << t0.secsStr(1) << " seconds";
}

void Storage::gentlyCloseAllDBs()
{
    p->db.utxoCache.reset(); // if was valid, implicitly flushes UTXO Cache pending writes to DB...

    // do FlushWAL() and Close() to gently close the dbs
    for (auto & [db] : p->db.openDBs) {
        if (!db) continue;
        const auto name = DBName(db.get());
        Debug() << "Flushing and closing " << name << " ...";
        rocksdb::Status status;
        rocksdb::FlushOptions fopts;
        fopts.wait = true; fopts.allow_write_stall = true;
        status = db->Flush(fopts);
        if (!status.ok())
            Warning() << "Flush of " << name << ": " << QString::fromStdString(status.ToString());
        status = db->FlushWAL(true);
        if (!status.ok())
            Warning() << "FlushWAL of " << name << ": " << QString::fromStdString(status.ToString());
        status = db->Close();
        if (!status.ok())
            Warning() << "Close of " << name << ": " << QString::fromStdString(status.ToString());
        db.reset();
    }
    p->db.openDBs.clear();
}

void Storage::cleanup()
{
    stop(); // joins our thread
    if (p->blocksWorker) p->blocksWorker.reset(); // stop the co-task
    if (txsubsmgr) txsubsmgr->cleanup();
    if (dspsubsmgr) dspsubsmgr->cleanup();
    if (subsmgr) subsmgr->cleanup();
    gentlyCloseAllDBs();
    // TODO: unsaved/"dirty state" detection here -- and forced save, if needed.
}


auto Storage::stats() const -> Stats
{
    // TODO ... more stuff here, perhaps
    QVariantMap ret;
    auto & c = p->db.concatOperator, & c2 = p->db.concatOperatorTxHash2TxNum;
    ret["merge calls"] = c ? c->merges.load() : QVariant();
    ret["merge calls (txhash2txnum)"] = c2 ? c2->merges.load() : QVariant();
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
        // db stats
        QVariantMap m;
        for (const auto ptr : { &p->db.blkinfo, &p->db.meta, &p->db.shist, &p->db.shunspent, &p->db.undo, &p->db.utxoset,
                                &p->db.txhash2txnum }) {
            QVariantMap m2;
            const auto & db = *ptr;
            const QString name = QFileInfo(QString::fromStdString(db->GetName())).fileName();
            for (const auto prop : { "rocksdb.estimate-table-readers-mem", "rocksdb.cur-size-all-mem-tables"}) {
                if (std::string s; LIKELY(db->GetProperty(prop, &s)) )
                    m2[prop] = QString::fromStdString(s);
            }
            if (auto fact = db->GetOptions().table_factory; LIKELY(fact) ) {
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
        }
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
    if (auto status = p->db.meta->Put(p->db.defWriteOpts, kMeta, ToSlice(Serialize(p->meta))); !status.ok()) {
        throw DatabaseError("Failed to write meta to db");
    }

    DebugM("Wrote new metadata to db");
}

void Storage::appendHeader(const Header &h, BlockHeight height)
{
    const auto targetHeight = p->headersFile->numRecords();
    if (UNLIKELY(height != targetHeight))
        throw InternalError(QString("Bad use of appendHeader -- expected height %1, got height %2").arg(targetHeight).arg(height));
    QString err;
    const auto res = p->headersFile->appendRecord(h, true, &err);
    if (UNLIKELY(!err.isEmpty()))
        throw DatabaseError(QString("Failed to append header %1: %2").arg(height).arg(err));
    else if (UNLIKELY(!res.has_value() || *res != height))
        throw DatabaseError(QString("Failed to append header %1: returned count is bad").arg(height));
}

void Storage::deleteHeadersPastHeight(BlockHeight height)
{
    QString err;
    const auto res = p->headersFile->truncate(height + 1, &err);
    if (!err.isEmpty())
        throw DatabaseError(QString("Failed to truncate headers past height %1: %2").arg(height).arg(err));
    else if (res != height + 1)
        throw InternalError("header truncate returned an unexepected value");
}

auto Storage::headerForHeight(BlockHeight height, QString *err) const -> std::optional<Header>
{
    std::optional<Header> ret;
    if (int(height) <= latestTip().first && int(height) >= 0) {
        ret = headerForHeight_nolock(height, err);
    } else if (err) { *err = QStringLiteral("Height %1 is out of range").arg(height); }
    return ret;
}

auto Storage::headerForHeight_nolock(BlockHeight height, QString *err) const -> std::optional<Header>
{
    std::optional<Header> ret;
    try {
        QString err1;
        ret.emplace( p->headersFile->readRecord(height, &err1) );
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
    std::vector<Header> ret = p->headersFile->readRecords(height, num, err);

    if (ret.size() != num && err && err->isEmpty())
        *err = "short header count returned from headers file";

    ret.shrink_to_fit();
    return ret;
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
    p->headersFile = std::make_unique<RecordFile>(options->datadir + QDir::separator() + "headers", size_t(p->blockHeaderSize()), 0x00f026a1); // may throw

    Log() << "Verifying headers ...";
    uint32_t num = unsigned(p->headersFile->numRecords());
    std::vector<QByteArray> hVec;
    const auto t0 = Util::getTimeNS();
    {
        if (num > MAX_HEADERS)
            throw DatabaseFormatError(QString("Header count (%1) in database exceeds MAX_HEADERS! This is likely due to"
                                              " a database format mistmatch. Delete the datadir and resynch it.")
                                      .arg(num));
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
        const auto elapsed = Util::getTimeNS();

        Debug() << "Read & verified " << num << " " << Util::Pluralize("header", num) << " from db in " << QString::number((elapsed-t0)/1e6, 'f', 3) << " msec";
    }

    if (!p->merkleCache->isInitialized() && !hVec.empty())
        p->merkleCache->initialize(hVec); // this may take a few seconds, and it may also throw

}

void Storage::loadCheckTxNumsFileAndBlkInfo()
{
    // may throw.
    p->txNumsFile = std::make_unique<RecordFile>(options->datadir + QDir::separator() + "txnum2txhash", HashLen, 0x000012e2);
    p->txNumNext = p->txNumsFile->numRecords();
    Debug() << "Read TxNumNext from file: " << p->txNumNext.load();
    TxNum ct = 0;
    if (const int height = latestTip().first; height >= 0)
    {
        p->blkInfos.reserve(std::min(size_t(height+1), MAX_HEADERS));
        Log() << "Checking tx counts ...";
        for (int i = 0; i <= height; ++i) {
            static const QString errMsg("Failed to read a blkInfo from db, the database may be corrupted");
            const auto blkInfo = GenericDBGetFailIfMissing<BlkInfo>(p->db.blkinfo.get(), uint32_t(i), errMsg, false, p->db.defReadOpts);
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
}

// this depends on the above function having been run already
void Storage::loadCheckTxHash2TxNumMgr()
{
    // the below may throw
    p->db.txhash2txnumMgr = std::make_unique<TxHash2TxNumMgr>(p->db.txhash2txnum.get(), p->db.defReadOpts, p->db.defWriteOpts,
                                                              p->txNumsFile.get(), 6, TxHash2TxNumMgr::KeyPos::End);
    try {
        // basic sanity checks -- ensure we can read the first, middle, and last hash in the txNumsFile,
        // and that those hashes exist in the txhash2txnum db
        const QString errMsg = "The txhash index failed basic sanity checks -- it is missing some records.";
        const auto nrecs = p->txNumsFile->numRecords();
        if (nrecs) {
            for (auto recNum : {uint64_t(0), uint64_t(nrecs/2), uint64_t(nrecs-1)}) {
                if (!p->db.txhash2txnumMgr->exists(p->txNumsFile->readRecord(recNum)))
                    throw DatabaseError(errMsg);
            }
        } else {
            // sanity check on empty db: if no records, db should also have no rows
            std::unique_ptr<rocksdb::Iterator> it(p->db.txhash2txnum->NewIterator(p->db.defReadOpts));
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
                auto opt = GenericDBGet<QByteArray>(p->db.shunspent.get(), mkShunspentKey(hashx, ctxo), true, "", false, p->db.defReadOpts);
                if (opt.has_value()) {
                    if (seenExceptions.insert(txo).second)
                        Debug() << "Seen exception: " << txo.toString() << ", height: " << height;
                }
            }
        }

        const Tic t0;
        {
            const int currentHeight = latestTip().first;

            std::unique_ptr<rocksdb::Iterator> iter(p->db.utxoset->NewIterator(p->db.defReadOpts));
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
                        (fail1 = (info.confirmedHeight.has_value() && int(*info.confirmedHeight) > currentHeight))
                        || (fail2 = info.txNum >= p->txNumNext)
                        || (fail3 = (tmpBa = GenericDBGet<QByteArray>(p->db.shunspent.get(), shuKey, true, errPrefix, false, p->db.defReadOpts).value_or("")).isEmpty())
                        || (fail4 = (!(shval = Deserialize<SHUnspentValue>(tmpBa)).valid || info.amount != shval.amount))
                        || (fail5 = (info.tokenDataPtr != shval.tokenDataPtr))) {
                    // TODO: reorg? Inconsisent db?  FIXME
                    QString msg;
                    {
                        QTextStream ts(&msg);
                        ts << "Inconsistent database: txo " << txo.toString() << " at height: "
                           << info.confirmedHeight.value();
                        if (fail1) {
                            ts << " > current height: " << currentHeight << ".";
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

    std::unique_ptr<rocksdb::Iterator> iter(p->db.shunspent->NewIterator(p->db.defReadOpts));
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
        const auto &[hashx, ctxo] = extractShunspentKey(iter->key());
        if (!ctxo.isValid())
            throw DatabaseError(QString("Read an invalid compact txo from the scripthash_unspent database. %1").arg(errMsg));
        TXOInfo info;
        {
            SHUnspentValue shuval = Deserialize<SHUnspentValue>(FromSlice(iter->value()));
            if (UNLIKELY(!shuval.valid || !bitcoin::MoneyRange(shuval.amount)))
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
        const auto optInfo = GenericDBGet<TXOInfo>(p->db.utxoset.get(), ToSlice(Serialize(txo)), true, "", false, p->db.defReadOpts);
        if (!optInfo) {
            // we permit the buggy utxos above to be off -- those are due to collisions in historical blockchain
            if (!exceptionsDueToBitcoinBugs.count(txo))
                throw DatabaseError(QString("The scripthash_unspent table is missing a corresponding entry in the UTXO table for TXO \"%1\". %2")
                                    .arg(txo.toString(), errMsg));
            else {
                seenExceptions.insert(txo);
                Debug() << "Seen exception: " << txo.toString() << ", height: " << info.confirmedHeight.value_or(0);
            }
        }

        if (!info.isValid() || !optInfo->isValid() || *optInfo != info) {
            // we permit the buggy utxos above to be off -- those are due to collisions in historical blockchain
            if (!exceptionsDueToBitcoinBugs.count(txo))
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

void Storage::loadCheckEarliestUndo()
{
    FatalAssert(!!p->db.undo,  __func__, ": Undo db is not open");

    const Tic t0;
    unsigned ctr = 0;
    using UIntSet = std::set<uint32_t>;
    UIntSet swissCheeseDetector;
    {
        std::unique_ptr<rocksdb::Iterator> iter(p->db.undo->NewIterator(p->db.defReadOpts));
        if (!iter) throw DatabaseError("Unable to obtain an iterator to the undo db");
        for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
            const auto keySlice = iter->key();
            if (keySlice.size() != sizeof(uint32_t))
                throw DatabaseFormatError("Unexpected key in undo database. We expect only 32-bit unsigned ints!");
            const uint32_t height = DeserializeScalar<uint32_t>(FromSlice(keySlice));
            if (height < p->earliestUndoHeight) p->earliestUndoHeight = height;
            swissCheeseDetector.insert(height);
            ++ctr;
        }
    }
    if (ctr) {
        Debug() << "Undo db contains " << ctr << " entries, earliest is " << p->earliestUndoHeight.load() << ", "
                << t0.msecStr(2) << " msec elapsed.";
    }
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
        for (auto it = swissCheeseDetector.begin(); it != eraseUntil; ++delctr) {
            GenericDBDelete(p->db.undo.get(), uint32_t(*it));
            it = swissCheeseDetector.erase(it);
        }
        p->earliestUndoHeight = !swissCheeseDetector.empty() ? *swissCheeseDetector.begin() : p->InvalidUndoHeight;
        ctr = swissCheeseDetector.size();
        if (delctr) {
            Warning() << "Deleted " << delctr << Util::Pluralize(" undo entry", delctr) << ", earliest undo entry is now "
                      << p->earliestUndoHeight.load() << ", total undo entries now in db: " << ctr;
        }
    }
    // heuristic to detect that the user changed the default on an already-synched dir
    if (const auto legacy = Options::oldFulcrumReorgDepth; configuredUndoDepth() > legacy && ctr == legacy) {
        Warning() << "You have specified max_reorg in the conf file as " << configuredUndoDepth() << "; older "
                  << APPNAME << " versions may not cope well with this setting. As such, it is recommended that you "
                  << "avoid using older versions of this program with this datadir now that you have set this option "
                  << "beyond the default.";
    }
    // sanity check that the latest Undo block deserializes correctly (detects older Fulcrum loading newer db)
    if (!swissCheeseDetector.empty()) {
        const uint32_t height = *swissCheeseDetector.rbegin();
        const QString errMsg(QString("Unable to read undo data for height %1").arg(height));
        const UndoInfo undoInfo = GenericDBGetFailIfMissing<UndoInfo>(p->db.undo.get(), height, errMsg);
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
        for (unsigned i = 0; i < n2del; ++i)
            GenericDBDelete(p->db.undo.get(), uint32_t(p->earliestUndoHeight++));
        Warning() << n2del << Util::Pluralize(" undo entry", n2del) << " deleted from db in " << t1.msecStr() << " msec";
    }
}

bool Storage::hasUndo() const {
    return p->earliestUndoHeight != p->InvalidUndoHeight;
}

struct Storage::UTXOBatch::P {
    rocksdb::WriteBatch utxosetBatch; ///< batch writes/deletes end up in the utxoset db (keyed off TXO)
    rocksdb::WriteBatch shunspentBatch; ///< batch writes/deletes end up in the shunspent db (keyed off HashX+CompactTXO)
    int addCt = 0, rmCt = 0;
    bool defunct = false;
    UTXOCache *cache{}; ///< if not nullptr, there is a UTXOCache active and we should give it the batch writes.
};

Storage::UTXOBatch::UTXOBatch(UTXOCache *cache) : p(new P) { p->cache = cache; }
Storage::UTXOBatch::UTXOBatch(UTXOBatch &&o) { p.swap(o.p); }

void Storage::issueUpdates(UTXOBatch &b)
{
    static const QString errMsg1("Error issuing batch write to utxoset db for a utxo update"),
                         errMsg2("Error issuing batch write to scripthash_unspent db for a utxo update");
    if (UNLIKELY(b.p->defunct))
        throw InternalError("Misuse of Storage::issueUpdates. Cannot issue the same updates using the same context more than once. FIXME!");
    assert(bool(p->db.utxoset) && bool(p->db.shunspent));
    if (!b.p->cache) {
        GenericBatchWrite(p->db.utxoset.get(), b.p->utxosetBatch, errMsg1, p->db.defWriteOpts); // may throw
        GenericBatchWrite(p->db.shunspent.get(), b.p->shunspentBatch, errMsg2, p->db.defWriteOpts); // may throw
    }
    p->utxoCt += b.p->addCt - b.p->rmCt; // tally up adds and deletes
    b.p->defunct = true;
}

void Storage::setInitialSync(bool b) {
    // take all locks now.. since this is a Big Deal.
    std::scoped_lock guard(p->blocksLock, p->headerVerifierLock, p->blkInfoLock, p->mempoolLock);
    assert(bool(p->db.utxoset) && bool(p->db.shunspent));
    if (b && !p->db.utxoCache) {
        if (options->utxoCache > 0) {
            Log() << "fast-sync: Enabled; UTXO cache size set to " << options->utxoCache
                  << " bytes (available physical RAM: " << Util::getAvailablePhysicalRAM() << " bytes)";
            p->db.utxoCache.reset(new UTXOCache("Storage UTXO Cache", p->db.utxoset, p->db.shunspent, p->db.defReadOpts, p->db.defWriteOpts));
            // Reserve about 3.6 million entries per GB of utxoCache memory given to us
            // We need to do this, despite the extra memory bloat, because it turns out rehashing is very painful.
            p->db.utxoCache->autoReserve(options->utxoCache);
        } else {
            Log() << "fast-sync: Not enabled";
        }
    } else if (!b && p->db.utxoCache) {
        Log() << "Initial sync ended, flushing and deleting UTXO Cache ...";
        p->db.utxoCache.reset(); // implicitly flushes
    }
}

void Storage::UTXOBatch::add(const TXO &txo, const TXOInfo &info, const CompactTXO &ctxo)
{
    const QByteArray shukey = mkShunspentKey(info.hashX, ctxo),
                     shuval = Serialize(info.amount, info.tokenDataPtr.get());
    if (!p->cache) {
        // Update db utxoset, keyed off txo -> txoinfo
        static const QString errMsgPrefix("Failed to add a utxo to the utxo batch");
        GenericBatchPut(p->utxosetBatch, txo, info, errMsgPrefix); // may throw on failure

        // Update the scripthash unspent. This is a very simple table which we scan by hashX prefix using
        // an iterator in listUnspent.  Each entry's key is prefixed with the HashX bytes (32) but suffixed with the
        // serialized CompactTXO bytes (8 or 9). Each entry's data is a 8-byte int64_t of the amount of the utxo to save
        // on lookup cost for getBalance().
        static const QString errMsgPrefix2("Failed to add an entry to the scripthash_unspent batch");
        GenericBatchPut(p->shunspentBatch, shukey, shuval, errMsgPrefix2); // may throw, which is what we want
    } else {
        // put in cache (in case these get deleted later on, it's a win to do this rather than hit the DB, if using cache)
        p->cache->put(txo, info);
        p->cache->putShunspent(shukey, shuval);
    }

    ++p->addCt;
}

void Storage::UTXOBatch::remove(const TXO &txo, const HashX &hashX, const CompactTXO &ctxo)
{
    if (!p->cache) {
        // enqueue delete from utxoset db -- may throw.
        static const QString errMsgPrefix("Failed to issue a batch delete for a utxo");
        GenericBatchDelete(p->utxosetBatch, txo, errMsgPrefix);

        // enqueue delete from scripthash_unspent db
        static const QString errMsgPrefix2("Failed to issue a batch delete for a utxo to the scripthash_unspent db");
        GenericBatchDelete(p->shunspentBatch, mkShunspentKey(hashX, ctxo), errMsgPrefix2);
    } else {
        // use cache which may end up doing no actual work if the utxo & shunspent was in cache and not yet committed to db
        p->cache->remove(txo);
        p->cache->removeShunspent(hashX, ctxo);
    }
    ++p->rmCt;
}


/// Thread-safe. Query db for a UTXO, and return it if found.  May throw on database error.
std::optional<TXOInfo> Storage::utxoGetFromDB(const TXO &txo, bool throwIfMissing)
{
    assert(bool(p->db.utxoset));
    static const QString errMsgPrefix("Failed to read a utxo from the utxo db");
    return GenericDBGet<TXOInfo>(p->db.utxoset.get(), txo, !throwIfMissing, errMsgPrefix, false, p->db.defReadOpts);
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

void Storage::addBlock(PreProcessedBlockPtr ppb, bool saveUndo, unsigned nReserve, bool notifySubs)
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

        if (p->db.utxoCache && p->db.utxoCache->cacheMisses) {
            p->db.utxoCache->prefetch(ppb); // will prefetch inputs in a thread
        }

        const auto blockTxNum0 = p->txNumNext.load();

        if (notify) {
            // Txs in block can never be in mempool. Ensure they are gone from mempool right away so that notifications
            // to clients are as accurate as possible (notifications may happen after this function returns).
            const auto sz = ppb->txInfos.size();
            const auto rsvsz = static_cast<Mempool::TxHashNumMap::size_type>(sz > 0 ? sz-1 : 0);
            Mempool::TxHashNumMap txidMap(/* bucket_count: */ rsvsz);
            notify->txidsAffected.reserve(rsvsz);
            for (std::size_t i = 1 /* skip coinbase */; i < sz; ++i) {
                const auto & txHash = ppb->txInfos[i].hash;
                txidMap.emplace(txHash, blockTxNum0 + i);
                notify->txidsAffected.insert(txHash); // add to notify set for txSubsMgr
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

            setDirty(true); // <--  no turning back. if the app crashes unexpectedly while this is set, on next restart it will refuse to run and insist on a clean resynch.

            {  // add txnum -> txhash association to the TxNumsFile...
                auto batch = p->txNumsFile->beginBatchAppend(); // may throw if io error in c'tor here.
                QString errStr;
                for (const auto & txInfo : ppb->txInfos) {
                    if (!batch.append(txInfo.hash, &errStr)) // does not throw here, but we do.
                        throw InternalError(QString("Batch append for txNums failed: %1.").arg(errStr));
                }
                // <-- The batch d'tor may close the app on error here with Fatal() if a low-level file error occurs now
                //     on header update (see: RecordFile.cpp, ~BatchAppendContext()).
            }

            p->txNumNext += ppb->txInfos.size(); // update internal counter

            if (p->txNumNext != p->txNumsFile->numRecords())
                throw InternalError("TxNum file and internal txNumNext counter disagree! FIXME!");

            // Asynch task -- the future will automatically be awaited on scope end (even if we throw here!)
            // NOTE: The assumption here is that ppb->txInfos is ok to share amongst threads -- that is, the assumption
            // is that nothing mutates it.  If that changes, please re-examine this code.
            CoTask::Future fut; // if valid, will auto-wait for us on scope end
            if (ppb->txInfos.size() > 1000) {
                // submit this to the co-task for blocks with enough txs
                fut = p->blocksWorker->submitWork([&]{
                    p->db.txhash2txnumMgr->insertForBlock(blockTxNum0, ppb->txInfos);
                });
            } else {
                // otherwise just do the work ourselves immediately here since this is likely faster (less overhead)
                p->db.txhash2txnumMgr->insertForBlock(blockTxNum0, ppb->txInfos);
            }

            constexpr bool debugPrt = false;

            // update utxoSet & scritphash history
            {
                std::unordered_set<HashX, HashHasher> newHashXInputsResolved;
                newHashXInputsResolved.reserve(1024); ///< todo: tune this magic number?

                {
                    // utxo batch block (updtes utxoset & scripthash_unspent tables)
                    UTXOBatch utxoBatch{p->db.utxoCache.get()};

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
                            TXOInfo info;
                            info.hashX = hashX;
                            info.amount = out.amount;
                            info.confirmedHeight = ppb->height;
                            info.txNum = blockTxNum0 + out.txIdx;
                            info.tokenDataPtr = out.tokenDataPtr;
                            const TXO txo{ hash, out.outN };
                            const CompactTXO ctxo(info.txNum, txo.outN);
                            utxoBatch.add(txo, info, ctxo); // add to db
                            if (undo) { // save undo info if we are in saveUndo mode
                                undo->addUndos.emplace_back(txo, info.hashX, ctxo);
                            }
                            if constexpr (debugPrt)
                                Debug() << "Added txo: " << txo.toString()
                                        << " (txid: " << hash.toHex() << " height: " << ppb->height << ") "
                                        << " amount: " << info.amount.ToString() << " for HashX: " << info.hashX.toHex();
                        }
                    }

                    if (p->db.utxoCache)
                        // we need the inputs resolved now, so end the prefetch
                        // note this may stall and also will empty out p->db.utxoCache->deferredAdds
                        p->db.utxoCache->waitForPrefetchToComplete();

                    // add spends (process inputs)
                    unsigned inum = 0;
                    for (auto & in : ppb->inputs) {
                        const TXO txo{in.prevoutHash, in.prevoutN};
                        if (!inum) {
                            // coinbase.. skip
                        } else if (in.parentTxOutIdx.has_value()) {
                            // was an input that was spent in this block so it's ok to skip.. we never added it to utxo set
                            if constexpr (debugPrt)
                                Debug() << "Skipping input " << txo.toString() << ", spent in this block (output # " << *in.parentTxOutIdx << ")";
                        } else if (std::optional<TXOInfo> opt;
                                   (p->db.utxoCache && (opt = p->db.utxoCache->get(txo))) || (opt = utxoGetFromDB(txo))) {
                            const auto & info = *opt;
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
                            // delete from db
                            utxoBatch.remove(txo, info.hashX, CompactTXO(info.txNum, txo.outN)); // delete from db
                            if (undo) { // save undo info, if we are in saveUndo mode
                                undo->delUndos.emplace_back(txo, info);
                            }
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

                    // commit the utxoset updates now.. this issues the writes to the db and also updates
                    // p->utxoCt. This may throw.
                    issueUpdates(utxoBatch);
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
                rocksdb::WriteBatch batch;
                for (auto & [hashX, ag] : ppb->hashXAggregated) {
                    if (notify) notify->scriptHashesAffected.insert(hashX); // fast O(1) insertion because we reserved the right size above.
                    for (auto & txNum : ag.txNumsInvolvingHashX) {
                        txNum += blockTxNum0; // transform local txIdx to -> txNum (global mapping)
                    }
                    // save scripthash history for this hashX, by appending to existing history. Note that this uses
                    // the 'ConcatOperator' class we defined in this file, which requires rocksdb be compiled with RTTI.
                    if (auto st = batch.Merge(ToSlice(hashX), ToSlice(Serialize(ag.txNumsInvolvingHashX))); !st.ok())
                        throw DatabaseError(QString("batch merge fail for hashX %1, block height %2: %3")
                                            .arg(QString(hashX.toHex())).arg(ppb->height).arg(StatusString(st)));
                }
                if (auto st = p->db.shist->Write(p->db.defWriteOpts, &batch) ; !st.ok())
                    throw DatabaseError(QString("batch merge fail for block height %1: %2")
                                        .arg(ppb->height).arg(StatusString(st)));
            }


            {
                // update BlkInfo
                if (nReserve) {
                    if (const auto size = p->blkInfos.size(); size + 1 > p->blkInfos.capacity())
                        p->blkInfos.reserve(size + nReserve); // reserve space for new blkinfos in 1 go to save on copying
                }

                p->blkInfos.emplace_back(
                    blockTxNum0, // .txNum0
                    unsigned(ppb->txInfos.size())
                );

                const auto & blkInfo = p->blkInfos.back();

                p->blkInfosByTxNum[blkInfo.txNum0] = unsigned(p->blkInfos.size()-1);

                // save BlkInfo to db
                static const QString blkInfoErrMsg("Error writing BlkInfo to db");
                GenericDBPut(p->db.blkinfo.get(), uint32_t(ppb->height), blkInfo, blkInfoErrMsg, p->db.defWriteOpts);

                if (undo) {
                    // save blkInfo to undo information, if in saveUndo mode
                    undo->blkInfo = p->blkInfos.back();
                }
            }

            // save the last of the undo info, if in saveUndo mode
            if (undo) {
                const auto t0 = Util::getTimeNS();
                undo->hash = BTC::HashRev(rawHeader);
                undo->scriptHashes = Util::keySet<decltype (undo->scriptHashes)>(ppb->hashXAggregated);
                static const QString errPrefix("Error saving undo info to undo db");

                GenericDBPut(p->db.undo.get(), uint32_t(ppb->height), *undo, errPrefix, p->db.defWriteOpts); // save undo to db
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
                    const auto elapsedms = (Util::getTimeNS() - t0)/1e6;
                    const size_t nTx = undo->blkInfo.nTx, nSH = undo->scriptHashes.size();
                    Debug() << "Saved V3 undo for block " << undo->height << ", "
                            << nTx << " " << Util::Pluralize("transaction", nTx)
                            << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
                            << ", in " << QString::number(elapsedms, 'f', 2) << " msec.";
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
                GenericDBDelete(p->db.undo.get(), uint32_t(expireUndoHeight), errPrefix, p->db.defWriteOpts);
                p->earliestUndoHeight = unsigned(expireUndoHeight + 1);
                if constexpr (debugPrt) DebugM("Deleted undo for block ", expireUndoHeight, ", earliest now ", p->earliestUndoHeight.load());
            }

            appendHeader(rawHeader, ppb->height);

            if (UNLIKELY(ppb->height == 0)) {
                // update genesis hash now if block 0 -- this info is used by rpc method server.features
                p->genesisHash = BTC::HashRev(rawHeader); // this variable is guarded by p->headerVerifierLock
            }

            if (size_t limit; p->db.utxoCache && (limit = options->utxoCache) && p->db.utxoCache->memUsage() > limit)
                p->db.utxoCache->limitSize(static_cast<size_t>(limit * 0.75) /* chop down to 3/4 size */);

            saveUtxoCt();
            setDirty(false);

            undoVerifierOnScopeEnd.disable(); // indicate to the "Defer" object declared at the top of this function that it shouldn't undo anything anymore as we are happy now with the db state now.
        }
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

        const auto t0 = Util::getTimeNS();

        // First, disable the UTXO Cache, if it happened to be enabled (implicitly causes it to flush to DB).
        // We must do this because the way the UTXO Cache works is fundamentally at odds with assumption we have
        // while we undo.
        p->db.utxoCache.reset(); // if valid, delete causes implicit flush to DB

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
        auto undoOpt = GenericDBGet<UndoInfo>(p->db.undo.get(), uint32_t(tip), true, errMsg1, false, p->db.defReadOpts);
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

            // first, undo the header
            p->headerVerifier.reset(prevHeight+1, prevHeader);
            setDirty(true); // <-- no turning back. we clear this flag at the end
            deleteHeadersPastHeight(prevHeight); // commit change to db
            p->merkleCache->truncate(prevHeight+1); // this takes a length, not a height, which is always +1 the height

            // undo the blkInfo from the back
            p->blkInfos.pop_back();
            p->blkInfosByTxNum.erase(undo.blkInfo.txNum0);
            GenericDBDelete(p->db.blkinfo.get(), uint32_t(undo.height), "Failed to delete blkInfo in undoLatestBlock");
            // clear num2hash cache
            p->lruNum2Hash.clear();
            // remove block from txHashes cache
            p->lruHeight2Hashes_BitcoindMemOrder.remove(undo.height);

            const auto txNum0 = undo.blkInfo.txNum0;

            // Asynch task -- the future will automatically be awaited on scope end (even if we throw here!)
            // Note: we await the result later down in this function before we truncate the txNumsFile. (Assumption
            // here is that the txNumsFile has all the hashes we want to delete until the below operation is done).
            CoTask::Future fut = p->blocksWorker->submitWork([&]{ p->db.txhash2txnumMgr->truncateForUndo(txNum0);});

            // undo the scripthash histories
            for (const auto & sh : undo.scriptHashes) {
                const QString shHex = Util::ToHexFast(sh);
                const auto vec = GenericDBGetFailIfMissing<TxNumVec>(p->db.shist.get(), sh, QStringLiteral("Undo failed because we failed to retrieve the scripthash history for %1").arg(shHex), false, p->db.defReadOpts);
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
                    GenericDBPut(p->db.shist.get(), sh, newVec, errMsg, p->db.defWriteOpts);
                } else {
                    // the sh in question lost all its history as a result of undo, just delete it from db to save space
                    GenericDBDelete(p->db.shist.get(), sh, errMsg, p->db.defWriteOpts);
                }
            }

            {
                // UTXO set update
                UTXOBatch utxoBatch;

                // now, undo the utxo deletions by re-adding them
                for (const auto & [txo, info] : undo.delUndos) {
                    // note that deletions may have an info with a txnum before this block, for obvious reasons
                    utxoBatch.add(txo, info, CompactTXO(info.txNum, txo.outN)); // may throw
                }

                // now, undo the utxo additions by deleting them
                for (const auto & [txo, hashx, ctxo] : undo.addUndos) {
                    assert(ctxo.txNum() >= txNum0); // all of the additions must have been in this block or newer
                    utxoBatch.remove(txo, hashx, ctxo); // may throw
                }

                issueUpdates(utxoBatch); // may throw, updates p->utxoCt and issues write to db.
            }

            if (p->earliestUndoHeight >= undo.height)
                // oops, we're out of undos now!
                p->earliestUndoHeight = p->InvalidUndoHeight;
            GenericDBDelete(p->db.undo.get(), uint32_t(undo.height)); // make sure to delete this undo info since it was just applied.

            // add all tx hashes that we are rolling back to the notify set for the txSubsMgr
            if (notify) {
                const auto txHashes = p->txNumsFile->readRecords(txNum0, undo.blkInfo.nTx);
                notify->txidsAffected.insert(txHashes.begin(), txHashes.end());
            }

            // Wait for the txhash2txnum truncate to finish before we proceed, since that co-task assumes the txNumsFile
            // won't change.
            if (fut.future.valid())
                fut.future.get(); // this may throw if task threw

            // lastly, truncate the tx num file and re-set txNumNext to point to this block's txNum0 (thereby recycling it)
            assert(long(p->txNumNext) - long(txNum0) == long(undo.blkInfo.nTx));
            p->txNumNext = txNum0;
            if (QString err; p->txNumsFile->truncate(txNum0, &err) != txNum0 || !err.isEmpty()) {
                throw InternalError(QString("Failed to truncate txNumsFile to %1: %2").arg(txNum0).arg(err));
            }

            saveUtxoCt();
            setDirty(false); // phew. done.

            nSH = undo.scriptHashes.size();

            if (notify) {
                if (notify->scriptHashesAffected.empty())
                    notify->scriptHashesAffected.swap(undo.scriptHashes);
                else
                    notify->scriptHashesAffected.merge(std::move(undo.scriptHashes));
            }
        }

        const size_t nTx = undo.blkInfo.nTx;
        const auto elapsedms = (Util::getTimeNS() - t0) / 1e6;
        Log() << "Applied undo for block " << undo.height << " hash " << Util::ToHexFast(undo.hash) << ", "
              << nTx << " " << Util::Pluralize("transaction", nTx)
              << " involving " << nSH << " " << Util::Pluralize("scripthash", nSH)
              << ", in " << QString::number(elapsedms, 'f', 2) << " msec, new height now: " << prevHeight;
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


void Storage::setDirty(bool dirtyFlag)
{
    static const QString errPrefix("Error saving dirty flag to the meta db");
    const auto & val = dirtyFlag ? kTrue : kFalse;
    GenericDBPut(p->db.meta.get(), kDirty, val, errPrefix, p->db.defWriteOpts);
}

bool Storage::isDirty() const
{
    static const QString errPrefix("Error reading dirty flag from the meta db");
    return GenericDBGet<bool>(p->db.meta.get(), kDirty, true, errPrefix, false, p->db.defReadOpts).value_or(false);
}

void Storage::saveUtxoCt()
{
    static const QString errPrefix("Error writing the utxo count to the meta db");
    const int64_t ct = p->utxoCt.load();
    GenericDBPut(p->db.meta.get(), kUtxoCount, ct, errPrefix, p->db.defWriteOpts);
}
int64_t Storage::readUtxoCtFromDB() const
{
    static const QString errPrefix("Error reading the utxo count from the meta db");
    return GenericDBGet<int64_t>(p->db.meta.get(), kUtxoCount, true, errPrefix, false, p->db.defReadOpts).value_or(0LL);
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
    const auto bytes = p->txNumsFile->readRecord(n, &errStr);
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

std::optional<TxHash> Storage::hashForHeightAndPos(BlockHeight height, unsigned posInBlock) const
{
    std::optional<TxHash> ret;
    TxNum txNum = 0;
    SharedLockGuard(p->blocksLock); // guarantee a consistent view (so that data doesn't mutate from underneath us)
    {
        SharedLockGuard g(p->blkInfoLock);
        if (height >= p->blkInfos.size())
            return ret;
        const BlkInfo & bi = p->blkInfos[height];
        if (posInBlock >= bi.nTx)
            return ret;
        txNum = bi.txNum0 + posInBlock;
    }
    ret = hashForTxNum(txNum);
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
    auto vec = p->txNumsFile->readRecords(startCount.first, startCount.second, &err);
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
static auto GetMaxHistoryCtrFunc(const QString &name, const HashX &hashX, size_t maxHistory)
{
    return [name, hashX, maxHistory, ctr = size_t{0u}](size_t incr = 1u) mutable {
        if (UNLIKELY((ctr += incr) > maxHistory)) {
            throw HistoryTooLarge(QString("%1 for scripthash %2 exceeds MaxHistory %3 with %4 items!")
                                  .arg(name, QString(hashX.toHex())).arg(maxHistory).arg(ctr));
        }
    };
}

auto Storage::getHistory(const HashX & hashX, bool conf, bool unconf) const -> History
{
    History ret;
    if (hashX.length() != HashLen)
        return ret;
    auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("History", hashX, options->maxHistory);
    try {
        SharedLockGuard g(p->blocksLock);  // makes sure history doesn't mutate from underneath our feet
        if (conf) {
            static const QString err("Error retrieving history for a script hash");
            auto nums_opt = GenericDBGet<TxNumVec>(p->db.shist.get(), hashX, true, err, false, p->db.defReadOpts);
            if (nums_opt.has_value()) {
                auto & nums = *nums_opt;
                IncrementCtrAndThrowIfExceedsMaxHistory(nums.size());
                ret.reserve(nums.size());
                // TODO: The below could use some optimization.  A batched version of both hashForTxNum and
                // heightForTxNum are low-hanging fruit for optimization.  Each call to the below takes a shared lock
                // then releases it, for each item.  I imagine batched versions would have significantly less overhead
                // per item, which could add up to huge performance savings on large histories.  This is a very
                // low hanging fruit for optimization -- thus I am leaving this comment here so I can remember to come
                // back and optmize the below.  /TODO
                for (auto num : nums) {
                    auto hash = hashForTxNum(num).value(); // may throw, but that indicates some database inconsistency. we catch below
                    auto height = heightForTxNum(num).value(); // may throw, same deal
                    ret.emplace_back(HistoryItem{hash, int(height), {}});
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
                    ret.emplace_back(HistoryItem{tx->hash, tx->hasUnconfirmedParentTx ? -1 : 0, tx->fee});
            }
        }
    } catch (const std::exception &e) {
        Warning(Log::Magenta) << __func__ << ": " << e.what();
    }
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
        auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("Unspent UTXOs", hashX, options->maxHistory);
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
                                        TxNum(1) + veryHighTxNum + TxNum(tx->hasUnconfirmedParentTx ? 1 : 0), // .txNum (this is fudged for sorting at the end properly)
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
                std::unique_ptr<rocksdb::Iterator> iter(p->db.shunspent->NewIterator(p->db.defReadOpts));
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
                        auto ctxo = extractCompactTXOFromShunspentKey(key); /* may throw if size is bad, etc */
                        throw InternalError(QString("Bad SHUnspentValue in db for ctxo %1, script_hash: %2")
                                            .arg(ctxo.toString(), QString(hashX.toHex())));
                    }
                    if (UNLIKELY(!bitcoin::MoneyRange(shval.amount))) {
                        auto ctxo = extractCompactTXOFromShunspentKey(key); /* may throw if size is bad, etc */
                        throw InternalError(QString("Out-of-range amount in db for ctxo %1, script_hash %2: %3")
                                            .arg(ctxo.toString(), QString(hashX.toHex())).arg(shval.amount / shval.amount.satoshi()));
                    }
                    if (ShouldFilter(shval.tokenDataPtr))
                        continue;
                    auto ctxo = extractCompactTXOFromShunspentKey(key); /* may throw if size is bad, etc */
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
    auto IncrementCtrAndThrowIfExceedsMaxHistory = GetMaxHistoryCtrFunc("GetBalance UTXOs", hashX, options->maxHistory);
    try {
        // take shared lock (ensure history doesn't mutate from underneath our feet)
        SharedLockGuard g(p->blocksLock);
        {
            // confirmed -- read from db using an iterator
            std::unique_ptr<rocksdb::Iterator> iter(p->db.shunspent->NewIterator(p->db.defReadOpts));
            const rocksdb::Slice prefix = ToSlice(hashX); // points to data in hashX

            // Search table for all keys that start with hashx's bytes. Note: the loop end-condition is strange.
            // See: https://github.com/facebook/rocksdb/wiki/Prefix-Seek-API-Changes#transition-to-the-new-usage
            rocksdb::Slice key;
            for (iter->Seek(prefix); iter->Valid() && (key = iter->key()).starts_with(prefix); iter->Next()) {
                IncrementCtrAndThrowIfExceedsMaxHistory(); // throw if we are iterating too much
                const CompactTXO ctxo = extractCompactTXOFromShunspentKey(key); // may throw if key has the wrong size, etc
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

void Storage::refreshMempoolHistogram()
{
    Mempool::FeeHistogramVec hist;
    {
        // shared lock
        auto [mempool, lock] = this->mempool();
        auto histTmp = mempool.calcCompactFeeHistogram();
        hist.swap(histTmp);
    }
    // lock exclusively to do the final swap
    ExclusiveLockGuard g(p->mempoolLock);
    p->mempoolFeeHistogram.swap(hist);
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

size_t Storage::dumpAllScriptHashes(QIODevice *outDev, unsigned int indent, unsigned int ilvl,
                                    const DumpProgressFunc &progFunc, size_t progInterval) const
{
    if (!outDev || !outDev->isWritable())
        return 0;
    SharedLockGuard g{p->blocksLock};
    std::unique_ptr<rocksdb::Iterator> it {p->db.shist->NewIterator(p->db.defReadOpts)};
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
    auto readOpts_utxo = p->db.defReadOpts;
    auto readOpts_shunspent = p->db.defReadOpts;
    const auto [ss_utxo, ss_shunspent, bheight, bhash] = [&] {
        SharedLockGuard g{p->blocksLock};
        using CSnapshot = const rocksdb::Snapshot;
        auto s1 = std::shared_ptr<CSnapshot>(p->db.utxoset->GetSnapshot(),
                                             [this](CSnapshot *ss){ p->db.utxoset->ReleaseSnapshot(ss); });
        auto s2 = std::shared_ptr<CSnapshot>(p->db.utxoset->GetSnapshot(),
                                             [this](CSnapshot *ss){ p->db.shunspent->ReleaseSnapshot(ss); });
        const auto & [height, hash] = latestTip(); // takes a subordinate lock to blocksLock
        return std::tuple(s1, s2, height, hash);
    }();
    readOpts_utxo.snapshot = ss_utxo.get();
    readOpts_shunspent.snapshot = ss_shunspent.get();
    std::unique_ptr<rocksdb::Iterator> it_utxo {p->db.utxoset->NewIterator(readOpts_utxo)};
    std::unique_ptr<rocksdb::Iterator> it_shu {p->db.shunspent->NewIterator(readOpts_shunspent)};
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
            // we serialize the 'magic' value as a simple scalar as a sort of endian check for the DB
            ds << SerializeScalarNoCopy(m.magic) << m.version << m.chain << m.platformBits << m.coin;
        }
        return ba;
    }
    template <> Meta Deserialize(const QByteArray &ba, bool *ok_ptr)
    {
        bool dummy;
        bool &ok (ok_ptr ? *ok_ptr : dummy);
        ok = false;
        Meta m{0, 0, {}};
        {
            QDataStream ds(ba);
            QByteArray magicBytes;
            ds >> magicBytes; // read magic as raw bytes.
            if ((ok = ds.status() == QDataStream::Status::Ok)) {
                m.magic = DeserializeScalar<decltype (m.magic)>(magicBytes, &ok);
                if (ok) {
                    ds >> m.version >> m.chain;
                    ok = ds.status() == QDataStream::Status::Ok;
                    if (ok && !ds.atEnd()) {
                        // TODO: make this field non-optional. For now we tolerate it missing since we added this field
                        // later and we want to be able to still test on our existing db's.
                        ds >> m.platformBits;
                    }
                    ok = ds.status() == QDataStream::Status::Ok;
                    if (ok) {
                        if (!ds.atEnd()) {
                            // Newer db's will always either have an empty string "", "BCH", or "BTC" here.
                            // Read the db value now. Client code gets this value via Storage::getCoin().
                            ds >> m.coin;
                        } else {
                            // Older db's pre-1.3.0 lacked this field -- but now we interpret missing data here as
                            // "BCH" (since all older db's were always BCH only).
                            m.coin = BTC::coinToName(BTC::Coin::BCH);
                            Debug() << "Missing coin info from Meta table, defaulting coin to: \"" << m.coin << "\"";
                        }
                    }
                    ok = ds.status() == QDataStream::Status::Ok;
                }
            }
        }
        return m;
    }

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

    // deep copy, raw bytes
    template <> QByteArray Serialize(const BlkInfo &b) { return DeepCpy(&b); }
    // will fail if extra bytes at the end
    template <> BlkInfo Deserialize(const QByteArray &ba, bool *ok) {
        BlkInfo ret;
        if (ba.length() != sizeof(ret)) {
            if (ok) *ok = false;
        } else {
            if (ok) *ok = true;
            std::memcpy(reinterpret_cast<std::byte *>(&ret), ba.constData(), sizeof(ret));
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
    };

    static_assert(std::has_unique_object_representations_v<UndoInfoSerHeader>, "This type is serialized as bytes to db");

    // Deserialize a header from bytes -- no checks are done other than length check.
    template <> UndoInfoSerHeader Deserialize(const QByteArray &ba, bool *ok) {
        UndoInfoSerHeader ret;
        if (ba.length() < int(sizeof(ret))) {
            if (ok) *ok = false;
        } else {
            if (ok) *ok = true;
            std::memcpy(reinterpret_cast<std::byte *>(&ret), ba.constData(), sizeof(ret));
        }
        return ret;
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
        ret.append(ShallowTmp(&hdr));
        // 2. .height
        ret.append(SerializeScalarNoCopy(u.height));
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
        const QByteArray blkInfoBytes = Serialize(u.blkInfo);
        ret.append(blkInfoBytes);
        // 5. .scriptHashes, 32 bytes each, for all in set
        for (const auto & sh : u.scriptHashes) {
            if (UNLIKELY(!chkHashLen(sh))) return ret;
            ret.append(sh);
        }
        // 6. .addUndos, 76 bytes each * nAddUndos
        for (const auto & [txo, hashX, ctxo] : u.addUndos) {
            if (UNLIKELY(!chkHashLen(hashX))) return ret;
            ret.append(txo.toBytes(true  /* force wide (3 byte IONum) */));
            ret.append(hashX);
            ret.append(ctxo.toBytes(true /* force wide (3 byte IONum) */));
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
        std::memcpy(ret.data() + offset_of_len, &hdr.len, sizeof(hdr.len));

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
        QByteArray ret(int(nBytes), Qt::Uninitialized);
        if (UNLIKELY(nBytes != size_t(ret.size()))) {
            throw DatabaseSerializationError(QString("Overflow or other error when attempting to serialize a TxNumVec"
                                                     " of %1 bytes").arg(qulonglong(nBytes)));
        }
        std::byte *cur = reinterpret_cast<std::byte *>(ret.data());
        for (const auto num : v) {
            CompactTXO::txNumToCompactBytes(cur, num);
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
        auto *cur = reinterpret_cast<const std::byte *>(ba.begin()), * const end = reinterpret_cast<const std::byte *>(ba.end());
        ret.reserve(N);
        for ( ; cur < end; cur += compactSize) {
            ret.push_back( CompactTXO::txNumFromCompactBytes(cur) );
        }
        return ret;
    }

    //template <> QByteArray Serialize(const CompactTXO &c) { return c.toBytes(false); }
    template <> CompactTXO Deserialize(const QByteArray &b, bool *ok) {
        CompactTXO ret = CompactTXO::fromBytes(b);
        if (ok) *ok = ret.isValid();
        return ret;
    }

    QByteArray Serialize(const bitcoin::Amount &a, const bitcoin::token::OutputData *ptok) {
        QByteArray ret = SerializeScalar(a / a.satoshi());
        BTC::SerializeTokenDataWithPrefix(ret, ptok); // may be no-op if ptok is nullptr
        return ret;
    }
    template <> SHUnspentValue Deserialize(const QByteArray &ba, bool *pok) {
        int pos = 0;
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
        static_assert(std::is_pod_v<KeyType> && !std::is_floating_point_v<KeyType>);
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
            throw Exception("Please pass the TFILE env var as a path to an existing \"txnum2hash\" data record file");
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
