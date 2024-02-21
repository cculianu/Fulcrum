//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "Util.h"

#include "bitcoin/block.h"
#include "bitcoin/hash.h"
#include "bitcoin/script.h"
#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"
#include "bitcoin/version.h"

#include <QByteArray>
#include <QHash>
#include <QMetaType>
#include <QString>

#include <cstddef> // for std::byte, etc
#include <cstring> // for memcpy
#include <ios>
#include <type_traits>
#include <utility> // for pair, etc

/// A namespace for Bitcoin-related classes and types. Despite the BTC moniker,
/// this namespace is not specific to Bitcoin (Core), but applies to BCH as well.
namespace BTC
{
    /// Used by the Storage and Controller subsystem to figure out what coin we are on (BCH vs BTC vs LTC)
    enum class Coin { Unknown = 0, BCH, BTC, LTC };

    QString coinToName(Coin);
    Coin coinFromName(const QString &);

    /// Tests
    namespace Tests {
        bool Base58(bool silent = false, bool throws = false);
    }

    /// Checks that the bitcoin lib has the correct endian settings for this platform. Will throw InternalError on
    /// failure. Also does other sanity checks, as well.
    extern void CheckBitcoinEndiannessAndOtherSanityChecks();

    /// -- Template Serialization / Deserialization methods to/from QByteArray --

    /// Serialize to a passed-in buffer. from_pos should be the position in the buffer to overwrite the serialized data
    /// into.  Note if from_pos is larger than the buffer, the buffer will be grown to encompass from_pos!
    /// In any case, the buffer will always be grown to accomodate the data if it's not big enough to hold it.
    /// Specify from_pos=-1 for appending at the end.  Returns a reference to the passed-in buffer.  This is very fast
    /// and done in-place.
    template <typename BitcoinObject>
    QByteArray & Serialize(QByteArray &buf, const BitcoinObject &thing, int from_pos = -1, bool allowSegWit = false,
                           bool allowMW = false)
    {
        if (from_pos < 0) from_pos = buf.size();
        int version = bitcoin::PROTOCOL_VERSION;
        if (allowSegWit) version |=  bitcoin::SERIALIZE_TRANSACTION_USE_WITNESS;
        if (allowMW) version |= bitcoin::SERIALIZE_TRANSACTION_USE_MWEB;
        bitcoin::GenericVectorWriter<QByteArray> vw(bitcoin::SER_NETWORK, version, buf, from_pos);
        thing.Serialize(vw);
        return buf;
    }
    /// Convenience for above -- serialize to a new QByteArray directly
    template <typename BitcoinObject>
    QByteArray Serialize(const BitcoinObject &thing, bool allowSegWit = false, bool allowMW = false)
    {
        QByteArray ret;
        Serialize(ret, thing, -1, allowSegWit, allowMW);
        return ret;
    }
    /// Deserialize to a pre-allocated bitcoin object such as bitcoin::CBlock, bitcoin::CBlockHeader,
    /// bitcoin::CMutableTransaction, etc
    template <typename BitcoinObject,
              /// NB: This in-place Deserialization does *NOT* work with CTransaction because if has const-fields.
              /// (use the non-in-place specialization instead)
              std::enable_if_t<!std::is_same_v<BitcoinObject, bitcoin::CTransaction>, int> = 0 >
    void Deserialize(BitcoinObject &thing, const QByteArray &bytes, int pos = 0, bool allowSegWit = false,
                     bool allowMW = false, bool allowCashTokens = true, bool throwIfJunkAtEnd = false)
    {
        int version = bitcoin::PROTOCOL_VERSION;
        if (allowSegWit) version |= bitcoin::SERIALIZE_TRANSACTION_USE_WITNESS;
        if (allowMW) version |= bitcoin::SERIALIZE_TRANSACTION_USE_MWEB;
        if (allowCashTokens) version |= bitcoin::SERIALIZE_TRANSACTION_USE_CASHTOKENS;
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, version, bytes, pos);
        thing.Unserialize(vr);
        if (throwIfJunkAtEnd && !vr.empty())
            throw std::ios_base::failure("Got unprocessed bytes at the end when deserializeing a bitcoin object");
    }
    /// Convenience for above.  Create an instance of object and deserialize to it
    template <typename BitcoinObject>
    BitcoinObject Deserialize(const QByteArray &bytes, int pos = 0, bool allowSegWit = false, bool allowMW = false,
                              bool allowCashTokens = true, bool noJunkAtEnd = false)
    {
        BitcoinObject ret;
        Deserialize(ret, bytes, pos, allowSegWit, allowMW, allowCashTokens, noJunkAtEnd);
        return ret;
    }

    template <typename BitcoinObject>
    struct is_block_or_tx {
        using BO = std::decay_t<BitcoinObject>;
        static constexpr bool value = std::is_base_of_v<bitcoin::CBlock, BO>
                                      || std::is_same_v<bitcoin::CTransaction, BO>
                                      || std::is_same_v<bitcoin::CMutableTransaction, BO>;
    };

    template <typename BitcoinObject>
    inline constexpr bool is_block_or_tx_v = is_block_or_tx<BitcoinObject>::value;

    /// Template specialization for CTransaction which has const fields and works a little differently
    template <> inline bitcoin::CTransaction Deserialize(const QByteArray &ba, int pos, bool allowSegWit, bool allowMW,
                                                         bool allowCashTokens, bool noJunkAtEnd)
    {
        // This *does* move the vectors from CMutableTransaction -> CTransaction
        return bitcoin::CTransaction{Deserialize<bitcoin::CMutableTransaction>(ba, pos, allowSegWit, allowMW,
                                                                               allowCashTokens, noJunkAtEnd)};
    }

    /// Convenience to deserialize segwit object (block or tx) (Core only)
    template <typename BitcoinObject>
    std::enable_if_t<is_block_or_tx_v<BitcoinObject>, BitcoinObject>
    /* BitcoinObject */ DeserializeSegWit(const QByteArray &ba, int pos = 0) {
        return Deserialize<BitcoinObject>(ba, pos, /* segwit= */ true, /* mw= */ false, /* cashtokens= */false);
    }

    /// Convenience to serialize segwit object (block or tx) (Core only)
    template <typename BitcoinObject>
    std::enable_if_t<is_block_or_tx_v<BitcoinObject>, QByteArray>
    /* QByteArray */ SerializeSegWit(const BitcoinObject &bo, int pos = -1) {
        return Serialize<BitcoinObject>(bo, pos, true, false);
    }

    /// Used for scripthash_unspent db value and/or for TXOInfo inside utxoset db. May throw on deser failure or will
    /// return a null object if `pos` is at end already. Will throw if there is junk at the end after deserialization.
    /// If the passed-in `ba` is not empty, the first byte MUST be bitcoin::token::PREFIX_BYTE otherwise this throws.
    /// The number of bytes consumed is always ba.length().
    bitcoin::token::OutputDataPtr DeserializeTokenDataWithPrefix(const QByteArray &ba, int pos);
    /// Appends prefix + token data to the end of byte stream `ba`. Will pre-reserve space first. May throw (unlikely).
    void SerializeTokenDataWithPrefix(QByteArray &ba, const bitcoin::token::OutputData *ptokenData);

    /// Helper -- returns the size of a block header. Should always be 80. Update this if that changes.
    constexpr int GetBlockHeaderSize() noexcept { return 80; }

    /// Returns the sha256 double hash (not reveresed -- little endian) of the input QByteArray. The results are copied
    /// once from the hasher into the returned QByteArray.  This is faster than obtaining a uint256 from bitcoin::Hash
    /// then converting to a QByteArray manually.
    /// Optionally, can hash once (a-la ElectrumX) if once=true
    extern QByteArray Hash(const QByteArray &, bool once = false);
    /// Identical to the above except it returns the REVERSED hash (which is what bitcoind gives you via JSON RPC or
    /// when doing uint256.ToString()). That is, this hash is in big-endian byte order.
    extern QByteArray HashRev(const QByteArray &, bool once = false);
    /// sha256d of the concatenation of a and b. This is faster than but equivalent to doing: Hash(a + b, false).
    extern QByteArray HashTwo(const QByteArray &a, const QByteArray &b);
    /// Convenient alias for Hash(b, true)
    inline QByteArray HashOnce(const QByteArray &b) { return Hash(b, true); }
    /// Like the Hash() function above, except does hash160 once. (not reversed).
    extern QByteArray Hash160(const QByteArray &);
    /// Hash any Bitcoin object in-place and return the hash. If `once` == true, we do single-sha256 hashing. If
    /// `reversed` == true, we reverse the result (making it big-endian ready for JSON).
    template <typename BitcoinObject>
    QByteArray HashInPlace(const BitcoinObject &bo, bool once = false, bool reversed = false) {
        QByteArray ret(bitcoin::CHash256::OUTPUT_SIZE, Qt::Uninitialized); // allocate without initializing
        bitcoin::SerializeHashInPlace(ret.data(), bo, bitcoin::SER_GETHASH, bitcoin::PROTOCOL_VERSION, once);
        if (reversed) std::reverse(ret.begin(), ret.end());
        return ret;
    }

    /// Takes a hash in bitcoin memory order and returns a deep copy QByteArray of the data, reversed
    /// (this is intended to keep our representation of bitcoin data closer to how we will send it to clients down
    /// the wire -- we send all hex encoded hashes in reverse order as is customary when representing bitcoin
    /// hashes in hex). See BlockProc.cpp for an example of where this is used.
    template <class BitcoinHashT>
    QByteArray Hash2ByteArrayRev(const BitcoinHashT &hash) {
        QByteArray ret(reinterpret_cast<const char *>(hash.begin()), hash.width()); // deep copy
        std::reverse(ret.begin(), ret.end()); // reverse it
        return ret;
    };

    /// returns true iff cscript is OP_RETURN, false otherwise
    inline bool IsOpReturn(const bitcoin::CScript &cs) {
        return cs.size() > 0 && *cs.begin() == bitcoin::opcodetype::OP_RETURN;
    }

    inline QByteArray HashXFromByteView(const ByteView &bv) { return BTC::HashRev(bv.toByteArray(false), true); }
    inline QByteArray HashXFromCScript(const bitcoin::CScript &cs) { return HashXFromByteView(cs); }

    /// Header Chain Verifier -
    /// To use: Basically keep calling operator() on it with subsequent headers and it will make sure
    /// hashPrevBlock of the current header matches the computed hash of the last header.
    /// If that is ever not the case, operator() returns false. Returns true otherwise.
    class HeaderVerifier {
        QByteArray prev; // 80 byte header data or empty
        long prevHeight = -1;

        bool checkInner(long height, const bitcoin::CBlockHeader &, QString *err);
    public:
        HeaderVerifier() = default;
        HeaderVerifier(unsigned fromHeight) : prevHeight(long(fromHeight)-1) {}

        /// keep calling this from a loop. Returns false if current header's hashPrevBlock  != the last header's hash.
        bool operator()(const QByteArray & header, QString *err = nullptr);
        bool operator()(const bitcoin::CBlockHeader & header, QString *err = nullptr);
        /// returns the height, 80 byte header of the last header seen. If no headers seen, returns (-1, Empty QByteArray)
        std::pair<int, QByteArray> lastHeaderProcessed() const;

        bool isValid() const { return prev.length() == GetBlockHeaderSize(); }
        void reset(unsigned nextHeight = 0, QByteArray prevHeader = QByteArray()) { prevHeight = long(nextHeight)-1; prev = prevHeader; }
    };

    /// Trivial hasher for sha256, rmd160, etc hashed byte arrays (for use with std::unordered_map,
    /// std::unordered_set, etc) -- just returns the middle 8 bytes reinterpreted as size_t since hashed data is
    /// already randomized.
    template <typename BytesT>
    struct GenericTrivialHashHasher {
        static_assert(std::is_convertible_v<BytesT, ByteView>, "Assumption here is that BytesT has an implicit conversion to ByteView");

        std::size_t operator()(const ByteView &bv) const noexcept {
            if (const auto bvsz = bv.size(); LIKELY(bvsz >= sizeof(std::size_t))) {
                // common case, just return the middle 8 bytes reinterpreted as size_t since this is already
                // a random hash.
                std::size_t ret;
                // We take the middle bytes of the hash just to prevent some strange sorts of hash collisions if people
                // "mine" txids (or hash160 addresses) or somesuch, or in case this hasher was inadvertently used with
                // a blockhash instead of a txid or hash160.
                const auto offset = bvsz / 2 - sizeof(ret) / 2;
                std::memcpy(reinterpret_cast<std::byte *>(&ret), bv.data() + offset, sizeof(ret));
                return ret;
            }
            // this should not normally be reached.
            return Util::hashForStd(bv);
        }
    };

    // useful type aliases to be passed as template args to eg std::unordered_map, robin_hood::unordered_flat_map, etc
    using QByteArrayHashHasher = GenericTrivialHashHasher<QByteArray>;
    using uint256HashHasher = GenericTrivialHashHasher<bitcoin::uint256>;
    using uint160HashHasher = GenericTrivialHashHasher<bitcoin::uint160>;

    /// After Nov. 2018, reorgs beyond this depth can not normally occur without user intervention.
    /// We use this constant to decide how far back a peer's headers have to agree with our headers
    /// before we disconnect from that peer in PeerMgr, declaring them as "serving up another chain".
    static constexpr unsigned DefaultBCHFinalizationDepth = 10;

    // -- The below Net-related stuff is mainly used by the BTC::Address class, but may be of general interest so it's
    //    been placed here.  See BTC_Address.h for how it's used.

    using Byte = uint8_t;

    enum Net : Byte {
        Invalid = 0xff,
        MainNet = 0x80, ///< matches secret key byte
        TestNet = 0xef, ///< matches secret key byte
        TestNet4 = TestNet+1, ///< does not match anything in the bitcoin world, just an enum value
        ScaleNet = TestNet+2, ///< does not match anything in the bitcoin world, just an enum value
        RegTestNet = TestNet+3, ///< does not match anything in the bitcoin world, just an enum value
        ChipNet = TestNet+4, ///< does not match anything in the bitcoin world, just an enum value
    };

    /// Given a Net, returns its name e.g. "main", "test", "regtest" (or "invalid" if parameter `net` is not valid).
    const QString & NetName(Net net) noexcept;
    /// Given a network name e.g. "main" or "test", returns the Net enum value, or Net::Invalid if parameter `name` is
    /// not recognized.
    Net NetFromName(const QString & name) noexcept;
    /// Given a network name e.g. "mainnet" or "test" or "main" or "testnet3" -> transform it to the canonical name
    /// (such as "main", "test").  This is so that our app uses a single consistent string name for all net names
    /// as reported by the bitcoin daemon (bchd uses different net names than bitcoind).
    inline const QString & NetNameNormalize(const QString &name) noexcept { return NetName(NetFromName(name)); }

} // end namespace


/// Utility -- compare any uint256 with a QByteArray for equality
inline bool operator==(const bitcoin::uint256 &hash, const QByteArray &ba) noexcept {
    constexpr int sz = bitcoin::uint256::width();
    if (ba.size() != sz) return false;
    return std::memcmp(hash.data(), ba.constData(), size_t(sz)) == 0;
}
inline bool operator==(const QByteArray &ba, const bitcoin::uint256 &hash) noexcept { return hash == ba; }
inline bool operator!=(const bitcoin::uint256 &hash, const QByteArray &ba) noexcept { return !(hash == ba); }
inline bool operator!=(const QByteArray &ba, const bitcoin::uint256 &hash) noexcept { return !(hash == ba); }

Q_DECLARE_METATYPE(BTC::Coin);
