//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "bitcoin/script.h"
#include "bitcoin/streams.h"
#include "bitcoin/transaction.h"
#include "bitcoin/version.h"

#include <QByteArray>
#include <QString>
#include <QHash>

#include <cstring> // for memcpy
#include <type_traits>
#include <utility> // for pair, etc

namespace BTC
{
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
    QByteArray & Serialize(QByteArray &buf, const BitcoinObject &thing, int from_pos = -1)
    {
        if (from_pos < 0) from_pos = buf.size();
        bitcoin::GenericVectorWriter<QByteArray> vw(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, buf, from_pos);
        thing.Serialize(vw);
        return buf;
    }
    /// Convenience for above -- serialize to a new QByteArray directly
    template <typename BitcoinObject>
    QByteArray Serialize(const BitcoinObject &thing)
    {
        QByteArray ret;
        Serialize(ret, thing);
        return ret;
    }
    /// Deserialize to a pre-allocated bitcoin object such as bitcoin::CBlock, bitcoin::CBlockHeader, bitcoin::CMutableTransaction, etc
    template <typename BitcoinObject,
              /// NB: This in-place Deserialization does *NOT* work with CTransaction because if has const-fields. (use the non-in-place specialization instead)
              std::enable_if_t<!std::is_same_v<BitcoinObject, bitcoin::CTransaction>, int> = 0 >
    void Deserialize(BitcoinObject &thing, const QByteArray &bytes, int pos = 0)
    {
        bitcoin::GenericVectorReader<QByteArray> vr(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, bytes, pos);
        thing.Unserialize(vr);
    }
    /// Convenience for above.  Create an instance of object and deserialize to it
    template <typename BitcoinObject>
    BitcoinObject Deserialize(const QByteArray &bytes, int pos = 0)
    {
        BitcoinObject ret;
        Deserialize(ret, bytes, pos);
        return ret;
    }
    /// Template specialization for CTransaction which has const fields and works a little differently (impl. in BTC.cpp)
    template <> bitcoin::CTransaction Deserialize(const QByteArray &, int pos);

    /// Helper -- returns the size of a block header. Should always be 80. Update this if that changes.
    constexpr int GetBlockHeaderSize() noexcept { return 80; }

    /// Returns the sha256 double hash (not reveresed) of the input QByteArray. The results are copied once from the
    /// hasher into the returned QByteArray.  This is faster than obtaining a uint256 from bitcoin::Hash then converting
    /// to a QByteArray manually.
    /// Optionally, can hash once (a-la ElectrumX) if once=true
    extern QByteArray Hash(const QByteArray &, bool once = false);
    /// Identical to the above except it returns the REVERSED hash (which is what bitcoind gives you via JSON RPC or
    /// when doing uint256.ToString()).
    extern QByteArray HashRev(const QByteArray &, bool once = false);
    /// Convenient alias for Hash(b, true)
    inline QByteArray HashOnce(const QByteArray &b) { return Hash(b, true); }
    /// Like the Hash() function above, except does hash160 once. (not reversed).
    extern QByteArray Hash160(const QByteArray &);

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

    inline QByteArray HashXFromCScript(const bitcoin::CScript &cs) {
        return QByteArray(BTC::HashRev(QByteArray::fromRawData(reinterpret_cast<const char *>(cs.data()), int(cs.size())), true));
    }

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
    /// std::unordered_set, etc) -- just returns the first 8 bytes reinterpreted as size_t since hashed data is
    /// already randomized.
    template <typename BytesT>
    struct GenericTrivialHashHasher {
        std::size_t operator()(const BytesT &b) const noexcept {
            if (LIKELY(std::size_t(b.size()) >= sizeof(std::size_t))) {
                // common case, just return the first 8 bytes reinterpreted as size_t since this is already
                // a random hash.
                static_assert (std::is_scalar_v<std::remove_pointer_t<decltype (b.begin())>>,
                               "GenericTrivialHasher must be used with a container type where .begin() returns a pointer to its data." );
                std::size_t ret;
                std::memcpy(&ret, b.begin(), sizeof(ret));
                return ret;
            }
            return hasher32(qHash(b, 0xf1234567)); // this should not normally be reached.
        }
    private:
        std::hash<uint> hasher32;
    };

    // useful type aliases to be passed as template args to eg std::unordered_map, robin_hood::unordered_flat_map, etc
    using QByteArrayHashHasher = GenericTrivialHashHasher<QByteArray>;
    using uint256HashHasher = GenericTrivialHashHasher<bitcoin::uint256>;
    using uint160HashHasher = GenericTrivialHashHasher<bitcoin::uint160>;

    /// After Nov. 2018, reorgs beyond this depth can never occur. We use this constant to limit the configurable minimum
    /// undo size.  For now, it's hard-coded at 100 blocks in Storage.h.
    static constexpr unsigned MaxReorgDepth = 10;

    // -- The below Net-related stuff is mainly used by the BTC::Address class, but may be of general interest so it's
    //    been placed here.  See BTC_Address.h for how it's used.

    using Byte = uint8_t;

    enum Net : Byte {
        Invalid = 0xff,
        MainNet = 0x80, ///< matches secret key byte
        TestNet = 0xef, ///< matches secret key byte
        RegTestNet = TestNet+1, ///< does not match anything in the bitcoin world, just an enum value
    };

    /// Given a Net, returns its name e.g. "main", "test", "regtest" (or "invalid" if parameter `net` is not valid).
    const QString & NetName(Net net) noexcept;
    /// Given a network name e.g. "main" or "test", returns the Net enum value, or Net::Invalid if parameter `name` is
    /// not recognized.
    Net NetFromName(const QString & name) noexcept;

} // end namespace
