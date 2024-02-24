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
#include "BTC.h"
#include "Common.h"
#include "Util.h"

#include "bitcoin/crypto/endian.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/hash.h"

#include <QMap>

#include <algorithm>
#include <utility>

namespace bitcoin
{
    inline void Endian_Check_In_namespace_bitcoin()
    {
        constexpr uint32_t magicWord = 0x01020304;
        const uint8_t wordBytes[4] = {0x01, 0x02, 0x03, 0x04}; // represent above as big endian
        const uint32_t bytesAsNum = *reinterpret_cast<const uint32_t *>(wordBytes);

        if (magicWord != be32toh(bytesAsNum))
        {
            throw Exception(QString("Program compiled with incorrect WORDS_BIGENDIAN setting.\n\n")
                            + "How to fix this:\n"
                            + " 1. Adjust WORDS_BIGENDIAN in the qmake .pro file to match your architecture.\n"
                            + " 2. Re-run qmake.\n"
                            + " 3. Do a full clean recompile.\n\n");
        }
    }
    extern bool TestBase58(bool silent, bool throws);
}

namespace BTC
{
    void CheckBitcoinEndiannessAndOtherSanityChecks() {
        bitcoin::Endian_Check_In_namespace_bitcoin();
        auto impl = bitcoin::SHA256AutoDetect();
        Debug() << "Using sha256: " << QString::fromStdString(impl);
        if ( ! bitcoin::CSHA256::SelfTest() )
            throw InternalError("sha256 self-test failed. Cannot proceed.");
        Tests::Base58(true, true);
    }


    namespace Tests {
        bool Base58(bool silent, bool throws) { return bitcoin::TestBase58(silent, throws); }
    }


    QByteArray Hash(const QByteArray &b, bool once)
    {
        bitcoin::CHash256 h(once);
        QByteArray ret(QByteArray::size_type(h.OUTPUT_SIZE), Qt::Initialization::Uninitialized);
        h.Write(reinterpret_cast<const uint8_t *>(b.constData()), static_cast<size_t>(b.length()));
        h.Finalize(reinterpret_cast<uint8_t *>(ret.data()));
        return ret;
    }

    QByteArray HashRev(const QByteArray &b, bool once)
    {
        QByteArray ret = Hash(b, once);
        std::reverse(ret.begin(), ret.end());
        return ret;
    }

    QByteArray HashTwo(const QByteArray &a, const QByteArray &b)
    {
        bitcoin::CHash256 h(/* once = */false);
        QByteArray ret(QByteArray::size_type(h.OUTPUT_SIZE), Qt::Initialization::Uninitialized);
        h.Write(reinterpret_cast<const uint8_t *>(a.constData()), static_cast<size_t>(a.length()));
        h.Write(reinterpret_cast<const uint8_t *>(b.constData()), static_cast<size_t>(b.length()));
        h.Finalize(reinterpret_cast<uint8_t *>(ret.data()));
        return ret;
    }

    QByteArray Hash160(const QByteArray &b) {
        bitcoin::CHash160 h;
        QByteArray ret(QByteArray::size_type(h.OUTPUT_SIZE), Qt::Initialization::Uninitialized);
        h.Write(reinterpret_cast<const uint8_t *>(b.constData()), static_cast<size_t>(b.length()));
        h.Finalize(reinterpret_cast<uint8_t *>(ret.data()));
        return ret;
    }

    // HeaderVerifier helper
    bool HeaderVerifier::operator()(const QByteArray & header, QString *err)
    {
        const long height = prevHeight+1;
        if (header.size() != BTC::GetBlockHeaderSize()) {
            if (err) *err = QString("Header verification failed for header at height %1: wrong size").arg(height);
            return false;
        }
        bitcoin::CBlockHeader curHdr = Deserialize<bitcoin::CBlockHeader>(header);
        if (!checkInner(height, curHdr, err))
            return false;
        prevHeight = height;
        prev = header;
        if (err) err->clear();
        return true;
    }
    bool HeaderVerifier::operator()(const bitcoin::CBlockHeader &curHdr, QString *err)
    {
        const long height = prevHeight+1;
        QByteArray header = Serialize(curHdr);
        if (header.size() != BTC::GetBlockHeaderSize()) {
            if (err) *err = QString("Header verification failed for header at height %1: wrong size").arg(height);
            return false;
        }
        if (!checkInner(height, curHdr, err))
            return false;
        prevHeight = height;
        prev = header;
        if (err) err->clear();
        return true;
    }

    bool HeaderVerifier::checkInner(long height, const bitcoin::CBlockHeader &curHdr, QString *err)
    {
        if (curHdr.IsNull()) {
            if (err) *err = QString("Header verification failed for header at height %1: failed to deserialize").arg(height);
            return false;
        }
        if (!prev.isEmpty() && Hash(prev) != QByteArray::fromRawData(reinterpret_cast<const char *>(curHdr.hashPrevBlock.begin()), int(curHdr.hashPrevBlock.width())) ) {
            if (err) *err = QString("Header %1 'hashPrevBlock' does not match the contents of the previous block").arg(height);
            return false;
        }
        return true;
    }
    std::pair<int, QByteArray> HeaderVerifier::lastHeaderProcessed() const
    {
        return { int(prevHeight), prev };
    }


    namespace {
        // Cache the netnames as QStrings since we will need them later for blockchain.address.* methods in Servers.cpp
        // Note that these must always match whatever bitcoind calls these because ultimately we decide what network
        // we are on by asking bitcoind what net it's on via the "getblockchaininfo" RPC call (upon initial synch).
        const QMap<Net, QString> netNameMap = {{
            // These names are all the "canonical" or normalized names (they are what BCHN calls them)
            // Note that bchd has altername names for these (see nameNetMap below).
            { MainNet, "main"},
            { TestNet, "test"},
            { TestNet4, "test4"},
            { ScaleNet, "scale"},
            { RegTestNet, "regtest"},
            { ChipNet, "chip"},
        }};
        const QMap<QString, Net> nameNetMap = {{
            {"main",     MainNet},     // BCHN, BU, ABC, Core, LitecoinCore
            {"mainnet",  MainNet},     // bchd
            {"test",     TestNet},     // BCHN, BU, ABC, Core, LitecoinCore
            {"test4",    TestNet4},    // BCHN, BU
            {"scale",    ScaleNet},    // BCHN, BU
            {"testnet3", TestNet},     // bchd
            {"testnet4", TestNet4},    // possible future bchd
            {"regtest",  RegTestNet},  // BCHN, BU, ABC, bchd, Core, LitecoinCore
            {"signet",   TestNet},     // Core only
            {"chip",     ChipNet},     // BCH only
        }};
        const QString invalidNetName = "invalid";
    };
    const QString & NetName(Net net) noexcept {
        if (auto it = netNameMap.find(net); it != netNameMap.end())
            return it.value();
        return invalidNetName; // not found
    }
    Net NetFromName(const QString & name) noexcept {
        return nameNetMap.value(name, Net::Invalid /* default if not found */);
    }

    namespace { const QString coinNameBCH{"BCH"}, coinNameBTC{"BTC"}, coinNameLTC{"LTC"}; }
    QString coinToName(Coin c) {
        QString ret; // for NRVO
        switch (c) {
        case Coin::BCH: ret = coinNameBCH; break;
        case Coin::BTC: ret = coinNameBTC; break;
        case Coin::LTC: ret = coinNameLTC; break;
        case Coin::Unknown: break;
        }
        return ret;
    }
    Coin coinFromName(const QString &s) {
        if (s == coinNameBCH) return Coin::BCH;
        if (s == coinNameBTC) return Coin::BTC;
        if (s == coinNameLTC) return Coin::LTC;
        return Coin::Unknown;
    }

    bitcoin::token::OutputDataPtr DeserializeTokenDataWithPrefix(const QByteArray &ba, int pos) {
        bitcoin::token::OutputDataPtr ret;
        if (ba.size() - pos > 0) {
            // attempt to deserialize token data
            if (uint8_t(ba[pos++]) != bitcoin::token::PREFIX_BYTE) // Expect: 0xef
                throw std::ios_base::failure(
                    strprintf("Expected token prefix byte 0x%02x, instead got 0x%02x in %s at position %i",
                              bitcoin::token::PREFIX_BYTE, uint8_t(ba[pos-1]), __func__, pos-1));
            ret.emplace();
            BTC::Deserialize<bitcoin::token::OutputData>(*ret, ba, pos , false, false,
                                                         true /* cashTokens */,
                                                         true /* noJunkAtEnd */);
        }
        return ret;
    }

    void SerializeTokenDataWithPrefix(QByteArray &ba, const bitcoin::token::OutputData *ptokenData) {
        if (ptokenData) {
            ba.reserve(ba.size() + 1 + ptokenData->EstimatedSerialSize());
            ba.append(char(bitcoin::token::PREFIX_BYTE)); // append PREFIX_BYTE since we expect it on deser
            BTC::Serialize(ba, *ptokenData); // append serialized token data
        }
    }


} // end namespace BTC


#ifdef ENABLE_TESTS
#include "App.h"

#include "bitcoin/transaction.h"
#include "bitcoin/uint256.h"

namespace {
    void test()
    {
        // Misc. unit tests for BTC namespace utility functions
        Log() << "Testing Hash2ByteArrayRev ...";
        bitcoin::uint256 hash = bitcoin::uint256S("080bb1010c4d32f3cb16c6a7f1ac2a949d0b5b0f0396f183870be7032cfc4da9");
        if (hash.ToString() != "080bb1010c4d32f3cb16c6a7f1ac2a949d0b5b0f0396f183870be7032cfc4da9") throw Exception("Hash parse fail");
        const QByteArray qba(reinterpret_cast<const char *>(std::as_const(hash).data()), hash.size());
        if (ByteView{hash} != ByteView{qba}) throw Exception("2");
        if (qba.toHex() != "a94dfc2c03e70b8783f196030f5b0b9d942aacf1a7c616cbf3324d0c01b10b08") throw Exception("Hash parse did not yield expected result");
        auto rhash = BTC::Hash2ByteArrayRev(hash);
        Debug() << "Expected hash: " << rhash.toHex();
        if (rhash.toHex() != "080bb1010c4d32f3cb16c6a7f1ac2a949d0b5b0f0396f183870be7032cfc4da9") throw Exception("BTC::Hash2ByteArrayRev is broken");

        Log() << "Testing Deserialize ...";
        const auto txnhex = "0100000001e7b81293c58fa088412949e485f7a7310c386a267a1825284e79c083d26b55670000000084410b00"
                            "086668d9c26c3bf44b4f136512d7edae0f01ddd66844e312fa00f54250e93457b5e2c823ca31ab452d22f27181"
                            "b13ce3560b974130b5e8a9e1b3ab820d0d414104e8806002111e3dfb6944e63a42461832437f2bbd616facc269"
                            "10becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff01fb"
                            "0cfe00000000001976a914590888ac04b1f1cf01f08110cca83dd3e3da7f7388accbb90c00";
        auto tx = BTC::Deserialize<bitcoin::CTransaction>(Util::ParseHexFast(txnhex));
        if (hash != tx.GetHash()) throw Exception("Txn did not deserialize ok");

        Log() << "Testing HashInPlace ...";
        if (BTC::HashInPlace(tx) != qba) throw Exception("Txn hash in place failed");
        if (BTC::HashInPlace(tx, false, /* reversed = */true) != rhash) throw Exception("Txn hash in place reversed failed");

        Log(Log::BrightWhite) << "All btcmisc unit tests passed!";
    }

    auto t1 = App::registerTest("btcmisc", test);
} // namespace
#endif
