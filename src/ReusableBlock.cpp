//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "ReusableBlock.h"

#include <cstring> // for std::memcpy
#include <type_traits>

namespace {
// we can save some space on disk by using uint32_t - max size is dependent on block, so if blocks overflow uint32::max txs this could fail
using HATSerializationVectorSizeType = uint32_t;

struct ReusableHATSerializer {
    QByteArray store;

    ReusableHATSerializer() {}

    template <typename T, std::enable_if_t<std::is_arithmetic_v<T>>* = nullptr> // required support for uint64_t and float (WHY float? see https://github.com/Tessil/hat-trie note about serialization)
    void operator()(const T& value) {
        store.append(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    void operator()(const PrefixMap::mapped_type& value) { // specialize for our list of TxNums
        HATSerializationVectorSizeType size = value.size();
        store.append(reinterpret_cast<const char*>(&size), sizeof(size));
        store.append(reinterpret_cast<const char*>(value.data()), size * sizeof(TxNum));
    }

    void operator()(const char* value, std::size_t value_size) {
        store.append(reinterpret_cast<const char*>(value), value_size);
    }
};

struct ReusableHATDeserializer {
    QByteArray store;
    size_t offset = 0u;

    explicit ReusableHATDeserializer(const QByteArray &store_): store(store_) {}

    template <typename T,
              std::enable_if_t<std::is_arithmetic_v<T>>* = nullptr> // required support for uint64_t and float (see note above)
    T operator()() {
        checkReadSizeOk(sizeof(T));
        T value;
        std::memcpy(reinterpret_cast<char*>(&value), store.constData() + offset, sizeof(T));
        offset += sizeof(T);
        return value;
    }

    template <typename T,
              std::enable_if_t<! std::is_arithmetic_v<T>>* = nullptr> // invert the above specialzation for vector (TODO make this more clean)
    T operator()() { // specialization on our value type for deserialization
        static_assert(std::is_same_v<T, PrefixMap::mapped_type>);
        HATSerializationVectorSizeType size = 0;
        size_t bytesToRead = sizeof(size);
        checkReadSizeOk(bytesToRead);
        std::memcpy(reinterpret_cast<char*>(&size), store.constData() + offset, bytesToRead);
        offset += bytesToRead;

        static_assert(std::is_same_v<TxNum, PrefixMap::mapped_type::value_type>);
        bytesToRead = size * sizeof(TxNum); // read "size" TxNums
        checkReadSizeOk(bytesToRead);
        PrefixMap::mapped_type value(size, TxNum{}); // resize our vector so we can copy into it without causing explosion
        std::memcpy(reinterpret_cast<char*>(value.data()), store.constData() + offset, bytesToRead);
        offset += bytesToRead;

        return value;
    }

    void operator()(char* value_out, size_t value_size) {
        checkReadSizeOk(value_size);
        std::memcpy(value_out, store.constData() + offset, value_size);
        offset += value_size;
    }

private:
    void checkReadSizeOk(const size_t bytesToRead) const {
        if (offset + bytesToRead > static_cast<size_t>(store.size()))
            throw InternalError("Attempt to read past end of buffer");
    }
};

} // namespace

QByteArray ReusableBlock::toBytes() const {
    ReusableHATSerializer serializer;
    pmap.serialize(serializer);
    return serializer.store;
}

/* static */ ReusableBlock ReusableBlock::fromBytes(const QByteArray &ba) {
    ReusableHATDeserializer deserializer(ba);
    ReusableBlock ret;
    ret.pmap = PrefixMap::deserialize(deserializer);
    return ret;
}

#ifdef ENABLE_TESTS
#include "App.h"

#include <QRandomGenerator>

#include <algorithm>
#include <array>
#include <map>
#include <vector>

namespace {
    void test()
    {
        QRandomGenerator *rgen = QRandomGenerator::global();
        if (rgen == nullptr) throw Exception("Failed to obtain random number generator");
        auto genRandomRuHash = [rgen] {
            using Arr = std::array<quint32, HashLen / sizeof(quint32)>;
            static_assert(Arr{}.size() * sizeof(quint32) == HashLen);
            // Lazy but who really would be so pedantic to care. Generate 8 32-bit ints = 256-bits (32-byte) random
            // hash.
            Arr randNums;
            rgen->generate(randNums.begin(), randNums.end());
            return RuHash(reinterpret_cast<const char *>(std::as_const(randNums).data()), HashLen);
        };

        using PrefixTable = std::map<std::string, std::vector<TxNum>>;
        PrefixTable prefixTable;

        Log() << "Testing ReusableBlock add...";
        ReusableBlock ru;
        for (size_t i = 0u; i < 1'000'000u; ++i) {
            const auto randHash = genRandomRuHash();
            const TxNum n = rgen->generate();
            ru.add(randHash, n); // add to prefix trie
            const auto prefix = ReusableBlock::ruHashToPrefix(randHash);
            prefixTable[prefix].push_back(n);
        }
        for (auto & [pfx, vec] : prefixTable)
            std::sort(vec.begin(), vec.end()); // ensure our check table is sorted

        struct CheckFail : Exception { using Exception::Exception; };
        auto checkRuEqualsTable = [](const ReusableBlock & rb, const PrefixTable & pft) {
            if (rb.size() != pft.size())
                throw CheckFail("ReusableBlock's size does not equal the check-table's size");

            // check everything in the table is in the prefix map
            for (const auto & [prefix, vec] : pft) {
                std::vector<TxNum> nums;
                const auto & [rangeBegin, rangeEnd] = rb.prefixSearch(prefix);
                for (auto it = rangeBegin; it != rangeEnd; ++it) {
                    nums.insert(nums.end(), it->begin(), it->end());
                }
                std::sort(nums.begin(), nums.end());
                // the vector of txnums now should equal prefixTable
                if (nums != vec)
                    throw CheckFail("ReusableBlock has consistency errors");
            }
        };
        Log() << "Testing ReusableBlock prefixSearch...";
        checkRuEqualsTable(ru, prefixTable);

        Log() << "Testing ReusableBlock serialize...";
        QByteArray serialized = ru.toBytes();

        Log() << "Testing ReusableBlock deserialize...";
        ReusableBlock ru2 = ReusableBlock::fromBytes(serialized);

        Log() << "Testing ReusableBlock equality...";
        if (ru != ru2)
            throw Exception("ReusableBlock not equal");

        Log() << "Testing ReusableBlock remove...";
        auto prefixTable2 = prefixTable;
        size_t i = 0;
        for (const auto & [pfx, vec] : prefixTable2) {
            prefixTable.erase(pfx);
            ru.removeForPrefix(pfx);
            if (++i % 10'000u == 0) {
                // check every 10,000th iteration that remove did what we expect (if we check every iteration this is SUPER slow!)
                checkRuEqualsTable(ru, prefixTable);
            }
        }
        checkRuEqualsTable(ru, prefixTable);
        checkRuEqualsTable(ru2, prefixTable2);
        auto checkRuNotEqualsTable = [&](const auto &arg1, const auto &arg2) {
            try {
                checkRuEqualsTable(arg1, arg2);
            } catch (const CheckFail &) {
                return;
            }
            throw CheckFail("ReusableBlock inequality check failed!");
        };
        checkRuNotEqualsTable(ru, prefixTable2);
        checkRuNotEqualsTable(ru2, prefixTable);

        Log() << "Testing ReusableBlock serializeInput...";
        // perform serialization of a bitcoin input; this is used to verify the faster ReusableBlock::serializeInput()
        auto serializeInputSlow = [](const bitcoin::CTxIn& input) -> RuHash {
            const auto serInput = BTC::Serialize(input);
            RuHash ruHash = BTC::Hash(serInput, false); // double sha2
            return ruHash;
        };
        std::vector<QByteArray> txStrs = {{
            "0100000001751ac11802cc3e4efc8aaaee87ca818482be9140dd6623f69db2c3af5c0b0ede01000000644161e02824b2ad3e24b19"
            "67ecd2e1bbcb53ca2b7c990802865b7f0f55e861849f7821daff5e78964346b1f7d16e5ce522d3354ca3cc1f6f4cba4ca0e57725a"
            "f59e412102c986f0b3d6f4f8c765469fe0118cf973d676862f358e62a14104fae7d43f3032feffffff02e8030000000000001976a"
            "914ed707a5dbba9f4c117086c547fdc4e1e7a5ba40088accc550100000000001976a914e32151fdef9bc46cbb11514a84f54d8f51"
            "a905e588ac747a0a00",
            "010000000a80042cde613152c5e77bada9a32567816286ef4cc5db92f39c8c385fa8d8c51300000000844110a19868da36f8cbf94"
            "23e7b8943cb76a18e9098a61973747198a358a1e3bf015f50e4609b240fe741da08da2317bfd6a8357e8126be278e509df7ed2f36"
            "001e414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa"
            "7f456634e1bdb11485dbbc9db20cb669dfeffffff6aa672caf2cc24751835cef735020c5e09e593a6e537a4819a7ef316fd99a714"
            "0100000084419d3102d640a5061a8e73dfa7ab2f0d72057d34cad4eb77720fc5a5d3990a79fc831fcf971bebce36b7be12ae7a494"
            "edc2d2e9c694840c641e47c64f50ab88c08414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa3886429"
            "72aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffffdc55076ed9e6f5bad08fa05be0bcded16"
            "9bb8a91dd3c2df0a3a5d741e4d87f280000000084413a0343b34d81b9403b9830f485376a799e10410bcdaa0c0351bb29e8b473dd"
            "40ce20749d049b8f655a8929a883d24e14d9f4f49084c271de53ec09b8e6469607414104e8806002111e3dfb6944e63a424618324"
            "37f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff9f"
            "a13f0698fc362d188fcae4e15d9b3967ef523c0b2d010f76a366b2e5a5773100000000844195dd906186f703505c095e89b06a97e"
            "3c5ec770ac89c721ad15432f0b1a6df5cbd872e23ca8016d7b2411ba7ffaa385f2b70c1d3c16525d342b0db11a35b83b0414104e8"
            "806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bd"
            "b11485dbbc9db20cb669dfeffffff6a49ee1b6fb4a528fb1ceeebc9930662dbe34dce6faa6256300ac263d3dbfd6b070000008441"
            "c421a57150ba601c7238cc9561f1178569f2c4bf471ad8d4b40683fcdebb06fe5e0fd8ae23002fdef975f950aa7df4a0c9edf1b2f"
            "447c99640fba268e8f7ac1f414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcd"
            "c2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff467d33729a55b1afd8556b201667c324b29fb9bcebbc3"
            "11912aecff58b4f9884000000008441d055f348d001335405280134e5ef90b90851ef1dd8a03f4bc4173b0dd1c12ed71a7020e1a1"
            "7e9129640cf2292ad12ce7926778676450bb1f8aebbea153459040414104e8806002111e3dfb6944e63a42461832437f2bbd616fa"
            "cc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff58654b4278c983"
            "119c66f0333dd3528f125c8269de977353a28fb1f46fdfca8e000000008441b7406309983640d6e04fc54709abb5e67f6ee272be2"
            "3242b92a737953d277dff73e2ea9287016f03cc62c099cdf590a6f3a54b91e4708210a7ee653d9e387352414104e8806002111e3d"
            "fb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9d"
            "b20cb669dfeffffff633293fdcdd1a735f31f243d64facd9279d6fa1ae5297db8e9b96010378ec0a00000000084411b7c298f0a4c"
            "238bb57e2d421599fc7f1b150a4d37bc8d1e89aebe840d5224d2167dcb7e34084c4181fae6f2d4ac358302a66d6ecb354335b4d2a"
            "1568ea3c0f8414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e"
            "7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff2ede1f74c36962315a67593f615028faa57335300518029e52593767e"
            "30bcceb0000000084414f93062b38e50e636907d99463aa7439113ad618c2d2b9051ec7a108057169141c0f5532b1211f88bbd8a8"
            "734d667ef863910e9e3bf2f8a2114aa799496f6e22414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa"
            "388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff3bfa6654a76ac12cec72dbc742"
            "be17f4c965b62fea2caf6b7241e14b163290f7010000008441d25525cf580724567390e0ab039011015be2ddab7296631fab5f20f"
            "e03d3eee63888527d9729ebd7060fdbb1b94e85abdcbfcc8518539237d62371d69ae11893414104e8806002111e3dfb6944e63a42"
            "461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfef"
            "fffff01174d7037000000001976a9147ee7b62fa98a985c5553ff66120a91b8189f658188ac931a0900",
        }};
        for (const auto & txStr : txStrs) {
            bitcoin::CMutableTransaction tx;
            BTC::Deserialize(tx, Util::ParseHexFast(txStr), 0, false);

            for (size_t n = 0, sz = tx.vin.size(); n < sz; ++n) {
                const auto & input = tx.vin[n];
                const RuHash ruHash = ReusableBlock::serializeInput(input);
                const RuHash ruHashSlow = serializeInputSlow(input);
                if (ruHash != ruHashSlow) throw Exception("Fast serializeInput does not match the slow version!");
                const std::string ruHashPrefix = ReusableBlock::ruHashToPrefix(ruHash);
                QByteArray prefixHex = Util::ToHexFast(QByteArray::fromStdString(ruHashPrefix));
                // remove leading 0 from hex to match the format we use otherwise
                for (size_t j = 0; j < 4; ++j) {
                    prefixHex.remove(j, 1);
                }
                const auto ruHashHex = Util::ToHexFast(ruHash);
                Log() << "   Txid: " << tx.GetId().ToString() << ":" << n
                      << " RuHash: " << Util::ToHexFast(ruHash)
                      << " Prefix: " << prefixHex;
                if (prefixHex.size() != 4 || ! ruHashHex.startsWith(prefixHex))
                    throw Exception("Prefix is not as expected.");
            }
        }

        Log(Log::Color::BrightWhite) << "All ReusableBlock unit tests passed!";
    }

    static const auto test_ = App::registerTest("reusable", &test);
}
#endif
