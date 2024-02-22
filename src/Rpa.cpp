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
#include "Rpa.h"

#include "BTC.h"
#include "PackedNumView.h"
#include "Util.h"

#include "bitcoin/crypto/endian.h"

#include <algorithm>
#include <cassert>
#include <cstring> // for std::memcpy
#include <stdexcept> // for std::invalid_argument
#include <string>
#include <type_traits>

namespace Rpa {

Hash::Hash(const bitcoin::CTxIn &txin) : QByteArray(BTC::HashInPlace(txin)) {}

Prefix::Prefix(uint16_t num, uint8_t bits_)
    : bits{std::clamp<uint8_t>(bits_, 8u, PrefixBits)},
      n{static_cast<uint16_t>(uint32_t{num} & (static_cast<uint32_t>((1u << bits) - 1u) << (PrefixBits - bits)))},
      bytes{static_cast<uint8_t>(n >> 8u), static_cast<uint8_t>(n & 0xffu)} {
    if (bits_ < 8u || bits_ > 16u) throw std::invalid_argument("Prefix bits may not be <8 or >16!");
}

Prefix::Prefix(const Hash & h) {
    if (h.isEmpty()) throw std::invalid_argument("Provided Rpa::Hash is empty!");
    bits = h.size() == 1u ? 8u : PrefixBits;
    unsigned i;
    for (i = 0u; i < std::min(PrefixBytes, size_t(h.size())); ++i)
        bytes[i] = static_cast<uint8_t>(h[i]);
    for ( ; i < PrefixBytes; ++i)
        bytes[i] = 0u; // fill rest with 0's
    std::memcpy(&n, bytes.data(), PrefixBytes);
    n = bitcoin::be16toh(n); // swab to host byte order from big endian
}

auto Prefix::range() const -> Range {
    assert(bits > 0u && bits <= PrefixBits); // NB: c'tor prevents PrefixBits from being 0 or >16!
    const uint32_t offset = 1u << (PrefixBits - std::min(bits, uint8_t{PrefixBits}));
    return {n, n + offset};
}

size_t PrefixTable::elementCount() const {
    size_t ct = 0u;
    for (const auto & v : *this) ct += v.size();
    return ct;
}

template <typename Ret>
Ret PrefixTable::serializeRow(size_t index) const {
    const auto & vec = at(index);
    using PNV = PackedNumView<SerializedTxNumBits>;
    const typename Ret::size_type bytesNeeded = vec.size() * PNV::bytesPerElement;
    constexpr auto initialization = [] {
        if constexpr (std::is_same_v<Ret, QByteArray>) return Qt::Uninitialized;
        else return '\0';
    }();
    Ret ret(bytesNeeded, initialization);
    PNV::Make(MakeUInt8Span(ret), Span{vec});
    return ret;
}

template QByteArray PrefixTable::serializeRow<QByteArray>(size_t index) const;
template std::string PrefixTable::serializeRow<std::string>(size_t index) const;

void PrefixTable::addForPrefix(const Prefix &p, TxNum n) {
    const auto [b, e] = p.range();
    for (size_t i = b; i < e; ++i) {
        auto & vec = this->at(i);
        if (vec.empty() || vec.back() != n) // optiization to avoid obvious dupes
            vec.push_back(n);
    }
}

std::vector<TxNum> PrefixTable::searchPrefix(const Prefix &prefix, bool sortAndMakeUnique) const {
    std::vector<TxNum> ret;
    const auto [b, e] = prefix.range();
    for (size_t i = b; i < e; ++i) {
        const auto & vec = this->at(i);
        ret.insert(ret.end(), vec.begin(), vec.end());
    }
    if (sortAndMakeUnique) {
        Util::sortAndUniqueify(ret, false);
    }
    return ret;
}

size_t PrefixTable::removeForPrefix(const Prefix & prefix) {
    size_t ret = 0u;
    const auto [b, e] = prefix.range();
    for (size_t i = b; i < e; ++i) {
        auto & vec = this->at(i);
        ret += vec.size();
        vec = value_type{}; // we clear the vector in this way to ensure memory for it is freed immediately, since vec.clear() won't guarantee this.
    }
    return ret;
}

} // namespace Rpa

#ifdef ENABLE_TESTS
#include "App.h"

#include <QRandomGenerator>

#include <algorithm>
#include <map>
#include <memory>
#include <vector>

namespace {
void test()
{
    QRandomGenerator *rgen = QRandomGenerator::global();
    if (rgen == nullptr) throw Exception("Failed to obtain random number generator");
    auto genRandomRpaHash = [rgen] {
        using Arr = std::array<quint32, HashLen / sizeof(quint32)>;
        static_assert(Arr{}.size() * sizeof(quint32) == HashLen);
        // Lazy but who really would be so pedantic to care. Generate 8 32-bit ints = 256-bits (32-byte) random
        // hash.
        Arr randNums;
        rgen->generate(randNums.begin(), randNums.end());
        return Rpa::Hash(reinterpret_cast<const char *>(std::as_const(randNums).data()), HashLen);
    };

    std::unique_ptr<Rpa::PrefixTable> prefixTable = std::make_unique<Rpa::PrefixTable>(); // put the PrefixTable on the heap since it eats ~1.5MB of memory due to being a huge array
    using VerifyTable = std::map<uint16_t, std::vector<uint64_t>>;
    VerifyTable verifyTable;

    Log() << "Testing PrefixTable add ...";
    if (! prefixTable->empty() || prefixTable->elementCount() != 0) throw Exception(".empty() and/or .elementCount() are wrong");
    size_t added = 0;
    for (size_t i = 0u; i < 1'000'000u; ++i) {
        const auto randHash = genRandomRpaHash();
        const TxNum n = rgen->generate64() & ((uint64_t{1u} << Rpa::PrefixTable::SerializedTxNumBits) - uint64_t{1u});
        const Rpa::Prefix prefix(randHash);
        prefixTable->addForPrefix(prefix, n); // add to prefix table
        auto & v = verifyTable[prefix.value()];
        if (v.empty() || v.back() != n) {
            v.push_back(n);
            ++added;
        }
    }
    if (prefixTable->elementCount() != added) throw Exception("PrefixTable's elementCount() is wrong");

    struct CheckFail : Exception { using Exception::Exception; };
    auto checkTableConsistency = [](const Rpa::PrefixTable & pt, const VerifyTable & vt) {
        if (pt.size() != vt.size())
            throw CheckFail("Rpa::PrefixTable's size does not equal the check-table's size");

        // check everything in the table is in the prefix map
        for (const auto & [pfxnum, vec] : vt) {
            const Rpa::Prefix pfx(pfxnum);
            const std::vector<TxNum> & nums = pt.at(pfx.value());
            // the vector of txnums now should equal prefixTable
            if (nums != vec)
                throw CheckFail("Rpa::PrefixTable has consistency errors");
        }
    };
    Log() << "Testing PrefixTable consistency ...";
    checkTableConsistency(*prefixTable, verifyTable);

    auto checkTableLookup = [](const Rpa::Prefix &p, const Rpa::PrefixTable & pt, const VerifyTable & vt, bool sort) {
        auto vpt = pt.searchPrefix(p, sort);
        const auto [b, e] = p.range();
        Debug() << "checkTableLookup(sort=" << int(sort) << ") for prefix: " << p.value()
                << ", '" << p.toByteArray(false).toHex() << "', bits: " << p.getBits()
                << ", range: [" << b << ", " << e << "), vecSize: " << vpt.size();
        VerifyTable::mapped_type vvt;
        for (size_t i = b; i < e; ++i) {
            const auto & v = vt.at(i);
            vvt.insert(vvt.end(), v.begin(), v.end());
        }
        if (sort) Util::sortAndUniqueify(vvt);
        if (vpt != vvt) throw Exception("Rpa::PrefixTable search yielded incorrect results");
    };
    Log() << "Testing PrefixTable search ...";
    for (size_t i = 0; i < 256u; ++i) {
        const Rpa::Prefix p(i << 8u, /* bits = */8u);
        checkTableLookup(p, *prefixTable, verifyTable, false);
        checkTableLookup(p, *prefixTable, verifyTable, true);
    }

    Log() << "Testing Rpa::PrefixTable serialize / unserialize...";
    for (size_t i = 0; i < prefixTable->size(); ++i) {
        const QByteArray serialized = prefixTable->serializeRow<QByteArray>(i);
        PackedNumView<Rpa::PrefixTable::SerializedTxNumBits> pnv(serialized);
        typename Rpa::PrefixTable::value_type vec;
        vec.insert(vec.end(), pnv.begin(), pnv.end());
        if (vec != prefixTable->at(i)) throw Exception("Rpa::PrefixTable ser/deser cycle yielded inconsistent results");
    }

    Log() << "Testing Rpa::PrefixTable equality ...";
    {
        auto pft2 = std::make_unique<Rpa::PrefixTable>(*prefixTable);
        if (*prefixTable != *pft2)
            throw Exception("Rpa::PrefixTable not equal");
        if ( ! pft2->back().empty()) {
            // invert the last element
            pft2->back().back() = ~pft2->back().back();
            // equality should fail
            if (*prefixTable == *pft2) throw Exception("Failed to break equality");
            pft2->back().back() = ~pft2->back().back();
            // restored the last element, equality preserved
            if (*prefixTable != *pft2) throw Exception("Failed to restore equality");
        } else Warning() << "EMPTY LAST ENTRY -- FIXME!";
        pft2->clear();
        if (!pft2->empty()) throw Exception(".clear() failed");
        if (*prefixTable == *pft2) throw Exception("operator== failed");
    }

    Log() << "Testing Rpa::PrefixTable remove ...";
    {
        auto prefixTable2 = std::make_unique<Rpa::PrefixTable>(*prefixTable);
        auto verifyTable2 = verifyTable;
        size_t rmct = 0;
        for (size_t i = 0; i < 256u; ++i) {
            const Rpa::Prefix p(i << 8u, /* bits = */8u);
            rmct += prefixTable->removeForPrefix(p);
            const auto [b, e] = p.range();
            for (size_t j = b; j < e; ++j) verifyTable[j].clear();
            if (i > 0u && i % 10u == 0u) {
                checkTableConsistency(*prefixTable, verifyTable);
                if (*prefixTable == *prefixTable2) throw Exception("Equality check failed");
                if (prefixTable->elementCount() + rmct != prefixTable2->elementCount()) throw Exception("Counts check failed");
            }
        }
        checkTableConsistency(*prefixTable, verifyTable);
        checkTableConsistency(*prefixTable2, verifyTable2);
        auto checkNotEqualsTable = [&](const auto &arg1, const auto &arg2) {
            try {
                checkTableConsistency(arg1, arg2);
            } catch (const CheckFail &) {
                return;
            }
            throw CheckFail("Inequality check failed!");
        };
        checkNotEqualsTable(*prefixTable2, verifyTable);
        checkNotEqualsTable(*prefixTable, verifyTable2);
    }
    prefixTable.reset(); // delete the table now to save memory

    Log() << "Testing Rpa::Hash (serializeInput) ...";
    // perform serialization of a bitcoin input; this is used to verify the faster Rpa::Hash(const CTxIn &)
    auto serializeInputSlow = [](const bitcoin::CTxIn& input) -> Rpa::Hash {
        const auto serInput = BTC::Serialize(input);
        Rpa::Hash rhash{BTC::Hash(serInput, false)}; // double sha2
        return rhash;
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
    for (const bool shortPrefix : {false, true}) {
        for (const auto & txStr : txStrs) {
            bitcoin::CMutableTransaction tx;
            BTC::Deserialize(tx, Util::ParseHexFast(txStr), 0, false);

            for (size_t n = 0, sz = tx.vin.size(); n < sz; ++n) {
                const auto & input = tx.vin[n];
                const Rpa::Hash rHash{input};
                const Rpa::Hash rHashSlow = serializeInputSlow(input);
                if (rHash != rHashSlow) throw Exception("Fast serializeInput does not match the slow version!");
                const auto prefix = Rpa::Prefix(!shortPrefix ? rHash : Rpa::Hash{rHash.mid(0, 1)});
                const std::string rHashPrefix = prefix.toString(true);
                QByteArray prefixHex = Util::ToHexFast(QByteArray::fromStdString(rHashPrefix));
                const auto rHashHex = Util::ToHexFast(rHash);
                Debug() << "   Txid: " << tx.GetId().ToString() << ":" << n
                        << " Rpa::Hash: " << Util::ToHexFast(rHash)
                        << " Prefix: " << prefixHex
                        << " Prefix bits: " << prefix.getBits();
                if (prefixHex.size() != 2 + (2 * !shortPrefix) || ! rHashHex.startsWith(prefixHex))
                    throw Exception("Prefix is not as expected.");
            }
        }
    }

    Log(Log::Color::BrightWhite) << "All Rpa unit tests passed!";
}

static const auto test_ = App::registerTest("rpa", &test);
}
#endif
