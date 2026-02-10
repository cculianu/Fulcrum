//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Tests.h"
#include "Json/Json.h"
#include "Util.h"

#include "bitcoin/utilstrencodings.h"

#include <QMap>
#include <QSet>

#include <algorithm>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
template<> struct std::hash<QString> {
    std::size_t operator()(const QString &s) const noexcept { return Util::hashForStd(s); }
};
#endif

// ---bench hexparse
BENCH_SUITE(hexparse)
BENCHMARK(hexparse) {
    const auto fn = std::getenv("HEXJSON");
    if (!fn)
        throw Exception("Please specify a HEXJSON= env var that points to a file containing a JSON array of hex strings");
    const QString filename = fn;
    const auto varlist = Json::parseFile(filename, Json::ParseOption::RequireArray).toList(); // throws on error
    QList<QByteArray> hexList;
    size_t bytes = 0;
    for (const auto & v : varlist) {
        auto ba = v.toByteArray();
        ba = ba.trimmed().simplified();
        if (ba.isEmpty())
            throw Exception(QString("read an empty bytearray for item %1 -- make sure json has hex strings").arg(hexList.size()));
        if (QByteArray::fromHex(ba).toHex() != ba)
            throw Exception(QString("read bad hex data at %1: %2").arg(hexList.count()).arg(v.toString()));
        bytes += size_t(ba.size());
        hexList.push_back(ba);
    }
    Log() << "Read " << bytes << " hex-digits in " << hexList.count() << " bytearrays ...";
    using BVec = std::vector<QByteArray>;
    BVec vec1, vec2;
    using UVec = std::vector<std::vector<uint8_t>>;
    UVec vec3;
    vec1.reserve(size_t(hexList.size()));
    vec2.reserve(size_t(hexList.size()));
    vec3.reserve(size_t(hexList.size()));
    const auto customMethod = [&vec1, &hexList, &bytes]() -> qint64 {
        size_t bytes2 = 0;
        Log() << "Parsing hex using Util::ParseHexFast() ...";
        const auto t0 = Util::getTimeNS();
        for (const auto & hex : hexList) {
            vec1.emplace_back(Util::ParseHexFast(hex));
        }
        const auto tf = Util::getTimeNS();
        for (const auto & b : vec1)
            bytes2 += size_t(b.size());
        if (bytes2 * 2 != bytes)
            throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
        const auto micros = qint64((tf-t0)/1000LL);
        Log() << "Util::ParseHexFast method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
        return micros;
    };
    const auto qtMethod = [&vec2, &hexList, &bytes]() -> qint64 {
        size_t bytes2 = 0;
        Log() << "Parsing hex using Qt's QByteArray::fromHex() ...";
        const auto t0 = Util::getTimeNS();
        for (const auto & hex : hexList) {
            vec2.emplace_back(QByteArray::fromHex(hex));
        }
        const auto tf = Util::getTimeNS();
        for (const auto & b : vec2)
            bytes2 += size_t(b.size());
        if (bytes2 * 2 != bytes)
            throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
        const auto micros = qint64((tf-t0)/1000LL);
        Log() << "Qt method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
        return micros;
    };
    const auto bitcoindMethod = [&vec3, &hexList, &bytes]() -> qint64 {
        size_t bytes2 = 0;
        Log() << "Parsing hex using bitcoin::ParseHex() from bitcoind ...";
        const auto t0 = Util::getTimeNS();
        for (const auto & hex : hexList) {
            vec3.emplace_back(bitcoin::ParseHex(hex.constData()));
        }
        const auto tf = Util::getTimeNS();
        for (const auto & b : vec3)
            bytes2 += size_t(b.size());
        if (bytes2 * 2 != bytes)
            throw Exception(QString("Decoded data is missing bytes: %1 != %2").arg(bytes2*2).arg(bytes));
        const auto micros = qint64((tf-t0)/1000LL);
        Log() << "bitcoind method: decoded " << bytes2 << " bytes, elapsed: " << micros << " usec";
        return micros;
    };
    customMethod();
    qtMethod();
    bitcoindMethod();
    if (vec1 == vec2)
        Log() << "The first two resulting vectors match perfectly";
    else
        throw Exception("The first two vectors don't match!");
    if (vec3.size() != vec2.size())
        throw Exception("The bitcoind method vector is of the wrong size");
    for (size_t i = 0; i < vec3.size(); ++i) {
        if (std::memcmp(vec3[i].data(), vec2[i].constData(), vec3[i].size()) != 0)
            throw Exception(QString("The bitcoind method hex string %1 does not match").arg(i));
    }
    Log() << "The bitcoind method data matches the other two data sets ok";

    Log() << "Checking ToHexFast vs. Qt vs. bitcoind ...";
    for (const auto & ba : vec1) {
        if (Util::ToHexFast(ba) != ba.toHex())
            throw Exception("ToHexFast and Qt toHex produced different hex strings!");
    }

           // Lasty, benchmark encoding hex
    BVec res; res.reserve(vec1.size());
    // Util::ToHexFast
    auto t0 = Tic();
    for (const auto & ba : vec1) {
        res.emplace_back(Util::ToHexFast(ba));
    }
    t0.fin();
    Log() << "Util::ToHexFast took: " << t0.usec() << " usec";
    res.clear(); res.reserve(vec1.size());
    // Qt toHex()
    t0 = Tic();
    for (const auto & ba : vec1) {
        res.emplace_back(ba.toHex());
    }
    t0.fin();
    Log() << "Qt toHex took: " << t0.usec() << " usec";
    // bitcoind HexStr()
    res.clear();
    {
        std::vector<std::string> res;
        res.reserve(vec1.size());
        t0 = Tic();
        for (const auto & ba : vec1) {
            res.emplace_back(bitcoin::HexStr(ba.cbegin(), ba.cend()));
        }
        t0.fin();
        Log() << "bitcoind HexStr took: " << t0.usec() << " usec";
    }
};
BENCH_SUITE_END()


// ---test util
TEST_SUITE(util)

const std::map<QString, QString> map{
    { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
};
const QMap<QString, QString> qmap{
    { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
};
const std::unordered_map<QString, QString> umap{
    { "hello", "hi" }, { "foo", "bar" }, { "biz", "baz" }, { "fulcrum", "rocks" }, { "booyaka", "sha" },
};

TEST_CASE(keySet<QSet>) {
    auto s1 = Util::keySet<QSet<QString>>(map);
    auto s2 = Util::keySet<QSet<QString>>(qmap);
    auto s3 = Util::keySet<QSet<QString>>(umap);
    TEST_CHECK(s1.size() == int(map.size()) && s2.size() == qmap.size() && s1 == s2 && s1 == s3);
    for (const auto &k : s1)
        TEST_CHECK(map.find(k) != map.end());
};

TEST_CASE(keySet<unordered_set>) {
    auto s1 = Util::keySet<std::unordered_set<QString>>(map);
    auto s2 = Util::keySet<std::unordered_set<QString>>(qmap);
    auto s3 = Util::keySet<std::unordered_set<QString>>(umap);
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(keySet<vector>) {
    auto s1 = Util::keySet<std::vector<QString>>(map);
    auto s2 = Util::keySet<std::vector<QString>>(qmap);
    auto s3 = Util::keySet<std::vector<QString>>(umap);
    std::sort(s3.begin(), s3.end());
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(keySet<list>) {
    auto s1 = Util::keySet<std::list<QString>>(map);
    auto s2 = Util::keySet<std::list<QString>>(qmap);
    auto s3 = Util::keySet<std::list<QString>>(umap);
    auto v = Util::toVec(s3);
    std::sort(v.begin(), v.end());
    s3 = Util::toList(v);
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(keySet<QStringList>) {
    auto s1 = Util::keySet<QStringList>(map);
    auto s2 = Util::keySet<QStringList>(qmap);
    auto s3 = Util::keySet<QStringList>(umap);
    std::sort(s3.begin(), s3.end());
    TEST_CHECK(s1.size() == int(map.size()) && s2.size() == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(valueSet<QSet>) {
    auto const s1 = Util::valueSet<QSet<QString>>(map);
    auto s2 = Util::valueSet<QSet<QString>>(qmap);
    auto s3 = Util::valueSet<QSet<QString>>(umap);
    TEST_CHECK(s1.size() == int(map.size()) && s2.size() == qmap.size() && s1 == s2 && s1 == s3);
    for (const auto &v : s1) {
        bool found = false;
        for (const auto & [mk, mv] : map) {
            if (v == mv) {
                found = true;
                break;
            }
        }
        TEST_CHECK(found);
    }
};

TEST_CASE(valueSet<unordered_map>) {
    auto s1 = Util::valueSet<std::unordered_set<QString>>(map);
    auto s2 = Util::valueSet<std::unordered_set<QString>>(qmap);
    auto s3 = Util::valueSet<std::unordered_set<QString>>(umap);
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(valueSet<vector>) {
    auto s1 = Util::valueSet<std::vector<QString>>(map);
    auto s2 = Util::valueSet<std::vector<QString>>(qmap);
    auto s3 = Util::valueSet<std::vector<QString>>(umap);
    for (auto * s : { &s1, &s2, &s3 })
        std::sort(s->begin(), s->end());
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(valueSet<list>) {
    auto s1 = Util::valueSet<std::list<QString>>(map);
    auto s2 = Util::valueSet<std::list<QString>>(qmap);
    auto s3 = Util::valueSet<std::list<QString>>(umap);
    for (auto * s : { &s1, &s2, &s3 }) {
        auto v = Util::toVec(*s);
        std::sort(v.begin(), v.end());
        *s = Util::toList(v);
    }
    TEST_CHECK(s1.size() == map.size() && int(s2.size()) == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(valueSet<QStringList>) {
    auto s1 = Util::valueSet<QStringList>(map);
    auto s2 = Util::valueSet<QStringList>(qmap);
    auto s3 = Util::valueSet<QStringList>(umap);
    for (auto * s : { &s1, &s2, &s3 })
        std::sort(s->begin(), s->end());
    TEST_CHECK(s1.size() == int(map.size()) && s2.size() == qmap.size() && s1 == s2 && s1 == s3);
};

TEST_CASE(endian) {
    const uint64_t testnum = 0x0102030405060708ull, rtestnum = 0x0807060504030201ull;
    const uint32_t testnum32 = 0x01020304u, rtestnum32 = 0x04030201u;
    const uint16_t testnum16 = 0x0102u, rtestnum16 = 0x0201u;
    TEST_CHECK(Util::byteSwap16(testnum16) == rtestnum16);
    TEST_CHECK(Util::byteSwap32(testnum32) == rtestnum32);
    TEST_CHECK(Util::byteSwap64(testnum) == rtestnum);
    uint64_t lenum, benum;
    uint32_t lenum32, benum32;
    uint16_t lenum16, benum16;
    if constexpr (Util::isLittleEndian()) {
        lenum = testnum;
        benum = rtestnum;
        lenum32 = testnum32;
        benum32 = rtestnum32;
        lenum16 = testnum16;
        benum16 = rtestnum16;
    } else {
        lenum = rtestnum;
        benum = testnum;
        lenum32 = rtestnum32;
        benum32 = testnum32;
        lenum16 = rtestnum16;
        benum16 = testnum16;
    }
    {
        // check endianness sanity
        static_assert(sizeof(lenum) == 8u);
        const std::byte *ple = reinterpret_cast<std::byte *>(&lenum),
                        *pbe = reinterpret_cast<std::byte *>(&benum),
                        *ple32 = reinterpret_cast<std::byte *>(&lenum32),
                        *pbe32 = reinterpret_cast<std::byte *>(&benum32),
                        *ple16 = reinterpret_cast<std::byte *>(&lenum16),
                        *pbe16 = reinterpret_cast<std::byte *>(&benum16);
        for (size_t i = 0; i < sizeof(lenum); ++i) {
            TEST_CHECK(pbe[i] == static_cast<std::byte>(i + 1u));
            TEST_CHECK(ple[i] == static_cast<std::byte>(8u - i));
            if (i < sizeof(uint32_t)) {
                TEST_CHECK(pbe32[i] == static_cast<std::byte>(i + 1u));
                TEST_CHECK(ple32[i] == static_cast<std::byte>(4u - i));
            }
            if (i < sizeof(uint16_t)) {
                TEST_CHECK(pbe16[i] == static_cast<std::byte>(i + 1u));
                TEST_CHECK(ple16[i] == static_cast<std::byte>(2u - i));
            }
        }
    }
    TEST_CHECK(Util::le64ToH(lenum) == testnum);
    TEST_CHECK(Util::be64ToH(benum) == testnum);
    TEST_CHECK(Util::le32ToH(lenum32) == testnum32);
    TEST_CHECK(Util::be32ToH(benum32) == testnum32);
    TEST_CHECK(Util::le16ToH(lenum16) == testnum16);
    TEST_CHECK(Util::be16ToH(benum16) == testnum16);

    TEST_CHECK(Util::hToLe64(testnum) == lenum);
    TEST_CHECK(Util::hToBe64(testnum) == benum);
    TEST_CHECK(Util::hToLe32(testnum32) == lenum32);
    TEST_CHECK(Util::hToBe32(testnum32) == benum32);
    TEST_CHECK(Util::hToLe16(testnum16) == lenum16);
    TEST_CHECK(Util::hToBe16(testnum16) == benum16);

    TEST_CHECK(Util::le64ToH(Util::hToLe64(testnum)) == testnum);
    TEST_CHECK(Util::be64ToH(Util::hToBe64(testnum)) == testnum);
    TEST_CHECK(Util::le32ToH(Util::hToLe32(testnum32)) == testnum32);
    TEST_CHECK(Util::be32ToH(Util::hToBe32(testnum32)) == testnum32);
    TEST_CHECK(Util::le16ToH(Util::hToLe16(testnum16)) == testnum16);
    TEST_CHECK(Util::be16ToH(Util::hToBe16(testnum16)) == testnum16);
};

TEST_SUITE_END()
