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
#include "PackedNumView.h"

#ifdef ENABLE_TESTS
#include "App.h"
#include "Common.h"
#include "Util.h"

#include "bitcoin/crypto/endian.h"

#include <QRandomGenerator>

#include <array>
#include <atomic>

namespace {

std::atomic_size_t nChecksOk = 0u;

#define CHK_EXC(stmt, exc) \
[&]() { \
try { \
    stmt ; \
} catch (const exc &e) { \
    DebugM("Expected exception was thrown: ", #exc, ", what: ", e.what()); \
    ++nChecksOk; \
    return; \
} catch (...) { } \
throw Exception("Failed to catch expected exception: " #exc ); \
}()

#define CHK(pred) \
do { \
    if (!( pred )) throw Exception("Failed predicate: " #pred ); \
    ++nChecksOk; \
} while(0)

template<unsigned BITS, typename Int>
void doTest(Span<Int> srcInts) {
    const QByteArray::size_type bufSz = BITS/8 * srcInts.size();
    QByteArray buf(bufSz, Qt::Uninitialized), bufbe(bufSz, Qt::Uninitialized);
    std::remove_cv_t<Int> prev = 0;
    const bool is_sorted = srcInts.empty() || std::all_of(srcInts.begin(), srcInts.end(), [&](const Int cur) {
                                                              if (cur < prev) return false;
                                                              prev = cur;
                                                              return true;
                                                          });

    {
        QByteArray bufTooBig(bufSz + BITS/8, Qt::Uninitialized);
        // Make with too big an output buffer should throw
        CHK_EXC(PackedNumView<BITS>::Make(MakeUInt8Span(bufTooBig), srcInts), std::invalid_argument);
        // But not if we specify the `true` flag
        auto pnv = PackedNumView<BITS>::Make(MakeUInt8Span(bufTooBig), srcInts, true);
        CHK(!pnv.empty());
        CHK(pnv.size() == srcInts.size() + 1); // should have 1 extra 0-element
        if (!srcInts.empty() && srcInts.back() != 0) CHK(pnv.back() == 0);

        // If the buffer is 1-byte too big, always throws
        QByteArray buf2 = buf;
        buf2.append('1');
        CHK_EXC(PackedNumView<BITS>::Make(MakeUInt8Span(buf2), srcInts, false), std::invalid_argument);
        CHK_EXC(PackedNumView<BITS>::Make(MakeUInt8Span(buf2), srcInts, true), std::invalid_argument);
    }

    // Test Make
    auto pnv = PackedNumView<BITS>::Make(MakeUInt8Span(buf), srcInts);
    auto pnvbe = PackedNumView<BITS, false>::Make(MakeUInt8Span(bufbe), srcInts);
    CHK(pnv.size() == srcInts.size());
    CHK(pnvbe.size() == srcInts.size());
    CHK(pnv.max() == (uint64_t{1} << BITS) - 1u);
    CHK(pnv.max() == pnvbe.max());

    // Test Iterator.valid()
    if (pnv.empty()) {
        CHK(pnv.begin() == pnv.end());
        CHK(! pnv.begin().valid());
    } else {
        CHK(pnv.begin().valid());
    }
    CHK(! pnv.end().valid());

    // Test operator[] and contents ok
    for (size_t i = 0; i < srcInts.size(); ++i) {
        const auto v = pnv[i];
        CHK(v == pnv.at(i)); // test .at() is same as operator[]
        CHK(v == pnvbe.at(i));
        CHK(v == pnvbe[i]);
        const auto si = srcInts[i];
        if (si <= pnv.max()) CHK(v == si);
        else CHK(v == (si & ((uint64_t{1u} << BITS) - 1u))); // should be truncated.

        // Test iterator offset ops
        auto it = pnv.begin() + i;
        CHK(it.valid());
        CHK(*it == v);
        auto it2 = pnv.end() - (pnv.size() - i);
        CHK(it2 == pnv.begin() + i);
        CHK(*it2 == v);
        CHK(it == it2);
        CHK(it.index() == it2.index());

        // Check endianness of data is what we expect
        uint64_t be{}, le{};
        ByteView vbe = pnvbe.viewForElement(i), vle = pnv.viewForElement(i);
        std::memcpy(&le, vle.data(), vle.size());
        std::memcpy(reinterpret_cast<char *>(&be) + (sizeof(uint64_t) - vbe.size()), vbe.data(), vbe.size());
        CHK(le64toh(le) == v);
        CHK(be64toh(be) == v);
    }
    CHK(pnv.begin() + pnv.size() == pnv.end());
    // ensure big endian and little endian look different at the low-level
    CHK(pnv.rawBytes() != pnvbe.rawBytes());
    // test .at() past end throws
    CHK_EXC(pnv.at(pnv.size()), std::out_of_range);

    // test operator==
    auto pnv2 = pnv;
    CHK(pnv == pnv2);

    // test operator!=
    if (!srcInts.empty()) {
        auto subSrcInts = srcInts.subspan(1);
        const QByteArray::size_type bufSz2 = BITS/8 * subSrcInts.size();
        QByteArray buf2(bufSz2, Qt::Uninitialized);
        auto pnv3 = PackedNumView<BITS>::Make(MakeUInt8Span(buf2), subSrcInts);
        CHK(pnv.size() > pnv3.size());
        CHK(pnv != pnv3);
        if (!pnv3.empty()) {
            CHK(pnv[1] == pnv3.front());
            CHK(pnv.back() == pnv3.back());
        }
    }

    // test find() and lower_bound()
    if (is_sorted && !pnv.empty()) {
        auto *rgen = QRandomGenerator::system();
        CHK(rgen != nullptr);
        const unsigned idx = rgen->bounded(unsigned(pnv.size()));
        auto it = pnv.find(pnv.at(idx));
        CHK(it != pnv.end());
        CHK(*it == pnv.at(idx));
        CHK(it.index() == idx);
        if (auto v = srcInts.back(); v < pnv.max()) {
            it = pnv.find(v + 1u);
            CHK(it == pnv.end());
        }
        if (auto v = srcInts.front(); v > pnv.min()) {
            it = pnv.find(v - 1u);
            CHK(it == pnv.end());
            it = pnv.lower_bound(v - 1u);
            CHK(it == pnv.begin());
            CHK(*it == pnv.front());
        }
    }
}

void test() {
    nChecksOk = 0u;
    std::array<unsigned, 7> foo = { 1, 5, 10, 67367, 16700000, 0xff'ff'03, 0xff'ff'ff'ff };
    std::array<const unsigned, 7> foo2 = { 1, 10, 129, 67367, 16700000, 0xff'ff'03, 0xff'ff'ff'ff };
    doTest<48>(Span{foo2});
    doTest<24>(Span{foo2});
    doTest<32>(Span{foo2});
    doTest<56>(Span{foo2});
    for (size_t i = 0u; i < 10u; ++i) {
        auto *rng = QRandomGenerator::system();
        CHK(rng != nullptr);
        const size_t arraysz = rng->bounded(32u) + 20u;
        std::vector<uint64_t> nums24, nums40, nums48, nums56;
        for (size_t j = 0u; j < arraysz; ++j) {
            const auto num = rng->generate64();
            nums24.push_back(num & 0xff'ff'ff);
            nums40.push_back(num & 0xff'ff'ff'ff'ff);
            nums48.push_back(num & 0xff'ff'ff'ff'ff'ff);
            nums56.push_back(num & 0xff'ff'ff'ff'ff'ff'ff);
        }
        for (auto * vec : {&nums24, &nums40, &nums48, &nums56})
            std::sort(vec->begin(), vec->end());
        doTest<24>(Span{nums24});
        doTest<40>(Span{nums40});
        doTest<48>(Span{nums48});
        doTest<56>(Span{nums56});
    }
    QByteArray buf(3 * foo.size(), Qt::Uninitialized), buf2(3 * foo.size(), Qt::Uninitialized);
    auto pnv = PackedNumView<24>::Make(MakeUInt8Span(buf), Span{foo});
    auto pnv2 = PackedNumView<24, false>::Make(MakeUInt8Span(buf2), Span{foo2});
    CHK(buf == Util::ParseHexFast("0100000500000a000027070160d2fe03ffffffffff"));
    CHK(buf2 == Util::ParseHexFast("00000100000a000081010727fed260ffff03ffffff"));
    Log() << "Buffer hex: " << buf.toHex();
    Log() << "Buffer2 hex: " << buf2.toHex();
    {
        Log l;
        for (const auto n : pnv) {
            l << n << ", ";
        }
    }
    {
        Log l;
        for (const auto n : pnv2) {
            l << n << ", ";
        }
    }
    if (auto it = pnv.lower_bound(60000); it != pnv.end()) {
        Log() << "Found " << *it << " at position " << it.index();
    }
    if (auto it = pnv2.lower_bound(0xffff03); it != pnv2.end()) {
        Log() << "Found " << *it << " at position " << it.index();
    }
    if (auto it = pnv.find(10); it != pnv.end())
        Log() << "Found " << *it << " at position " << it.index();
    if (auto it = pnv2.find(11); it != pnv2.end())
        Log() << "Found " << *it << " at position " << it.index();
    else Log() << "11 not found";
    auto pnv3 = PackedNumView<24>(ByteView{});
    Log() << "pnv3 size: " << pnv3.size();
    if (auto it = pnv3.find(10); it != pnv3.end())
        Log() << "Found " << *it << " at position " << it.index();
    else Log() << "10 not found";

    Log(Log::BrightWhite) << nChecksOk.load() << " checks passed ok";
}

static const auto test_ = App::registerTest("packednumview", &test);

#undef CHK
#undef CHK_EXC

} // namespace
#endif // ENABLE_TESTS
