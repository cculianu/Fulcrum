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
#include "ByteView.h"
#include "Tests.h"

#include <cstdint>
#include <string>
#include <vector>

TEST_SUITE(byteview)

TEST_CASE(comparison_ops) {
    ByteView a, b;

    TEST_CHECK(a == b); // empty byteviews are equal

    // Test a == b
    auto ChkEq = [&] {
        TEST_CHECK(a.compare(b) == 0);
        TEST_CHECK(b.compare(a) == 0);
        TEST_CHECK(a == b);
        TEST_CHECK(b == a);
        TEST_CHECK(!(a != b));
        TEST_CHECK(!(b != a));
        TEST_CHECK(!(a < b));
        TEST_CHECK(!(b < a));
        TEST_CHECK(!(a > b));
        TEST_CHECK(!(b > a));
        TEST_CHECK(a >= b);
        TEST_CHECK(b >= a);
        TEST_CHECK(a <= b);
        TEST_CHECK(b <= a);
    };
    a = "abc"_bv;
    b = "abc"_bv;
    ChkEq();
    b = "abcdefgh"_bv.substr(0, 3);
    ChkEq();

    // Set b to be greater-than a
    b = "abcd"_bv;
    TEST_CHECK(a.compare(b) == -1);
    TEST_CHECK(b.compare(a) == 1);
    TEST_CHECK(a != b);
    TEST_CHECK(b != a);
    TEST_CHECK(!(a == b));
    TEST_CHECK(!(b == a));
    TEST_CHECK(a < b);
    TEST_CHECK(!(b < a));
    TEST_CHECK(!(a > b));
    TEST_CHECK(b > a);
    TEST_CHECK(!(a >= b));
    TEST_CHECK(b >= a);
    TEST_CHECK(a <= b);
    TEST_CHECK(!(b <= a));

    std::string s{"abc"};
    b = s; // ensure and b pointers differ to really test the non-fast-path of operator==
    ChkEq();

    // Create some random strings and check operators
    for (size_t i = 0; i < 100; ++i) {
        const size_t lena = i < 10 ? 128 : InsecureRandRange(128); // first 10 iters used fixed-size, otherwise use random size
        const size_t lenb = i < 10 ? 128 : InsecureRandRange(128);
        std::string sr1(lena, '\0'), sr2(lenb, '\0');
        GetRandBytes(sr1.data(), sr1.size());
        GetRandBytes(sr2.data(), sr2.size());

        const std::string_view sa = sr1, sb = sr2;

        a = sa;
        b = sb;

        TEST_CHECK(a.size() == sa.size());
        TEST_CHECK(b.size() == sb.size());

        TEST_CHECK((a == b) == (sa == sb));
        TEST_CHECK((a != b) == (sa != sb));
        TEST_CHECK((a <= b) == (sa <= sb));
        TEST_CHECK((a >= b) == (sa >= sb));
        TEST_CHECK((a < b) == (sa < sb));
        TEST_CHECK((a > b) == (sa > sb));

        const int compval = sa == sb ? 0 : (sa < sb ? -1 : 1);
        TEST_CHECK(a.compare(b) == compval);
    }
};

TEST_CASE(ctor_pod) {
    auto Chk = [&](auto val) {
        auto bv = ByteView(val);
        TEST_CHECK(bv.size() == sizeof(val));
        TEST_CHECK(bv.data() == reinterpret_cast<std::byte *>(&val));
        decltype(val) val2{};
        std::memcpy(reinterpret_cast<char *>(&val2), bv.charData(), sizeof(val2));
        TEST_CHECK(val == val2);
    };
    Chk(42);
    Chk(1234ull);
    Chk(1234ll);
    Chk('f');
    Chk('\0');
    struct S {
        long val;
        char buf[sizeof(long)];
        bool operator==(const S& s) const { return std::memcmp(this, &s, sizeof(*this)) == 0; }
    };
    static_assert(std::has_unique_object_representations_v<S>);
    Chk(S{42, "Foo"});

    Chk(std::array<short, 6>{1, 2, 3, 4, 5, 6});
};

TEST_CASE(ctor_container) {
    ByteView bv;
    std::string_view sv{"muahahaha"};

    bv = sv;
    TEST_CHECK(std::string_view{bv.charData()} == sv);

    QString qs{"the quick brown fox"};

    bv = qs;
    TEST_CHECK(std::string_view{bv.charData()} != sv);
    TEST_CHECK(QString::fromRawData(reinterpret_cast<const QChar *>(bv.data()), bv.size() / sizeof(QChar)) == qs);
    TEST_CHECK(reinterpret_cast<const QChar *>(bv.data()) == qs.constData());
    TEST_CHECK(bv.size() == qs.size() * sizeof(QChar));

    std::vector<uint8_t> vec(256, uint8_t{});
    GetRandBytes(vec.data(), vec.size());
    bv = vec;
    TEST_CHECK(bv.ucharData() == vec.data());
    TEST_CHECK(bv.size() == vec.size());
};

TEST_CASE(substr) {
    ByteView bv;
    std::string_view sv = "the quick brown fox jumped over the lazy dogs";

    bv = sv;

    TEST_CHECK(bv.charData() == sv.data());
    TEST_CHECK(bv.ucharData() == reinterpret_cast<const uint8_t *>(sv.data()));
    TEST_CHECK(bv.data() == reinterpret_cast<const std::byte *>(sv.data()));

    for (size_t i = 0; i < sv.size(); ++i) {
        TEST_CHECK(bv.substr(i) == sv.substr(i));
        TEST_CHECK(bv.substr(i).data() == bv.data() + i);
        for (size_t j = 0; j < sv.size(); ++j) {
            const auto mid = bv.substr(i, j);
            TEST_CHECK(mid.data() == bv.data() + i); // check pointer is where we expect
            const auto svmid = sv.substr(i, j);
            TEST_CHECK(mid == svmid); // check correctness versus known-good sv.substr() implementation
            TEST_CHECK(std::string(mid.charData(), mid.size()) == std::string{svmid}); // check equality using std::string (paranoia)
        }
    }
};

TEST_CASE(conversion) {
    const auto bv = "this is a test muahaha"_bv;

    TEST_CHECK(bv.toByteArray() == QByteArray("this is a test muahaha"));
    TEST_CHECK(bv.toByteArray(false) == "this is a test muahaha");
    TEST_CHECK(bv.toByteArray(false).constData() == bv.charData());

    using namespace std::string_view_literals;
    TEST_CHECK(bv.toStringView() == "this is a test muahaha"sv);
};

TEST_SUITE_END()
