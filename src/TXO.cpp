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
#include "TXO.h"

#include <QString>

QString TXO::toString() const
{
    return isValid()
            ? QStringLiteral("%1:%2").arg(QString(txHash.toHex())).arg(outN)
            : QStringLiteral("<txo_invalid>");
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "TXO_Compact.h"

#include <QByteArray>
#include <QRandomGenerator>

#include <cstdlib>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace {
    void test()
    {
        // TXO and CompactTXO comparison ops test
        {
            auto h2b = [](const QByteArray &hex) { return QByteArray::fromHex(hex); };
            size_t ctr = 0u;
#           define CHK(expr) do { ++ctr; if (!(expr)) throw Exception(QString("Failed check: %2 (line: %1, file: %3)") \
                                                                      .arg(__LINE__).arg( #expr ,  __FILE__)); } while(false)
            Log() << "Testing TXO & CompactTXO comparison ops ...";
            TXO a, b;
            a = b = TXO{h2b("01"), 1};
            CHK(a == b);
            CHK(!(a != b));
            CHK(!(a < b));
            CHK(!(a > b));
            CHK(a <= b);
            CHK(a >= b);

            a = TXO{h2b("0102030405"), 5};
            b = TXO{h2b("0102030405"), 6};
            CHK(!(a == b));
            CHK(a != b);
            CHK(a < b);
            CHK(!(a > b));
            CHK(a <= b);
            CHK(!(a >= b));

            a = TXO{h2b("0102030405"), 6};
            b = TXO{h2b("0102030405"), 5};
            CHK(!(a == b));
            CHK(a != b);
            CHK(!(a < b));
            CHK(a > b);
            CHK(!(a <= b));
            CHK(a >= b);

            a = TXO{h2b("0102030405"), 5};
            b = TXO{h2b("0102030406"), 5};
            CHK(!(a == b));
            CHK(a != b);
            CHK(a < b);
            CHK(!(a > b));
            CHK(a <= b);
            CHK(!(a >= b));

            a = TXO{};
            CHK(!(a == b));
            CHK(a != b);
            CHK(a < b);
            CHK(!(a > b));
            CHK(a <= b);
            CHK(!(a >= b));

            a = TXO{h2b("0102030406"), 5};
            b = TXO{h2b("0102030405"), 5};
            CHK(!(a == b));
            CHK(a != b);
            CHK(!(a < b));
            CHK(a > b);
            CHK(!(a <= b));
            CHK(a >= b);

            CompactTXO ca, cb;
            ca = cb = CompactTXO{1, 1};
            CHK(ca == cb);
            CHK(!(ca != cb));
            CHK(!(ca < cb));
            CHK(!(ca > cb));
            CHK(ca <= cb);
            CHK(ca >= cb);

            ca = CompactTXO{}; // default constructed is all 0xff, so it's always greater
            CHK(!(ca == cb));
            CHK(ca != cb);
            CHK(!(ca < cb));
            CHK(ca > cb);
            CHK(!(ca <= cb));
            CHK(ca >= cb);

            ca = CompactTXO{12345, 5};
            cb = CompactTXO{12345, 6};
            CHK(!(ca == cb));
            CHK(ca != cb);
            CHK(ca < cb);
            CHK(!(ca > cb));
            CHK(ca <= cb);
            CHK(!(ca >= cb));

            ca = CompactTXO{12345, 6};
            cb = CompactTXO{12345, 5};
            CHK(!(ca == cb));
            CHK(ca != cb);
            CHK(!(ca < cb));
            CHK(ca > cb);
            CHK(!(ca <= cb));
            CHK(ca >= cb);

            ca = CompactTXO{12345, 5};
            cb = CompactTXO{12346, 5};
            CHK(!(ca == cb));
            CHK(ca != cb);
            CHK(ca < cb);
            CHK(!(ca > cb));
            CHK(ca <= cb);
            CHK(!(ca >= cb));

            ca = CompactTXO{12346, 5};
            cb = CompactTXO{12345, 5};
            CHK(!(ca == cb));
            CHK(ca != cb);
            CHK(!(ca < cb));
            CHK(ca > cb);
            CHK(!(ca <= cb));
            CHK(ca >= cb);

            Log() << ctr << " comparison ops passed ok";

#           undef CHK
        }

        // basic hasher test
        std::unordered_set<TXO> set; // checks that TXOs hash correctly
        std::unordered_set<CompactTXO> setctxo; // checks that CompactTXOs hash correctly
        std::set<TXO> oset; // checks that operator< is correct
        std::set<CompactTXO> osetctxo; // checks that CompactTXOs have correct operator<
        std::vector<QByteArray> hashes;
        std::map<QByteArray, IONum> ioNums;
        std::map<QByteArray, TxNum> txNums;
        constexpr int n = 100'000;
        Log() << "Testing TXO hasher for correctness with " << n << " items ...";
        for (int i = 0; i < n; ++i) {
            QByteArray buf;
            buf.resize(32);
            QRandomGenerator::global()->fillRange(reinterpret_cast<uint32_t *>(buf.data()), buf.size() / sizeof(uint32_t));
            const IONum randIoNum = IONum(QRandomGenerator::global()->generate());
            const TxNum randTxNum = TxNum(QRandomGenerator::global()->generate64());
            hashes.push_back(buf);
            ioNums[buf] = randIoNum;
            txNums[buf] = randTxNum;
            const TXO t = {buf, randIoNum};
            set.insert(t);
            oset.insert(t);
            const CompactTXO ct{randTxNum, t.outN};
            setctxo.insert(ct);
            osetctxo.insert(ct);
        }
        Log() << "Set has " << set.size() << " items, verifying ...";
        for (int i = n-1; i >= 0; --i) {
            const auto &hash = hashes.at(i);
            const IONum & ioNum = ioNums[hash];
            const TxNum & txNum = txNums[hash];
            const TXO t = { hash, ioNum };
            if (set.count(t) != 1) {
                throw Exception(QString("Missing a txo from the unordered set for item %1!").arg(i));
            }
            if (oset.count(t) != 1) {
                throw Exception(QString("Missing a txo from the ordered set for item %1!").arg(i));
            }
            const CompactTXO ct{txNum, t.outN};
            if (setctxo.count(ct) != 1)
                throw Exception(QString("Missing a compact txo from the unordered set for item %1!").arg(i));
            if (osetctxo.count(ct) != 1)
                throw Exception(QString("Missing a compact txo from the ordered set for item %1!").arg(i));
        }
        Log() << "All " << n << " items verified ok";
    }

    static const auto test_  = App::registerTest("txo", &test);
}
#endif
