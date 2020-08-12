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

#include <QByteArray>
#include <QRandomGenerator>

#include <cstdlib>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace {
    void test()
    {
        // basic hasher test
        std::unordered_set<TXO> set;
        std::vector<QByteArray> hashes;
        constexpr int n = 100'000;
        Log() << "Testing TXO hasher for correctness with " << n << " items...";
        for (int i = 0; i < n; ++i) {
            QByteArray buf;
            buf.resize(32);
            QRandomGenerator::global()->fillRange(reinterpret_cast<uint32_t *>(buf.data()), buf.size() / sizeof(uint32_t));
            hashes.push_back(buf);
            TXO t = { buf, IONum(i) };
            set.insert(t);
        }
        Log() << "Set has " << set.size() << " items, verifying...";
        for (int i = n-1; i >= 0; --i) {
            auto &buf = hashes[i];
            TXO t = { buf, IONum(i) };
            if (set.count(t) != 1) {
                throw Exception(QString("Missing a txo from the set for item %1!").arg(i));
            }
        }
        Log() << "All " << n << " items verified ok";
    }

    static const auto test_  = App::registerTest("txo", &test);
}
#endif
