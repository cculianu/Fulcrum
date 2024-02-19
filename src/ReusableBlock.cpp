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
#ifdef ENABLE_TESTS
#include "App.h"
#include "ReusableBlock.h"

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

        Log(Log::Color::BrightWhite) << "All ReusableBlock unit tests passed!";
    }

    static const auto test_ = App::registerTest("reusable", &test);
}
#endif
