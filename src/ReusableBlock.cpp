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
#ifdef ENABLE_TESTS
#include "App.h"
#include "ReusableBlock.h"
#include <QRandomGenerator>
#include <QVector>


namespace {
    void test()
    {
        QRandomGenerator rgen = QRandomGenerator();
        auto genRandomRuHash = [&rgen] {
            QVector<quint32> vec(32);
            rgen.fillRange(vec.data(), vec.size());
            RuHash h; // lazy but who really would be so pedantic to care
            for (size_t i=0; i<h.size(); ++i) // shh
                h.push_back(vec[i]);
            return h;
        };

        Log() << "Testing ReusableBlock add...";
        ReusableBlock ru;
        for (size_t i=1; i<100; ++i) {
            size_t times = rgen.bounded(4);
            for (size_t j=0; j<times; ++j)
                ru.add(genRandomRuHash(), i);
        }

        Log() << "Testing ReusableBlock serialize...";
        QByteArray serialized = ru.toBytes();

        Log() << "Testing ReusableBlock deserialize...";
        ReusableBlock ru2 = ReusableBlock::fromBytes(serialized);

        Log() << "Testing equality...";
        if (ru != ru2)
            throw Exception("ReusableBlock not equal");
    }

    static const auto test_  = App::registerTest("reusable", &test);
}
#endif
