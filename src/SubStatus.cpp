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
#include "SubStatus.h"
#include "Util.h"

QVariant SubStatus::toVariant() const
{
    QVariant ret; // if empty we simply notify as 'null'
    if (has_value()) {
        if (auto *ba = byteArray(); ba && !ba->isEmpty())
            ret = Util::ToHexFast(*ba);
        else if (auto *dsp = dsproof(); dsp && !dsp->isEmpty())
            ret = dsp->toVarMap();
        else if (auto bh = blockHeight(); bh)
            ret = *bh; // optional -> value
    }
    return ret;
}

#ifdef ENABLE_TESTS
#include "App.h"
#include "Common.h"
#include "Util.h"

namespace {
    using Print = Log;

    bool doTest()
    {
        size_t ctr = 0;
        const Tic t0;
#undef STR
#undef CHK
#define STR(x) #x
#define CHK(x) \
    do { \
        ++ctr; \
        if ( ! (x) ) { \
            Error() << "Test: \"" << STR(x) << "\" failed!"; \
            return false; \
        } else { \
            Print() << "Test: \"" << STR(x) << "\"" << " passed"; \
        } \
    } while(0)

    CHK(!SubStatus().has_value());
    CHK(SubStatus(QByteArray{}).has_value());
    CHK(SubStatus(DSProof{}).has_value());
    CHK(SubStatus(std::nullopt).has_value());
    CHK(!SubStatus(std::nullopt).blockHeight().has_value());
    CHK(SubStatus(BlockHeight{1}).blockHeight().has_value());
    CHK(SubStatus(BlockHeight{1}).blockHeight().value_or(0) == 1);
    CHK(SubStatus(std::nullopt).has_value());
    CHK(!SubStatus(std::nullopt).blockHeight().has_value());
    CHK(SubStatus(BlockHeight{1}).blockHeight().has_value());
    CHK(SubStatus(BlockHeight{1}).blockHeight().value_or(0) == 1);

    CHK(SubStatus{}.byteArray() == nullptr);
    CHK(SubStatus(QByteArray{}).byteArray() != nullptr);
    CHK(SubStatus(DSProof{}).byteArray() == nullptr);
    CHK(SubStatus(BlockHeight{}).byteArray() == nullptr);

    CHK(SubStatus{}.dsproof() == nullptr);
    CHK(SubStatus(QByteArray{}).dsproof() == nullptr);
    CHK(SubStatus(DSProof{}).dsproof() != nullptr);
    CHK(SubStatus(BlockHeight{}).dsproof() == nullptr);

    CHK(SubStatus{}.blockHeight() == std::nullopt);
    CHK(SubStatus(QByteArray{}).blockHeight() == std::nullopt);
    CHK(SubStatus(DSProof{}).blockHeight() == std::nullopt);
    CHK(SubStatus(BlockHeight{}).blockHeight() != std::nullopt);

    SubStatus null;
    SubStatus qb{QByteArray(32, 'c')};
    SubStatus ds{DSProof{DspHash(), QByteArray{128, 'e'}, TXO{TxHash{32, 'a'}, 1}, TxHash{32, 'f'}, {}}};
    SubStatus bh{12345};
    SubStatus tmp;

    CHK(bh != SubStatus{12346});
    CHK(!(SubStatus{12346} == bh));
    CHK(bh == SubStatus{12345});
    CHK(ds.dsproof() && !ds.dsproof()->isEmpty());
    CHK(ds != DSProof{});
    const DSProof ds2{DspHash(), QByteArray{128, 'e'}, TXO{TxHash{32, 'a'}, 1}, TxHash{32, 'f'}, {}};
    const DSProof ds3{DspHash(), QByteArray{128, 'z'}, TXO{TxHash{32, 'a'}, 1}, TxHash{32, 'f'}, {}};
    CHK(ds == ds2);
    CHK(ds != ds3);
    CHK(bh != ds2);
    CHK(ds != std::optional<BlockHeight>(12345));
    CHK(bh == std::optional<BlockHeight>(12345));
    CHK(bh != std::optional<BlockHeight>(12346));
    CHK(qb == QByteArray(32, 'c'));
    CHK(qb != QByteArray(32, '!'));

    CHK(tmp == null);
    CHK(!tmp.has_value());
    CHK(tmp != qb);
    CHK(tmp != ds);
    CHK(tmp != bh);
    CHK(!tmp.byteArray());
    CHK(!tmp.dsproof());
    CHK(!tmp.blockHeight().has_value());

    tmp = qb;
    CHK(tmp.has_value());
    CHK(tmp != null);
    CHK(tmp == qb);
    CHK(tmp != ds);
    CHK(tmp != bh);
    CHK(tmp.byteArray());
    CHK(!tmp.dsproof());
    CHK(!tmp.blockHeight().has_value());
    tmp.reset();
    CHK(!tmp.has_value());
    CHK(tmp == null);

    tmp = ds;
    CHK(tmp.has_value());
    CHK(tmp != null);
    CHK(tmp != qb);
    CHK(tmp == ds);
    CHK(tmp != bh);
    tmp.reset();
    CHK(!tmp.has_value());
    CHK(tmp == null);

    tmp = bh;
    CHK(tmp.has_value());
    CHK(tmp != null);
    CHK(tmp != qb);
    CHK(tmp != ds);
    CHK(tmp == bh);
    tmp.reset();
    CHK(!tmp.has_value());
    CHK(tmp == null);

    auto oqb = qb;
    tmp = std::move(qb);
    CHK(tmp == oqb && tmp.byteArray() != nullptr);

    auto ods = ds;
    tmp = std::move(ds);
    CHK(tmp == ods && tmp.dsproof() != nullptr);

    auto obh = bh;
    tmp = std::move(bh);
    CHK(tmp == obh && tmp.blockHeight() != std::nullopt);

    tmp = SubStatus{};
    CHK(tmp == null && !tmp.has_value() && !tmp.blockHeight() && !tmp.byteArray() && !tmp.dsproof());

    Print() << "substatus passed " << ctr << " checks ok in " << t0.msecStr() << " msecs";
    return true;
#undef STR
#undef CHK
    }

    const auto t = App::registerTest("substatus", []{
        if (!doTest()) throw Exception("substatus test failed");
    });
} // namespace

#endif
