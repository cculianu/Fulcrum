//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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
        else if (auto *bh = blockHeight(); bh && *bh)
            ret = **bh; // ptr -> optional -> value
        else if (auto *hs = hashSet(); hs && *hs) {
            const HashSet& source = **hs;
            std::vector<HashX> transformed;
            transformed.reserve( source.size() );
            std::transform( source.begin(), source.end(),
                            std::back_inserter(transformed),
                            [](const TxHash& hash) { return Util::ToHexFast(hash); });

#if QT_VERSION < QT_VERSION_CHECK(5, 14, 0)
            // Qt < 5.14 lacks the ranged constructors for containers so we must do this.
            ret = QVariantList::fromStdList(Util::toList<std::list<QVariant>>(transformed));
#else
            ret = Util::toList<QVariantList>(transformed);
#endif
        }
    }
    return ret;
}
