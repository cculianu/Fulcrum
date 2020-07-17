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
#include "Mempool.h"

#include <algorithm>
#include <functional>
#include <map>

auto Mempool::calcCompactFeeHistogram(double binSize) const -> FeeHistogramVec
{
    // this algorithm is taken from:
    // https://github.com/Electron-Cash/electrumx/blob/fbd00416d804c286eb7de856e9399efb07a2ceaf/electrumx/server/mempool.py#L139
    FeeHistogramVec ret;
    std::map<unsigned, unsigned, std::greater<unsigned>> histogram; // sorted map, descending order by key

    for (const auto & [txid, tx] : txs) {
        const auto feeRate = unsigned(tx->fee / bitcoin::Amount::satoshi()) // sats
                             /  std::max(tx->sizeBytes, 1u); // per byte
        histogram[feeRate] += tx->sizeBytes; // accumulate size by feeRate
    }

    // now, compact the bins
    ret.reserve(8);
    unsigned cumSize = 0;
    double r = 0.;

    for (const auto & [feeRate, size] : histogram) {
        cumSize += size;
        if (cumSize + r > binSize) {
            ret.push_back(FeeHistogramItem{feeRate, cumSize});
            r += double(cumSize) - binSize;
            cumSize = 0;
            binSize *= 1.1;
        }
    }
    ret.shrink_to_fit(); // save memory
    return ret;
}
