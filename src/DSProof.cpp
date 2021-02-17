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

#include "BTC.h"
#include "DSProof.h"

#include <algorithm>
#include <type_traits>
#include <utility>


bool DSPs::add(DSProof && dspIn)
{
    if (!dspIn.hash.isValid())
        throw BadArgs("Bad dsp hash");
    if (dspIn.txHash.size() != HashLen || !dspIn.descendants.count(dspIn.txHash))
        throw BadArgs("Expected dsp txHash to be valid and in its own descendant set");
    auto [it, inserted] = dsproofs.emplace(DspHash(dspIn.hash), std::move(dspIn));
    if (!inserted)
        return false;
    const auto &dsp = it->second;
    for (const auto & txHash : dsp.descendants)
        txDspsMap[txHash].emplace(dsp.hash);
    return true;
}
DSProof * DSPs::getMutable(const DspHash &hash) // private
{
    if (auto it = dsproofs.find(hash); it != dsproofs.end())
        return &it->second;
    return nullptr;
}
const DSProof * DSPs::get(const DspHash &hash) const { return const_cast<DSPs *>(this)->getMutable(hash); }
std::size_t DSPs::rm(const DspHash &hash)
{
    auto it = dsproofs.find(hash);
    if (it == dsproofs.end()) return 0;
    auto & dsp = it->second;
    // erase all links from tx -> dsp
    std::size_t ret{};
    for (const auto &txHash : dsp.descendants) {
        auto it2 = txDspsMap.find(txHash);
        if (it2 == txDspsMap.end()) continue; // may happen if we are called from rmTx()
        it2->second.erase(hash);
        if (it2->second.empty())
            // no more dsps linked to this tx, remove from map
            txDspsMap.erase(it2);
        ++ret;
    }
    dsproofs.erase(it);
    return ret;
}
bool DSPs::addTx(const DspHash &dspHash, const TxHash &txHash)
{
    DSProof *dsp;
    if (txHash.size() != HashLen || !(dsp = getMutable(dspHash)))
        return false;
    txDspsMap[txHash].emplace(dsp->hash);
    dsp->descendants.emplace(txHash); // this is how calling code adds new descendants it learns about
    return true;
}
std::size_t DSPs::rmTx(const TxHash &txHash)
{
    auto it = txDspsMap.find(txHash);
    if (it == txDspsMap.end()) return 0;
    const DspHashSet dspHashes{std::move(it->second)};
    txDspsMap.erase(it);
    // remove from descendant set for all associated dsps
    std::size_t ret{};
    for (const auto &dspHash : dspHashes) {
        auto *dsp = getMutable(dspHash);
        if (!dsp) {
            // this should never happen
            Error() << "FIXME: missing dsp " << dspHash.toHex() << " for tx " << txHash.toHex();
            continue;
        }
        if (dsp->txHash == txHash) {
            // master tx gone! Remove this dsproof, and all the links to its descendants
            rm(dsp->hash); // will invalidate pointer `dsp`
        } else {
            // descendant tx, erase from set
            if (!dsp->descendants.erase(txHash))
                // this should never happen
                Error() << "FIXME: dsp " << dspHash.toHex() << " missing tx " << txHash.toHex() << " in its descendants list";
        }
        ++ret;
    }
    return ret;
}

auto DSPs::dspHashesForTx(const TxHash &txHash) const -> const DspHashSet *
{
    if (auto it = txDspsMap.find(txHash); it != txDspsMap.end())
        return &it->second;
    return nullptr;
}

std::vector<const DSProof *> DSPs::proofsLinkedToTx(const TxHash &txHash) const
{
    std::vector<const DSProof *> ret;
    auto *dspHashes = dspHashesForTx(txHash);
    if (!dspHashes) return ret;
    ret.reserve(dspHashes->size());
    for (const auto &hash : *dspHashes)
        if (auto *dsp = get(hash))
            ret.push_back(dsp);
    return ret;
}

const DSProof * DSPs::proofForTx(const TxHash &txHash) const
{
    for (auto *dsp : proofsLinkedToTx(txHash))
        if (dsp->txHash == txHash)
            return dsp;
    return nullptr;
}
