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
#include "ZmqSequence.h"

#include "bitcoin/crypto/common.h" // ReadLE32, ReadLE64

namespace ZmqSequence {

std::optional<Msg> parseBody(const QByteArray &body)
{
    constexpr int kLabelPos = HashLen, kBlockMsgLen = HashLen + 1, kTxMsgLen = HashLen + 1 + 8;
    if (body.size() != kBlockMsgLen && body.size() != kTxMsgLen)
        return std::nullopt;
    Msg ret;
    switch (const char c = body.at(kLabelPos)) {
    case 'C': case 'D': case 'A': case 'R':
        ret.label = static_cast<Msg::Label>(c);
        break;
    default:
        return std::nullopt;
    }
    // "A" and "R" always carry an 8-byte mempool sequence number, "C" and "D" never do
    if (ret.isTx() != (body.size() == kTxMsgLen))
        return std::nullopt;
    ret.hash = body.left(HashLen);
    if (ret.isTx())
        ret.mempoolSeq = bitcoin::ReadLE64(reinterpret_cast<const uint8_t *>(body.constData()) + kLabelPos + 1);
    return ret;
}

std::optional<uint32_t> parseMsgCounter(const QByteArray &part)
{
    if (part.size() != int(sizeof(uint32_t)))
        return std::nullopt;
    return bitcoin::ReadLE32(reinterpret_cast<const uint8_t *>(part.constData()));
}

Delta computeDelta(const std::vector<Event> &events, const uint64_t fromSeq, const uint64_t toSeq)
{
    Delta d;
    d.nextSeq = fromSeq;
    for (const auto & e : events) {
        if (e.mempoolSeq < fromSeq || e.mempoolSeq >= toSeq)
            continue;
        ++d.nEvents;
        if (e.added) {
            d.adds.insert(e.txHash);
        } else {
            d.adds.erase(e.txHash); // added, then removed again within this run: nothing to fetch
            d.drops.insert(e.txHash);
        }
        if (e.mempoolSeq >= d.nextSeq)
            d.nextSeq = e.mempoolSeq + 1u;
    }
    return d;
}

std::size_t countUnexplained(const TxHashSet &appeared, const TxHashSet &vanished, const std::vector<Event> &events,
                             const uint64_t fromSeq, const uint64_t snapshotSeq)
{
    const Delta d = computeDelta(events, fromSeq, snapshotSeq);
    std::size_t ct = 0u;
    for (const auto & txHash : appeared)
        if (!d.adds.contains(txHash)) // appeared, yet there was no (final) "A" for it
            ++ct;
    for (const auto & txHash : vanished)
        if (!d.drops.contains(txHash) || d.adds.contains(txHash)) // vanished, yet it was not (finally) removed
            ++ct;
    return ct;
}

} // namespace ZmqSequence
