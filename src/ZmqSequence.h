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
#pragma once

#include "BlockProcTypes.h"

#include <QByteArray>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <unordered_set>
#include <vector>

/// Helpers for the bitcoind ZMQ "sequence" topic (`-zmqpubsequence`, Bitcoin Core >= 0.21).
///
/// Unlike "hashtx", which only says that *some* tx arrived, the "sequence" topic reports every mempool addition ("A")
/// and every mempool removal for a reason other than block inclusion ("R"), each stamped with bitcoind's mempool
/// sequence number, as well as block connects ("C") and disconnects ("D"). Together with `getrawmempool false true`,
/// which returns the mempool txids plus the mempool sequence number that the *next* mempool event will be assigned,
/// this lets a subscriber mirror the mempool exactly: take one snapshot, then apply, in order, every A/R event whose
/// mempool sequence is >= the snapshot's. There is then no need to download the entire txid list on every change.
///
/// Wire format of a "sequence" message (see bitcoind's doc/zmq.md):
///
///     part 1: "sequence"
///     part 2: <32-byte hash, reversed (i.e. display/RPC byte order)> <label: 'C' | 'D' | 'A' | 'R'>
///             [<8-byte little-endian mempool sequence>, only for 'A' and 'R']
///     part 3: <4-byte little-endian per-topic message counter>
///
/// The message counter increments by exactly 1 for every message published on the topic, so any discontinuity means
/// messages were lost (e.g. dropped at the ZMQ high water mark). The mempool sequence number, by contrast, also
/// advances for block-inclusion removals (which are not published as "R"), so gaps in it are normal and must not be
/// treated as loss.
namespace ZmqSequence {

    /// A decoded "sequence" topic message body.
    struct Msg {
        enum class Label : char { BlockConnected = 'C', BlockDisconnected = 'D', TxAdded = 'A', TxRemoved = 'R' };
        /// 32 bytes, already in the same (big-endian, display) byte order Fulcrum uses for TxHash and BlockHash.
        QByteArray hash;
        Label label{};
        /// Present iff `label` is TxAdded or TxRemoved.
        std::optional<uint64_t> mempoolSeq;

        bool isTx() const noexcept { return label == Label::TxAdded || label == Label::TxRemoved; }
    };

    /// Parses the body (the 2nd message part) of a "sequence" topic message. Returns std::nullopt if it is malformed.
    std::optional<Msg> parseBody(const QByteArray &body);

    /// Parses the 4-byte little-endian per-topic message counter (the 3rd message part). Returns std::nullopt if it
    /// is malformed.
    std::optional<uint32_t> parseMsgCounter(const QByteArray &part);

    /// Returns true iff `next` is the message counter that immediately follows `prev` (the counter wraps at 2^32).
    constexpr bool isNextMsgCounter(uint32_t prev, uint32_t next) noexcept { return uint32_t(prev + 1u) == next; }

    /// A mempool addition or removal, as received on the topic.
    struct Event {
        TxHash txHash;
        uint64_t mempoolSeq{};
        bool added{}; ///< true for "A", false for "R"
    };

    using TxHashSet = std::unordered_set<TxHash, HashHasher>;

    /// The net effect of a run of events on a mempool mirror that already reflects every event below some mempool
    /// sequence number. Drops must be applied before adds.
    struct Delta {
        /// Remove these, if present (along with their in-mempool descendants). A txid that was removed and then
        /// re-added within the run appears in both `drops` and `adds`, so that it is refetched rather than trusted.
        TxHashSet drops;
        /// These must be in the mempool afterwards (i.e. they are to be fetched if absent once `drops` are applied).
        TxHashSet adds;
        /// The first mempool sequence number not covered by this delta.
        uint64_t nextSeq{};
        /// The number of events folded into this delta.
        std::size_t nEvents{};
    };

    /// Folds the `events` whose mempool sequence number lies in [fromSeq, toSeq) into a Delta. `events` must be in
    /// arrival order (which is also mempool sequence order).
    Delta computeDelta(const std::vector<Event> &events, uint64_t fromSeq,
                       uint64_t toSeq = std::numeric_limits<uint64_t>::max());

    /// Verification helper for a full snapshot taken while a mirror was being maintained incrementally.
    ///
    /// `appeared` are the txids that were in the snapshot but not in the mirror, and `vanished` are the txids that
    /// were in the mirror but not in the snapshot, where the mirror reflected every event < `fromSeq` and the snapshot
    /// reflects every event < `snapshotSeq`. Returns how many of those differences are *not* explained by the `events`
    /// in [fromSeq, snapshotSeq). A non-zero result means the incremental mirror had drifted from bitcoind's mempool.
    std::size_t countUnexplained(const TxHashSet &appeared, const TxHashSet &vanished, const std::vector<Event> &events,
                                 uint64_t fromSeq, uint64_t snapshotSeq);

} // namespace ZmqSequence
