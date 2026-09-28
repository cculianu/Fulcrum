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
#include "Tests.h"
#include "ZmqSequence.h"

#include "bitcoin/crypto/common.h" // WriteLE32, WriteLE64

#include <optional>
#include <vector>

namespace {
    QByteArray makeHash(char fill) { return QByteArray(HashLen, fill); }

    /// Builds a "sequence" message body exactly as bitcoind publishes it
    QByteArray makeBody(const QByteArray &hash, char label, std::optional<uint64_t> mempoolSeq = std::nullopt) {
        QByteArray ret = hash;
        ret.append(label);
        if (mempoolSeq) {
            uint8_t buf[8];
            bitcoin::WriteLE64(buf, *mempoolSeq);
            ret.append(reinterpret_cast<const char *>(buf), int(sizeof(buf)));
        }
        return ret;
    }

    QByteArray makeCounter(uint32_t ctr) {
        uint8_t buf[4];
        bitcoin::WriteLE32(buf, ctr);
        return QByteArray(reinterpret_cast<const char *>(buf), int(sizeof(buf)));
    }
} // namespace

TEST_SUITE(zmqsequence)

TEST_CASE(parse_body) {
    const QByteArray h = makeHash('\x11');
    // block connected / disconnected carry no mempool sequence number
    for (const char c : {'C', 'D'}) {
        const auto m = ZmqSequence::parseBody(makeBody(h, c));
        TEST_CHECK(m.has_value());
        TEST_CHECK(m && m->hash == h && !m->isTx() && !m->mempoolSeq && static_cast<char>(m->label) == c);
    }
    // tx added / removed carry an 8-byte little-endian mempool sequence number
    for (const char c : {'A', 'R'}) {
        const auto m = ZmqSequence::parseBody(makeBody(h, c, 0x0102030405060708ull));
        TEST_CHECK(m.has_value());
        TEST_CHECK(m && m->hash == h && m->isTx() && m->mempoolSeq == 0x0102030405060708ull
                   && static_cast<char>(m->label) == c);
    }
    // the byte layout is: 32-byte hash, 1-byte label, then the LE uint64 (so the lowest-order byte comes first)
    {
        QByteArray raw = h + QByteArray("A") + QByteArray::fromHex("2a00000000000000");
        const auto m = ZmqSequence::parseBody(raw);
        TEST_CHECK(m && m->label == ZmqSequence::Msg::Label::TxAdded && m->mempoolSeq == 42u);
    }
    // malformed bodies are rejected
    TEST_CHECK(!ZmqSequence::parseBody(QByteArray{}));
    TEST_CHECK(!ZmqSequence::parseBody(h)); // no label
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'X'))); // unknown label
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'X', 1u))); // unknown label, tx-sized
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'A'))); // "A" lacking its mempool sequence
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'R'))); // "R" lacking its mempool sequence
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'C', 1u))); // "C" must not carry a mempool sequence
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'A', 1u) + 'x')); // trailing junk
    TEST_CHECK(!ZmqSequence::parseBody(makeBody(h, 'A', 1u).mid(1))); // truncated hash
};

TEST_CASE(msg_counter) {
    TEST_CHECK(ZmqSequence::parseMsgCounter(makeCounter(0u)) == 0u);
    TEST_CHECK(ZmqSequence::parseMsgCounter(makeCounter(0xfffffffeu)) == 0xfffffffeu);
    TEST_CHECK(ZmqSequence::parseMsgCounter(QByteArray::fromHex("01000000")) == 1u); // little-endian
    TEST_CHECK(!ZmqSequence::parseMsgCounter(QByteArray{}));
    TEST_CHECK(!ZmqSequence::parseMsgCounter(QByteArray(3, '\0')));
    TEST_CHECK(!ZmqSequence::parseMsgCounter(QByteArray(5, '\0')));

    TEST_CHECK(ZmqSequence::isNextMsgCounter(0u, 1u));
    TEST_CHECK(ZmqSequence::isNextMsgCounter(0xffffffffu, 0u)); // wraps around
    TEST_CHECK(!ZmqSequence::isNextMsgCounter(5u, 5u)); // duplicate
    TEST_CHECK(!ZmqSequence::isNextMsgCounter(5u, 7u)); // one message was lost
    TEST_CHECK(!ZmqSequence::isNextMsgCounter(5u, 0u)); // counter reset (e.g. bitcoind restarted)
};

TEST_CASE(compute_delta) {
    using ZmqSequence::computeDelta;
    using Set = ZmqSequence::TxHashSet;
    const auto a = makeHash('a'), b = makeHash('b'), c = makeHash('c'), d = makeHash('d'), e = makeHash('e');
    const std::vector<ZmqSequence::Event> evs = {
        {a, 10, true},                 // plain addition
        {b, 11, true}, {b, 12, false}, // added then removed again: nothing to fetch, drop if present
        {c, 13, false},                // plain removal
        {d, 14, false}, {d, 15, true}, // removed then re-added: drop it and fetch it again
        {e, 20, true},                 // the mempool sequence may jump (block-inclusion removals are not published)
    };

    const auto all = computeDelta(evs, 10);
    TEST_CHECK_EQUAL(all.nEvents, 7u);
    TEST_CHECK_EQUAL(all.nextSeq, 21u);
    TEST_CHECK(all.adds == Set({a, d, e}));
    TEST_CHECK(all.drops == Set({b, c, d}));

    // events below the baseline are already reflected in the mirror and are ignored
    const auto tail = computeDelta(evs, 14);
    TEST_CHECK_EQUAL(tail.nEvents, 3u);
    TEST_CHECK_EQUAL(tail.nextSeq, 21u);
    TEST_CHECK(tail.adds == Set({d, e}));
    TEST_CHECK(tail.drops == Set({d}));

    // the upper bound is exclusive
    const auto head = computeDelta(evs, 0, 12);
    TEST_CHECK_EQUAL(head.nEvents, 2u);
    TEST_CHECK_EQUAL(head.nextSeq, 12u);
    TEST_CHECK(head.adds == Set({a, b}));
    TEST_CHECK(head.drops.empty());

    // no events in range: nextSeq stays put
    const auto none = computeDelta(evs, 100);
    TEST_CHECK(none.nEvents == 0u && none.nextSeq == 100u && none.adds.empty() && none.drops.empty());
    TEST_CHECK_EQUAL(computeDelta({}, 7).nextSeq, 7u);
};

TEST_CASE(count_unexplained) {
    using ZmqSequence::countUnexplained;
    using Set = ZmqSequence::TxHashSet;
    const auto a = makeHash('a'), b = makeHash('b'), c = makeHash('c'), d = makeHash('d'), e = makeHash('e');
    const std::vector<ZmqSequence::Event> evs = { {a, 5, true}, {b, 6, false}, {c, 7, false}, {c, 8, true} };

    // mirror at 5, snapshot at 9: a appeared and b vanished, both explained; c was re-added so it is in both (no diff)
    TEST_CHECK_EQUAL(countUnexplained(Set({a}), Set({b}), evs, 5, 9), 0u);
    // d appeared without an "A" and e vanished without an "R"
    TEST_CHECK_EQUAL(countUnexplained(Set({a, d}), Set({b, e}), evs, 5, 9), 2u);
    // c vanished although its last event in the window was "A"
    TEST_CHECK_EQUAL(countUnexplained(Set{}, Set({c}), evs, 5, 9), 1u);
    // events outside [fromSeq, snapshotSeq) explain nothing
    TEST_CHECK_EQUAL(countUnexplained(Set({a}), Set{}, evs, 6, 9), 1u);
    TEST_CHECK_EQUAL(countUnexplained(Set({a}), Set{}, evs, 0, 5), 1u);
    // no differences, no events: nothing unexplained
    TEST_CHECK_EQUAL(countUnexplained(Set{}, Set{}, {}, 0, 100), 0u);
};

TEST_SUITE_END()
