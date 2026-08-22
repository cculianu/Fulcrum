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
#include "BTC.h"
#include "Tests.h"
#include "Util.h"

#include "bitcoin/block.h"
#include "bitcoin/crypto/blake2b.h"
#include "bitcoin/uint256.h"

#include <QByteArray>
#include <QString>

#include <cstdint>
#include <string>

namespace {

// Vectors lifted verbatim from Bitcoin Knots' src/test/data/block_header_v2.json
// (tag v29.4.1.knots20260508rc2), which cover all four ASIC profiles.
struct V2Vector {
    const char *name;
    const char *serialized;
    const char *blockHash;
    std::int32_t nVersion;
    std::uint32_t nTime, nBits, nNonce, nonce2, nonce3, timeOffset;
    std::uint16_t txcount;
    std::uint8_t flags, xorKeyMaskClearBits;
    std::int32_t height;
    const char *xorKey, *extranonce, *mmRhs;
};

const V2Vector v2Vectors[] = {
    {
        "profile_0_time_offset",
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704",
        536870912, 2000000000u, 486604799u, 195948557u, 287454020u, 2309737967u, 600u, 3u, 28u,
        0u, 840000, "00000000000000000000000000000000", "00112233445566778899aabbccddeeff", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    },
    {
        "profile_1_time_offset_nonzero_key",
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000001001d00efcdab8967452301efcdab896745230141d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "44b383821dea9af8d7d81ba7741c34ac8c07ab81ab081d8b6bf0575a787a1eef",
        536870912, 2000000000u, 486604799u, 195948557u, 287454020u, 2309737967u, 600u, 1u, 29u,
        0u, 840001, "0123456789abcdef0123456789abcdef", "00112233445566778899aabbccddeeff", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    },
    {
        "profile_2_time_offset_selector_7",
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0bddccbbaaefcdab89ffeeddccbbaa998877665544332211005802000003001e071032547698badcfe1032547698badcfe40d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "06fddae4eaca10b85c87a3c7ed71717fd83998a32fe13f4780722b1f5d882e76",
        536870912, 2000000000u, 486604799u, 195948557u, 2864434397u, 2309737967u, 600u, 3u, 30u,
        7u, 840000, "fedcba9876543210fedcba9876543210", "00112233445566778899aabbccddeeff", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    },
    {
        "profile_3_time_offset_selector_8",
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211040302010000000000000000ffffffffffffffff5802000003001f081032547698badcfe1032547698badcfe40d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab",
        "e6304527536f619d3ad71b1c21a22fdef9068498acc561b4100b034373a87058",
        536870912, 2000000000u, 486604799u, 195948557u, 287454020u, 16909060u, 600u, 3u, 31u,
        8u, 840000, "fedcba9876543210fedcba9876543210", "ffffffffffffffff0000000000000000", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    },
    {
        "profile_0_time_offset_disabled_selector_255",
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f000943577ffff001dffffffff44332211efcdab89ffeeddccbbaa9988776655443322110088776655030018ff2222222222222222111111111111111140d10c000000000000000000000000000000000000000000000000000000000000000000",
        "c31b24420d67f86e524f980a24a18e88f36c821046d5288251b5d88998c69f86",
        536870912, 2000000000u, 486604799u, 4294967295u, 287454020u, 2309737967u, 1432778632u, 3u, 24u,
        255u, 840000, "11111111111111112222222222222222", "00112233445566778899aabbccddeeff", "0000000000000000000000000000000000000000000000000000000000000000"
    },
};

QByteArray hexToBytes(const char *hex) { return Util::ParseHexFast(QByteArray(hex)); }

QString toHex(const QByteArray &b) { return QString::fromLatin1(Util::ToHexFast(b)); }

QString blobHex(const std::uint8_t *p, std::size_t n) {
    return toHex(QByteArray(reinterpret_cast<const char *>(p), int(n)));
}

void checkV2Vector(const V2Vector &v) {
    const QByteArray raw = hexToBytes(v.serialized);
    TEST_CHECK_MESSAGE(raw.size() == int(bitcoin::CBlockHeader::V2_SIZE), v.name);

    const auto hdr = BTC::Deserialize<bitcoin::CBlockHeader>(raw, 0, false, false, true, /* noJunkAtEnd = */ true);

    TEST_CHECK_MESSAGE(hdr.m_header_v2, v.name);
    TEST_CHECK_MESSAGE(hdr.GetSerializedSize() == bitcoin::CBlockHeader::V2_SIZE, v.name);

    // The version field excludes the v2 flag, but the wire form keeps it.
    TEST_CHECK_MESSAGE(hdr.nVersion == v.nVersion, v.name);
    TEST_CHECK_MESSAGE(hdr.GetCompleteVersion()
                       == (bitcoin::CBlockHeader::VERSION_HEADER_V2_FLAG | std::uint32_t(v.nVersion)), v.name);

    TEST_CHECK_MESSAGE(hdr.nTime == v.nTime, v.name);
    TEST_CHECK_MESSAGE(hdr.nBits == v.nBits, v.name);
    TEST_CHECK_MESSAGE(hdr.nNonce == v.nNonce, v.name);
    TEST_CHECK_MESSAGE(hdr.m_nonce2 == v.nonce2, v.name);
    TEST_CHECK_MESSAGE(hdr.m_nonce3 == v.nonce3, v.name);
    TEST_CHECK_MESSAGE(hdr.m_time_offset == v.timeOffset, v.name);
    TEST_CHECK_MESSAGE(hdr.m_txcount == v.txcount, v.name);
    TEST_CHECK_MESSAGE(hdr.m_flags == v.flags, v.name);
    TEST_CHECK_MESSAGE(hdr.m_xor_key_mask_clear_bits == v.xorKeyMaskClearBits, v.name);
    TEST_CHECK_MESSAGE(hdr.m_height == v.height, v.name);
    // The blob fields are given in the JSON in display (big-endian) order, as ToString() renders them.
    TEST_CHECK_MESSAGE(hdr.m_xor_key.ToString() == std::string(v.xorKey), v.name);
    TEST_CHECK_MESSAGE(hdr.m_extranonce.ToString() == std::string(v.extranonce), v.name);
    TEST_CHECK_MESSAGE(hdr.m_mm_rhs.ToString() == std::string(v.mmRhs), v.name);

    // The BLAKE2b block hash.
    TEST_CHECK_MESSAGE(hdr.GetHash().ToString() == std::string(v.blockHash), v.name);

    // Round-trips byte-for-byte, including the nTime/m_time_offset dance.
    TEST_CHECK_MESSAGE(toHex(BTC::Serialize(hdr)) == QString(v.serialized), v.name);
}

} // namespace

TEST_SUITE(blockheader)

TEST_CASE(blake2b_kats) {
    // Standard BLAKE2b-256 known-answer tests, to prove the vendored reference code is wired up correctly.
    const std::pair<const char *, const char *> kats[] = {
        {"", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
        {"abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
    };
    for (const auto & [in, expected] : kats) {
        std::uint8_t out[32];
        const std::size_t len = std::string(in).size();
        TEST_CHECK(0 == bitcoin::blake2b_nokey(out, sizeof(out), in, len));
        TEST_CHECK_EQUAL(blobHex(out, sizeof(out)), QString(expected));
    }
};

TEST_CASE(header_v2_vectors) {
    for (const auto &v : v2Vectors) checkV2Vector(v);
};

TEST_CASE(header_v1_unchanged) {
    // Mainnet block 100,000 -- a legacy header must deserialize, hash and re-serialize exactly as before.
    const char * const serialized =
        "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd002000000000"
        "06657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b"
        "4d4c86041b0f2b5710";
    const QByteArray raw = hexToBytes(serialized);
    TEST_CHECK_EQUAL(raw.size(), int(bitcoin::CBlockHeader::V1_SIZE));

    const auto hdr = BTC::Deserialize<bitcoin::CBlockHeader>(raw, 0, false, false, true, /* noJunkAtEnd = */ true);

    TEST_CHECK(!hdr.m_header_v2);
    TEST_CHECK_EQUAL(hdr.GetSerializedSize(), bitcoin::CBlockHeader::V1_SIZE);
    TEST_CHECK_EQUAL(hdr.nVersion, 1);
    TEST_CHECK_EQUAL(hdr.GetCompleteVersion(), 1u);
    TEST_CHECK_EQUAL(hdr.GetTimeOnWire(), hdr.nTime);
    TEST_CHECK_EQUAL(hdr.GetHash().ToString(),
                     std::string("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"));
    TEST_CHECK_EQUAL(toHex(BTC::Serialize(hdr)), QString(serialized));

    // And the v2 fields stay null for a legacy header.
    bitcoin::CBlockHeader nulled = hdr;
    nulled.SetV2FieldsNull();
    TEST_CHECK_EQUAL(toHex(BTC::Serialize(nulled)), QString(serialized));
};

TEST_SUITE_END()
