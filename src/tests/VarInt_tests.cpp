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
#include "Span.h"
#include "Tests.h"
#include "VarInt.h"

#include "bitcoin/tinyformat.h"

#include <QByteArray>
#include <QRandomGenerator>
#include <QString>
#include <QTimer>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace {

template <unsigned bits>
constexpr std::uint64_t bmax() {
    static_assert (bits <= 64);
    if constexpr (bits == 64)
        return std::numeric_limits<std::uint64_t>::max();
    else
        return (std::uint64_t(0x1) << bits) - 1L;
}

template <typename Int>
void doTest(const char *typeName, int n = 200)
{
    if (const auto empty = VarInt{}; empty.value<int>() != 0 || empty.size() != 1)
        throw std::runtime_error("Default constructed value should represent 0");
    else if (0 != std::memcmp(empty.data(), std::vector<char>(empty.maxSize, 0).data(), empty.maxSize))
        throw std::runtime_error("Expected empty VarInt to be all 0's");
    static_assert (sizeof(Int) <= sizeof(uint64_t));
    Log() << "Iterating " << n << " times for type: " << typeName;
    Int val{};
    QString hex, hexBe;
    QByteArray byteBlob, byteBlobBe;
    std::vector<Int> vals;
    const int checkEvery = std::min(n/10, 1'000);
    vals.reserve(checkEvery);
    try {
        auto CheckCompOps = [](const auto &a, const auto &b) {
            const auto ha = a.hex().toStdString(), hb = b.hex().toStdString();
            const bool ok =    (a == b) == (ha == hb)
                            && (a != b) == (ha != hb)
                            && (a <  b) == (ha <  hb)
                            && (a <= b) == (ha <= hb)
                            && (a >  b) == (ha >  hb)
                            && (a >= b) == (ha >= hb)
                            && (a <=> b) == (ha <=> hb);
            if (!ok) throw std::runtime_error(strprintf("Ops check failed for: %s (hex) and %s (hex)", ha, hb));
        };
        std::optional<VarInt> viPrev;
        std::optional<VarIntBE> viBePrev;
        for (int i = 0; i < n; ++i) {
            Tests::GetRandBytes(reinterpret_cast<std::byte *>(&val), sizeof(val)); // random byte pattern for "val"
            hex.clear();
            const VarInt vi = val;
            const ByteView bv = vi.byteView();
            const VarIntBE viBe(val);
            const ByteView bvBe = viBe.byteView();
            hex = vi.hex();
            hexBe = viBe.hex();
            const Int val2 = vi.value<Int>();
            const Int val3 = viBe.value<Int>();
            Trace() << "Value: " << val <<  " hex: " << hex << " (big-endian: " << hexBe << ") deserialized: " << val2
                    << " (big endian: " << val3 << ") byteLen: " << vi.byteView().size();
            if (val != val2 || val != val3)
                throw std::runtime_error("Ser/deser mistmatch!");
            CheckCompOps(vi, viPrev.value_or(VarInt{}));
            CheckCompOps(viBe, viBePrev.value_or(VarIntBE{}));
            viPrev = vi;
            viBePrev = viBe;
            int expectedLen = 1;
            const std::uint64_t u64val = std::uint64_t(std::make_unsigned_t<Int>(val));
            if (u64val > 247 && u64val <= bmax<8>()) {
                expectedLen = 2;
                TEST_CHECK(bv[0] == static_cast<std::byte>(248));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(248));
            } else if (u64val > bmax<8>() && u64val <= bmax<16>()) {
                expectedLen = 3;
                TEST_CHECK(bv[0] == static_cast<std::byte>(249));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(249));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint8_t>(), std::overflow_error);
            } else if (u64val > bmax<16>() && u64val <= bmax<24>()) {
                expectedLen = 4;
                TEST_CHECK(bv[0] == static_cast<std::byte>(250));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(250));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint16_t>(), std::overflow_error);
            } else if (u64val > bmax<24>() && u64val <= bmax<32>()) {
                expectedLen = 5;
                TEST_CHECK(bv[0] == static_cast<std::byte>(251));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(251));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint16_t>(), std::overflow_error);
            } else if (u64val > bmax<32>() && u64val <= bmax<40>()) {
                expectedLen = 6;
                TEST_CHECK(bv[0] == static_cast<std::byte>(252));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(252));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint32_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint32_t>(), std::overflow_error);
            } else if (u64val > bmax<40>() && u64val <= bmax<48>()) {
                expectedLen = 7;
                TEST_CHECK(bv[0] == static_cast<std::byte>(253));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(253));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint32_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(viBe.value<uint32_t>(), std::overflow_error);
            } else if (u64val > bmax<48>() && u64val <= bmax<56>()) {
                expectedLen = 8;
                TEST_CHECK(bv[0] == static_cast<std::byte>(254));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(254));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint32_t>(), std::overflow_error);
            } else if (u64val > bmax<56>() && u64val <= bmax<64>()) {
                expectedLen = 9;
                TEST_CHECK(bv[0] == static_cast<std::byte>(255));
                TEST_CHECK(bvBe[0] == static_cast<std::byte>(255));
                TEST_CHECK_THROW(vi.value<int8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<int32_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint8_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint16_t>(), std::overflow_error);
                TEST_CHECK_THROW(vi.value<uint32_t>(), std::overflow_error);
            }
            TEST_CHECK(static_cast<int>(bv.size()) == expectedLen);
            TEST_CHECK(static_cast<int>(bvBe.size()) == expectedLen);

            // check serialization is as expected
            if (expectedLen <= 9) {
                std::array<std::byte, 9> arr;
                std::byte *payloadBegin = arr.data(), *payloadEnd = arr.data() + expectedLen;
                if (expectedLen > 1) {
                    *payloadBegin++ = static_cast<std::byte>(246 + expectedLen); // control byte
                }
                const uint64_t arrPayloadLen = payloadEnd - payloadBegin;
                TEST_CHECK(arrPayloadLen <= 8);
                // convert the value to little-endian 64-bit value, and use that as the serialization we expect
                uint64_t le_val = Util::hToLe64(u64val);
                std::memcpy(payloadBegin, reinterpret_cast<std::byte *>(&le_val), arrPayloadLen);
                TEST_CHECK(0 == std::memcmp(bv.data(), arr.data(), expectedLen));

                // now try the big endian encoding
                uint64_t be_val = Util::hToBe64(u64val << (8ull - arrPayloadLen) * 8ull);
                std::memcpy(payloadBegin, reinterpret_cast<std::byte *>(&be_val), arrPayloadLen);
                TEST_CHECK(0 == std::memcmp(bvBe.data(), arr.data(), expectedLen));
            }

            // check deserialize method every 'checkEvery' iterations
            vals.push_back(val);
            byteBlob.append(vi.byteArray(false));
            byteBlobBe.append(viBe.byteArray(false));
            if (vals.size() % checkEvery == 0) {
                Log() << "Validating serialization of " << vals.size() << " items, " << byteBlob.size() << " bytes ...";
                auto byteSpan1 = Span<const char>{byteBlob}, byteSpan1Be = Span<const char>{byteBlobBe};
                Span<const std::byte> byteSpan2(reinterpret_cast<const std::byte *>(byteBlob.constData()), std::size_t(byteBlob.size()));
                Span<const std::byte> byteSpan2Be(reinterpret_cast<const std::byte *>(byteBlobBe.constData()), std::size_t(byteBlobBe.size()));
                int i = 0;
                for (const auto & v : vals) {
                    const VarInt v1 = VarInt::deserialize(byteSpan1),
                                 v2 = VarInt::deserialize(byteSpan2);
                    if (v1.value<Int>() != v || v2.value<Int>() != v || v1 != v2)
                        throw std::runtime_error(QString("Value %1 failed to compare equal (index: %2, hex1: %3, hex2: %4)")
                                                 .arg(v).arg(i).arg(v1.hex(), v2.hex()).toStdString());
                    TEST_CHECK(v1.value<Int>() == v && v2.value<Int>() == v && v1 == v2);
                    // Next, do the same for big endian version
                    const VarIntBE v1Be = VarIntBE::deserialize(byteSpan1Be),
                                   v2Be = VarIntBE::deserialize(byteSpan2Be);
                    if (v1Be.value<Int>() != v || v2Be.value<Int>() != v || v1Be != v2Be)
                        throw std::runtime_error(QString("Value %1 failed to compare equal (index: %2, hex1: %3, hex2: %4)")
                                                     .arg(v).arg(i).arg(v1Be.hex(), v2Be.hex()).toStdString());
                    TEST_CHECK(v1Be.value<Int>() == v && v2Be.value<Int>() == v && v1Be == v2Be);
                    ++i;
                }
                vals.clear();
                byteBlob.clear();
                byteBlobBe.clear();
            }
        }
    } catch (const std::exception &e) {
        const QString msg = QString("Exception for value (%1) hex (%2): %3").arg(val).arg(hex, QString(e.what()));
        throw std::runtime_error(msg.toStdString());
    }
}

} // namespace

TEST_SUITE(varint)
TEST_CASE(test_uint8_t) { doTest<std::uint8_t>("uint8_t"); };
TEST_CASE(test_int8_t) { doTest<std::int8_t>("int8_t"); };
TEST_CASE(test_uint16_t) { doTest<std::uint16_t>("uint16_t"); };
TEST_CASE(test_int16_t) { doTest<std::int16_t>("int16_t"); };
TEST_CASE(test_uint32_t) { doTest<std::uint32_t>("uint32_t"); };
TEST_CASE(test_int32_t) { doTest<std::int32_t>("int32_t"); };
TEST_CASE(test_uint64_t) { doTest<std::uint64_t>("uint64_t"); };
TEST_CASE(test_int64_t) { doTest<std::int64_t>("int64_t"); };
TEST_SUITE_END()


