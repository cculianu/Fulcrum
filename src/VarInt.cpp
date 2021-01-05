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
#ifdef ENABLE_TESTS
#include "App.h"
#include "Span.h"
#include "Util.h"
#include "VarInt.h"

#include <QByteArray>
#include <QRandomGenerator>
#include <QString>
#include <QTimer>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace {

template <unsigned bits>
constexpr std::uint64_t bmax() {
    static_assert (bits <= 64);
    if constexpr (bits == 64)
        return std::numeric_limits<std::uint64_t>::max();
    return (std::uint64_t(0x1) << bits) - 1;
}

#define EXCPECT_EXCEPTION(exc, statement) \
    do { \
        try { \
            statement; \
        } catch (const exc &) { \
            break; \
        } catch (...) { \
            throw std::runtime_error("Expression \"" #statement "\" threw an unexpected exception"); \
        } \
        throw std::runtime_error("Expression \"" #statement "\" did not throw " #exc " as expected"); \
    } while (0)

template <typename Int>
void doTest(int n = 200)
{
    auto * const rgen = QRandomGenerator::system();
    static_assert (sizeof(Int) <= sizeof(quint64));
    constexpr quint64 max = sizeof(Int) < sizeof(quint64) || std::is_signed_v<Int>
                            ? quint64(std::numeric_limits<Int>::max()) + 1
                            : quint64(std::numeric_limits<Int>::max());
    Log() << "Iterating " << n << " times for type: " << typeid(Int).name();
    Int val;
    QString hex;
    QByteArray byteBlob;
    std::vector<Int> vals;
    const int checkEvery = std::min(n/10, 1'000);
    vals.reserve(checkEvery);
    try {
        for (int i = 0; i < n; ++i) {
            val = Int(rgen->generate64() % max);
            if constexpr (std::is_signed_v<Int>) {
                // randomly make half the values be negative
                const bool b = rgen->generate() % 2;
                if (b) val = -val;
            }
            hex.clear();
            const VarInt vi = val;
            hex = vi.hex();
            const Int val2 = vi.value<Int>();
            Log() << "Value: " << val <<  " hex: " << vi.hex() << " deserialized: " << val2 << " byteLen: " << vi.bytes().length();
            if (val != val2)
                throw std::runtime_error("Ser/deser mistmatch!");
            int expectedLen = 1;
            std::uint64_t u64val = std::uint64_t(std::make_unsigned_t<Int>(val));
            if (u64val > 247 && u64val <= bmax<8>())
                expectedLen = 2;
            else if (u64val > bmax<8>() && u64val <= bmax<16>()) {
                expectedLen = 3;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
            } else if (u64val > bmax<16>() && u64val <= bmax<24>()) {
                expectedLen = 4;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
            } else if (u64val > bmax<24>() && u64val <= bmax<32>()) {
                expectedLen = 5;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
            } else if (u64val > bmax<32>() && u64val <= bmax<40>()) {
                expectedLen = 6;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int32_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint32_t>());
            } else if (u64val > bmax<40>() && u64val <= bmax<48>()) {
                expectedLen = 7;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int32_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint32_t>());
            } else if (u64val > bmax<48>() && u64val <= bmax<56>()) {
                expectedLen = 8;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int32_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint32_t>());
            } else if (u64val > bmax<56>() && u64val <= bmax<64>()) {
                expectedLen = 9;
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<int32_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint8_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint16_t>());
                EXCPECT_EXCEPTION(std::overflow_error, vi.value<uint32_t>());
            }
            if (vi.bytes().length() != expectedLen)
                throw std::runtime_error("Length is not as expected!");

            // check deserialize method every 'checkEvery' iterations
            vals.push_back(val);
            byteBlob.append(vi.bytes());
            if (vals.size() % checkEvery == 0) {
                Log() << "Validating serialization of " << vals.size() << " items, " << byteBlob.size() << " bytes ...";
                auto byteSpan1 = MakeCSpan(byteBlob);
                Span<const std::byte> byteSpan2(reinterpret_cast<const std::byte *>(byteBlob.constData()), std::size_t(byteBlob.size()));
                int i = 0;
                for (const auto & v : vals) {
                    const VarInt v1 = VarInt::deserialize(byteSpan1),
                                 v2 = VarInt::deserialize(byteSpan2);
                    if (v1.value<Int>() != v || v2.value<Int>() != v || v1 != v2)
                        throw std::runtime_error(QString("Value %1 failed to compare equal (index: %2, hex1: %3, hex2: %4)")
                                                 .arg(v).arg(i).arg(v1.hex(), v2.hex()).toStdString());
                    ++i;
                }
                vals.clear();
                byteBlob.clear();
            }
        }
    } catch (const std::exception &e) {
        const QString msg = QString("Exception for value (%1) hex (%2): %3")
                            .arg(val).arg(hex, QString(e.what()));
        throw std::runtime_error(msg.toStdString());
    }
}

void test()
{
    doTest<std::uint8_t>();
    doTest<std::int8_t>();
    doTest<std::uint16_t>();
    doTest<std::int16_t>();
    doTest<std::uint32_t>();
    doTest<std::int32_t>();
    doTest<std::uint64_t>();
    doTest<std::int64_t>();
}

const auto test_ = App::registerTest("varint", &test);

} // namespace

#endif // ENABLE_TESTS
