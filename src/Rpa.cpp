//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Rpa.h"

#include "BlockProcTypes.h"
#include "BTC.h"
#include "Common.h"
#include "PackedNumView.h"
#include "Span.h"
#include "Util.h"

#include "bitcoin/crypto/endian.h"
#include "bitcoin/transaction.h"

#include <algorithm>
#include <cassert>
#include <cstring> // for std::memcpy
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <stdexcept> // for std::invalid_argument

namespace Rpa {

namespace {
static constexpr bool VERBOSE = false; // set to true to see some perf./compression stats as we process stuff info in Debug() mode.
} // namespace

Hash::Hash(const bitcoin::CTxIn &txin) : QByteArray(BTC::HashInPlace(txin)) {}

Prefix::Prefix(uint16_t num, uint8_t bits_)
    : bits{std::clamp<uint8_t>(bits_, PrefixBitsMin, PrefixBits)},
      n{static_cast<uint16_t>((uint32_t{num} & static_cast<uint32_t>((1u << bits) - 1u)) << (PrefixBits - bits))},
      bytes{numToBytes(n)} {
    if (bits_ < PrefixBitsMin || bits_ > PrefixBits)
        throw std::invalid_argument(QString("Prefix bits may not be <%1 or >%2!").arg(PrefixBitsMin).arg(PrefixBits).toStdString());
}

Prefix::Prefix(const Hash & h) {
    if (h.isEmpty()) throw std::invalid_argument("Provided Rpa::Hash is empty!");
    bits = h.size() == 1u ? 8u : PrefixBits;
    unsigned i;
    const unsigned nb =  std::min(PrefixBytes, size_t(h.size()));
    for (i = 0u; i < nb; ++i)
        bytes[i] = static_cast<uint8_t>(h[i]);
    for ( ; i < PrefixBytes; ++i)
        bytes[i] = 0u; // fill rest with 0's
    std::memcpy(&n, bytes.data(), PrefixBytes);
    n = be16toh(n); // swab to host byte order from big endian
}

auto Prefix::range() const -> Range {
    assert(bits >= PrefixBitsMin && bits <= PrefixBits); // NB: c'tor enforces this anyway
    const uint32_t offset = 1u << (PrefixBits - std::min(bits, uint8_t{PrefixBits}));
    return {n, n + offset};
}

QByteArray Prefix::toHex() const {
    auto ret = Util::ToHexFast(toByteArray(false, true));
    const size_t desiredSize = bits / 4u + (bits % 4u ? 1u : 0u); // truncate the hex at the nybble level
    if (size_t(ret.size()) > desiredSize) ret = ret.left(desiredSize);
    return ret;
}

/* static */
std::optional<Prefix> Prefix::fromHex(const QString &hexIn) {
    const QByteArray hex = hexIn.trimmed().toLatin1();
    std::optional<Rpa::Prefix> ret; // default: !has_value(), for error paths below
    uint32_t val = 0;
    unsigned bits = 0;
    for (const char c : hex) {
        val <<= 4; // shift left by 1 nybble for each character encountered
        bits += 4;
        if (bits > Rpa::PrefixBits) return ret; // fail if it exceeds 4 hex chars (16 bits)
        if (c >= '0' && c <= '9')
            val += c - '0';
        else if (c >= 'A' && c <= 'F')
            val += 10 + (c - 'A');
        else if (c >= 'a' && c <= 'f')
            val += 10 + (c - 'a');
        else
            return ret; // fail on non-hex chars
    }
    if (bits < Rpa::PrefixBitsMin) return ret; // fail if <4 bits (0 characters)
    ret.emplace(uint16_t(val), uint8_t(bits));
    //Debug() << "Prefix: '" << hex << "' -> value: " << ret->value() << ", bytes: '" << ret->toHex() << "', bits: " << ret->getBits();
    return ret;
}

auto PrefixTable::ReadOnly::operator=(const ReadOnly &o) -> ReadOnly & {
    serializedData = o.serializedData;
    // ensure cleared so we deserialize on-demand, and so rows doesn't potentially point to o.serializedData
    for (auto & row : rows) row = PNV{};
    toc = o.toc;
    return *this;
}

namespace {
    template <typename T>
    bool is_obvious_dupe(const std::vector<T> &vec, const T &item) { return !vec.empty() && vec.back() == item; }
    template <typename T, typename U>
    bool is_obvious_dupe(const std::unordered_set<T, U> &, const T &) { return false; }

    template <typename Container>
    void addForPrefixGeneric(Container &cont, const Prefix &p, const typename Container::value_type::value_type & item) {
        auto [b, e] = p.range();
        e = std::min<uint32_t>(e, cont.size());
        for (size_t i = b; i < e; ++i) {
            auto & vecOrSet = cont[i];
            if (!is_obvious_dupe(vecOrSet, item)) // optimization to avoid obvious dupes
                Util::CallPushBackOrInsert{}(vecOrSet, item);
        }
    }

    template <typename Container, typename Func>
    std::vector<typename Container::value_type::value_type>
    searchPrefixGeneric(const Container &cont, const Prefix &prefix, bool sortAndMakeUnique, Func && lazyLoadRow) {
        std::vector<typename Container::value_type::value_type> ret;
        auto [b, e] = prefix.range();
        e = std::min<uint32_t>(e, cont.size());
        for (size_t i = b; i < e; ++i) {
            lazyLoadRow(i);
            const auto & vecOrSet = cont[i];
            ret.insert(ret.end(), vecOrSet.begin(), vecOrSet.end());
        }
        if (sortAndMakeUnique && ret.size() > 1u) {
            Util::sortAndUniqueify(ret, false);
        }
        return ret;
    }

    template <typename Container>
    size_t removeForPrefixGeneric(Container & cont, const Prefix & prefix,
                                  const typename Container::value_type::value_type * individualItem = nullptr) {
        size_t ret = 0u;
        auto [b, e] = prefix.range();
        e = std::min<uint32_t>(e, cont.size());
        for (size_t i = b; i < e; ++i) {
            using VecOrSet = typename Container::value_type;
            VecOrSet & vecOrSet = cont[i];
            if (! individualItem) {
                ret += vecOrSet.size();
                vecOrSet = VecOrSet{}; // we clear the vector (or set) in this way to ensure memory for it is freed immediately, since vecOrSet.clear() won't guarantee this.
            } else {
                using BareType = std::remove_reference_t<std::remove_cv_t<VecOrSet>>;
                if constexpr (std::is_same_v<BareType, std::vector<typename BareType::value_type>>) {
                    // This branch is for vectors and is slow, and only provided here for this code to compile.
                    // It's O(N).  Don't use this branch in production.
                    Warning() << "Slow branch taken in removeForPrefixGeneric()! FIXME!";
                    auto it = vecOrSet.begin();
                    while (it != vecOrSet.end()) {
                        it = std::find(it, vecOrSet.end(), *individualItem);
                        if (it != vecOrSet.end()) {
                            it = vecOrSet.erase(it);
                            ++ret;
                        }
                    }
                } else {
                    // Regular fast set find
                    auto it = vecOrSet.find(*individualItem);
                    if (it != vecOrSet.end()) {
                        it = vecOrSet.erase(it);
                        ++ret;
                    }
                }
            }
        }
        return ret;
    }

    template <typename Container, typename Func>
    size_t elementCountGeneric(const Container &cont, Func && lazyLoadRow) {
        size_t ct = 0u;
        for (size_t i = 0u; i < cont.size(); ++i) {
            lazyLoadRow(i);
            const auto & vecOrSet = cont[i];
            ct += vecOrSet.size();
        }
        return ct;
    }
} // namespace

size_t PrefixTable::elementCount() const {
    return std::visit(
        Overloaded{
            [&](const ReadOnly & ro){
                return elementCountGeneric(ro.rows, [this, &ro](size_t i) { lazyLoadRow(i, &ro); });
            },
            [&](const ReadWrite & rw){
                if (rw.isDefinitelyEmpty) return size_t{0};
                return elementCountGeneric(rw.rows, [](auto){});
            }
        }, var);
}

QByteArray PrefixTable::serializeRow(size_t index, bool deepCopy) const {
    return std::visit(
        Overloaded{
            [&](const ReadOnly & ro){
                lazyLoadRow(index, &ro);
                const auto & pnv = ro.rows.at(index);
                return pnv.rawBytes().toByteArray(deepCopy);
            },
            [&](const ReadWrite & rw){
                const auto & vec = rw.rows.at(index);
                const QByteArray::size_type bytesNeeded = vec.size() * PNV::bytesPerElement;
                QByteArray ret(bytesNeeded, Qt::Uninitialized);
                PNV::Make(MakeUInt8Span(ret), Span{vec});
                return ret;
            }
        }, var);
}

static_assert(PrefixBits == sizeof(uint16_t) * 8u && PrefixTable::numRows() - 1u == std::numeric_limits<uint16_t>::max(),
              "PrefixTable::serialize(), PrefixTable::PrefixTable(QByteArray), and PrefixTable::lazyLoadRow() assumptions.");

namespace {
std::optional<const QByteArray> emptySerialization;
std::shared_mutex emptySerializationMut;
} // namespace

QByteArray PrefixTable::serialize() const {
    // Fast-path check for "empty" serializations. This is so that testnet synching is fast since many blocks have no
    // inputs and thus an "empty" Rpa PrefixTable. In that case we don't bother with the below code and just return the
    // cached serialization for an empty prefix table.
    bool isDefEmpty = false, needToCacheEmptySer = false;
    if (auto *rw = std::get_if<ReadWrite>(&var); rw && (isDefEmpty = rw->isDefinitelyEmpty)) {
        std::shared_lock l(emptySerializationMut);
        if (emptySerialization) {
            return *emptySerialization;
        } else {
            needToCacheEmptySer = true;
        }
    }
    // /Fast-path

    QByteArray dataBuf;
    size_t elementCount = 0;
    constexpr size_t numUint8s = 0x1u << 8u; // 256u
    // minimal size for an empty table: more than ~64KiB
    constexpr size_t minTableSize =
        numRows()                      // 0-byte compactsize * 65536
        + numUint8s * sizeof(uint64_t) // 8-byte uint64_t's * 256
        + 3u                           // 3-byte compactsize for the number of toc entries (0xfd,0x00,0x01)
        + 11u;                         // 2-byte header + 9-byte reserved space for offset of toc
    dataBuf.reserve(minTableSize);
    bitcoin::GenericVectorWriter vw(0, 0, dataBuf, dataBuf.size());
    vw << uint8_t{Rpa::PrefixBits}; // byte 0 always a 16
    vw << uint8_t{Rpa::SerializedTxIdxBits}; // byte 1 always a 32
    vw << uint8_t{} << uint64_t{}; // reserve 9 bytes at byte offset 2
    ReadOnly::Toc toc;

    if (toc.prefix0Offsets.size() < numUint8s)
        throw InternalError(QString("toc should have %1 rows, yet it has %2 rows! FIXME!").arg(numUint8s).arg(toc.prefix0Offsets.size()));
    for (size_t i = 0u; i < numRows(); ++i) {
        if (Prefix::pfxN<1>(i) == 0u) { // new prefix0 when prefix1 == 0x0
            // mark the offset of this new prefix0
            toc.prefix0Offsets[Prefix::pfxN<0>(i)] = dataBuf.size();
        }

        const auto rowData = serializeRow(i, false);
        elementCount += rowData.size() / (SerializedTxIdxBits / 8u);

        // write compactSize + bytes
        bitcoin::WriteCompactSize(vw, rowData.size());
        vw << MakeUInt8Span(rowData);
    }
    // mark the offset of the TOC at position 2
    {
        bitcoin::GenericVectorWriter vw2(0, 0, dataBuf, /* pos = */ 2); // start writing at position 2 again
        bitcoin::WriteCompactSize(vw2, dataBuf.size()); // this compact size will always fit into the initial 9 bytes at position 2
    }
    // write the TOC
    bitcoin::WriteCompactSize(vw, toc.prefix0Offsets.size()); // write that there are 256 entries in the toc
    for (const uint64_t val : toc.prefix0Offsets) {
        vw << val; // note how we forced this to be 64-bit fixed-sized ints for fast initial lookup
    }

    // serialized data is compressed to save space, since for small blocks it is mostly 0's!
    Tic t0;
    const auto compressed = qCompress(dataBuf);
    if constexpr (VERBOSE) {
        if (Debug::isEnabled() && (elementCount >= 100u || t0.msec() >= 5))
            Debug(Log::BrightGreen).operator()
                ("PrefixTable: elementCount: ", elementCount,
                 " uncompressedSize: ", dataBuf.size(), ", compressed size: ", compressed.size(),
                 ", ratio: ", QString::asprintf("%1.3f", double(compressed.size())/double(dataBuf.size())),
                 ", B/entry: ", QString::asprintf("%1.2f", elementCount != 0 ? double(compressed.size())/double(elementCount) : 0.0),
                 ", compression took: ", t0.msecStr(4), " msec");
    }

    // Cache "empty serialization" to static var if flagged that we need to cache it and the returned value *is* the compressed "empty serialization".
    if (isDefEmpty && needToCacheEmptySer) {
        std::unique_lock l(emptySerializationMut);
        if (!emptySerialization) { // check again with lock held, and if still !has_value, cache the empty serialization.
            emptySerialization.emplace(compressed);
        }
    }

    return compressed;
}

PrefixTable::PrefixTable(const QByteArray &compressedSerializedData) : var(std::in_place_type<ReadOnly>) {
    Tic t0;
    auto & ro = std::get<ReadOnly>(var);
    auto & toc = ro.toc;
    Tic t1;
    ro.serializedData = qUncompress(compressedSerializedData);
    const auto & serData = std::as_const(ro.serializedData);
    t1.fin();
    Defer d([&]{
        if constexpr (VERBOSE) {
            if (Debug::isEnabled() && (serData.size() > 100'000 || t1.msec() >= 1))
                Debug(Log::BrightGreen).operator()
                    ("PrefixTable: uncompress of ", serData.size(), " bytes took: ", t1.msecStr(4), " msec, total time: ",
                     t0.msecStr(), " msec");
        }
    });
    if (ro.serializedData.isNull()) throw std::ios_base::failure("PrefixTable: Failed to uncompress serialized data .. is the data corrupt?");
    {
        bitcoin::GenericVectorReader vr(0, 0, serData, 0);
        uint8_t pbits = 0xff, dbits = 0xff;
        vr >> pbits >> dbits;
        if (pbits != Rpa::PrefixBits) throw std::ios_base::failure("PrefixTable: Wrong byte value at position 0");
        if (dbits != Rpa::SerializedTxIdxBits) throw std::ios_base::failure("PrefixTable: Wrong byte value at position 1");
        const uint64_t tocOffset = bitcoin::ReadCompactSize(vr, false);
        if (tocOffset >= size_t(serData.size())) throw std::ios_base::failure("PrefixTable: Bad tocOffset, exceeds buffer size");
        vr.seek(tocOffset);
        const uint64_t numTocEntries = bitcoin::ReadCompactSize(vr, false);
        if (numTocEntries != toc.prefix0Offsets.size()) throw std::ios_base::failure("PrefixTable: Bad toc entry count");
        for (uint64_t & val : toc.prefix0Offsets) {
            vr >> val;
            if (val > std::numeric_limits<size_t>::max() || val >= uint64_t(serData.size()))
                throw std::ios_base::failure("PrefixTable: Bad toc entry, out of range");
        }
    }
    // Note: we don't read the rest of the data, instead lazyLoadRow() must be called before accessing a row to
    // lazy-read the prefix table data on-demand.
}

void PrefixTable::addForPrefix(const Prefix &p, TxIdx n) {
    auto *rw = std::get_if<ReadWrite>(&var);
    if (!rw) throw Exception("addForPrefix called on a read-only PrefixTable");
    addForPrefixGeneric(rw->rows, p, n);
    rw->isDefinitelyEmpty = false;
}

void PrefixTable::lazyLoadRow(const size_t index, const ReadOnly *ro) const {
    if (!ro) {
        ro = std::get_if<ReadOnly>(&var);
        if (!ro) return; // nothing to do for read-write table, return
    }
    if (UNLIKELY(ro->rows.size() != numRows())) throw InternalError("Bad size for ro->rows(). FIXME!");
    PNV & row = ro->rows.at(index); // may throw
    if (! row.isNull()) return; // if not null, then we already been through here once, and the data is populated already (even if with a 0-sized array .isNull() will be false)
    const auto & serData = ro->serializedData;
    const auto prefixBytes = Prefix::numToBytes(index);
    static_assert(prefixBytes.size() == 2u);
    const size_t pfx0 = prefixBytes[0];
    if (UNLIKELY(pfx0 >= ro->toc.prefix0Offsets.size()))
        throw InternalError(QString("PrefixTable serialized TOC has bad size, indexing position %1 but TOC size is %2. FIXME!")
                                .arg(pfx0).arg(ro->toc.prefix0Offsets.size()));
    bitcoin::GenericVectorReader vr(0, 0, serData, ro->toc.prefix0Offsets[pfx0]); // start reading at prefix0 offset
    const size_t pfx1 = prefixBytes[1];
    // read forward until we hit prefix1
    for (size_t i = 0; i < pfx1; ++i) {
        const auto sz = bitcoin::ReadCompactSize(vr, false); // read size of this row
        vr.seek(vr.GetPos() + sz); // skip this row
    }
    const auto sz = bitcoin::ReadCompactSize(vr, false);
    const size_t pos = vr.GetPos();
    if (const auto bufsz = size_t(serData.size()); UNLIKELY(sz > bufsz || pos + sz > bufsz)) {
        throw std::ios_base::failure("Bad size read from serialized data buffer when attempting to deserialize a PrefixTable row");
    }
    auto * const begin = serData.constData() + pos;
    auto * const end = begin + sz;
    row = PNV(Span{begin, end}); // ensure data pointer is valid, even if length happens to be 0
}

const VecTxIdx * PrefixTable::getRowPtr(size_t index) const {
    auto const *rw = std::get_if<ReadWrite>(&var);
    if (!rw) return nullptr;
    if (index >= rw->rows.size()) return nullptr;
    return &rw->rows[index];
}

VecTxIdx PrefixTable::searchPrefix(const Prefix &prefix, bool sortAndMakeUnique) const {
    return std::visit(
        Overloaded{
            [&](const ReadOnly & ro){
                return searchPrefixGeneric(ro.rows, prefix, sortAndMakeUnique, [this, &ro](size_t i) { lazyLoadRow(i, &ro); });
            },
            [&](const ReadWrite & rw){
                return searchPrefixGeneric(rw.rows, prefix, sortAndMakeUnique, [](auto){});
            }
        }, var);
}

size_t PrefixTable::removeForPrefix(const Prefix & prefix) {
    auto *rw = std::get_if<ReadWrite>(&var);
    if (!rw) throw Exception("removeForPrefix called on a read-only PrefixTable");
    return removeForPrefixGeneric(rw->rows, prefix);
}

bool PrefixTable::operator==(const PrefixTable &o) const {
    // do a row-wise data compare
    for (size_t i = 0; i < numRows(); ++i) {
        if (serializeRow(i, false) != o.serializeRow(i, false))
            return false;
    }
    return true;
}

void MempoolPrefixTable::addForPrefix(const Prefix & prefix, const TxHash & txHash) {
    addForPrefixGeneric(prefixTable, prefix, txHash);
}

auto MempoolPrefixTable::searchPrefix(const Prefix &prefix, bool sortAndMakeUnique) const -> VecTxHash {
    return searchPrefixGeneric(prefixTable, prefix, sortAndMakeUnique, [](auto){});
}

size_t MempoolPrefixTable::elementCount() const {
    return elementCountGeneric(prefixTable, [](auto){});
}

size_t MempoolPrefixTable::removeForPrefix(const Prefix & prefix) {
    return removeForPrefixGeneric(prefixTable, prefix);
}

size_t MempoolPrefixTable::removeForPrefixAndHash(const Prefix & prefix, const TxHash &txHash) {
    return removeForPrefixGeneric(prefixTable, prefix, &txHash);
}

} // namespace Rpa

#ifdef ENABLE_TESTS
#include "App.h"

#include <QFile>
#include <QRandomGenerator>

#include <algorithm>
#include <map>
#include <set>
#include <vector>

namespace {

#define CHK(pred) \
do { \
        if (!( pred )) throw Exception("Failed predicate: " #pred ); \
        ++nChecksOk; \
} while(0)

void testPrefixBasic()
{
    Log() << "Testing basic Prefix functionality ...";

    size_t nChecksOk = 0;
    using Rpa::Prefix, Rpa::Hash;

    // Construction from a number
    Prefix p(42, 8);
    CHK(p.toHex() == "2a");
    CHK(p.value() == 42 << 8);
    CHK(p.range() == Prefix::Range(0x2a00, 0x2b00));
    p = Prefix(42, 16);
    CHK(p.toHex() == "002a");
    CHK(p.value() == 42);
    p = Prefix(42, 12);
    CHK(p.toHex() == "02a");
    CHK(p.value() == 42 << 4);
    CHK(p.range() == Prefix::Range(0x02a0, 0x02b0));
    p = Prefix(42, 6);
    CHK(p.toHex() == "a8");
    CHK(p.value() == 42 << 10);
    p = Prefix(42, 5); // truncated since 42 needs 6 bits
    CHK(p.toHex() == "50");
    CHK(p.value() == 10 << 11);

    // Construction from a Hash
    p = Prefix(Hash(Util::ParseHexFast("abcd")));
    CHK(p.toHex() == "abcd");
    CHK(p.getBits() == 16);
    CHK(p.value() == 0xabcd);
    p = Prefix(Hash(Util::ParseHexFast("ef")));
    CHK(p.toHex() == "ef");
    CHK(p.getBits() == 8);
    CHK(p.value() == 0xef << 8);

    // Equality takes into account bits
    CHK(Prefix(0xff, 8) == Prefix(0xff, 8));
    CHK(Prefix(0xff, 8).value() == Prefix(0xff, 8).value());
    CHK(Prefix(0xff, 8).value() == Prefix(0xff00, 16).value()); // even though they have the same value, but different bits
    CHK(Prefix(0xff, 8) != Prefix(0xff00, 16)); // ... they compare !=
    CHK(Prefix(0xff, 8).value() == Prefix(0xff0, 12).value()); // same value
    CHK(Prefix(0xff, 8) != Prefix(0xff0, 12)); // different bits makes them !=
    CHK(Prefix(0xff0, 12).value() == Prefix(0xff00, 16).value());  // same value
    CHK(Prefix(0xff0, 12) != Prefix(0xff00, 16)); // different bits makes them !=
    CHK(Prefix(0x1, 4).value() == Prefix(0x10, 8).value()); // same value
    CHK(Prefix(0x1, 4) != Prefix(0x10, 8)); // different bits makes them !=
    CHK(Prefix(0b1, 5).value() == Prefix(0b00001000, 8).value()); // same value
    CHK(Prefix(0b1, 5) != Prefix(0b00001000, 8)); // different bits makes them !=

    // fromHex and toHex
    p = Prefix::fromHex("abc").value();
    CHK(p.toHex() == "abc");
    CHK(p.getBits() == 12);
    CHK(p.value() == 0xabc << 4);

    // Range
    Prefix::Range r;
    r = Prefix(0xabcd, 16).range();
    CHK(r.size() == 1);
    CHK(r.begin == 0xabcd);
    CHK(r.end == 0xabce);
    r = Prefix(0x42, 8).range();
    CHK(r.size() == 256);
    CHK(r.begin == 0x4200);
    CHK(r.end == 0x4300);
    r = Prefix(0x123, 12).range();
    CHK(r.size() == 16);
    CHK(r.begin == 0x1230);
    CHK(r.end == 0x1240);

    Log() << nChecksOk << " basic checks ok";
}

void test()
{
    testPrefixBasic();

    QRandomGenerator *rgen = QRandomGenerator::global();
    if (rgen == nullptr) throw Exception("Failed to obtain random number generator");
    auto genRandomRpaHash = [rgen] {
        using Arr = std::array<quint32, HashLen / sizeof(quint32)>;
        static_assert(Arr{}.size() * sizeof(quint32) == HashLen);
        // Lazy but who really would be so pedantic to care. Generate 8 32-bit ints = 256-bits (32-byte) random
        // hash.
        Arr randNums;
        rgen->generate(randNums.begin(), randNums.end());
        return Rpa::Hash(reinterpret_cast<const char *>(std::as_const(randNums).data()), HashLen);
    };

    using TxIdx = Rpa::TxIdx;
    Rpa::PrefixTable prefixTable;
    using VerifyTable = std::map<uint16_t, std::vector<TxIdx>>;
    VerifyTable verifyTable;

    Log() << "Testing PrefixTable add ...";
    if (! prefixTable.empty() || prefixTable.elementCount() != 0) throw Exception(".empty() and/or .elementCount() are wrong");
    size_t added = 0;
    for (size_t i = 0u; i < 1'000'000u; ++i) {
        const auto randHash = genRandomRpaHash();
        const TxIdx n = rgen->generate64() & ((uint64_t{1u} << Rpa::SerializedTxIdxBits) - uint64_t{1u});
        const Rpa::Prefix prefix(randHash);
        prefixTable.addForPrefix(prefix, n); // add to prefix table
        auto & v = verifyTable[prefix.value()];
        if (v.empty() || v.back() != n) {
            v.push_back(n);
            ++added;
        }
    }
    if (prefixTable.elementCount() != added) throw Exception("PrefixTable's elementCount() is wrong");

    struct CheckFail : Exception { using Exception::Exception; };
    auto checkTableConsistency = [](const Rpa::PrefixTable & pt, const VerifyTable & vt) {
        if (pt.numRows() != vt.size()) {
            // If the size is off, it could be because we have empty rows, so account for those
            long diff = long(pt.numRows()) - long(vt.size());
            for (size_t i = 0; i < pt.numRows(); ++i) {
                if (vt.find(i) != vt.end()) continue; // skip
                if (auto *r = pt.getRowPtr(i)) {
                    if (r->empty()) --diff;
                } else {
                    if (pt.searchPrefix(Rpa::Prefix(i)).empty()) --diff;
                }
            }
            if (diff)
                throw CheckFail(QString("Rpa::PrefixTable's size (%1) does not equal the check-table's size (%2)")
                                    .arg(pt.numRows()).arg(vt.size()));
        }

        // check everything in the table is in the prefix map
        for (const auto & [pfxnum, vec] : vt) {
            const Rpa::Prefix pfx(pfxnum);
            if (pt.isReadWrite()) {
                const auto * nums = pt.getRowPtr(pfx.value());
                // the vector of txnums now should equal prefixTable
                if (!nums || *nums != vec)
                    throw CheckFail("Rpa::PrefixTable has consistency errors (1)");
            } else {
                // read-only table, do search
                auto vec2 = pt.searchPrefix(Rpa::Prefix{uint16_t{pfxnum}, 16}, false);
                if (vec != vec2)
                    throw CheckFail("Rpa::PrefixTable has consistency errors (2)");
            }
        }
    };
    Log() << "Testing PrefixTable consistency ...";
    checkTableConsistency(prefixTable, verifyTable);

    auto checkTableLookup = [](const Rpa::Prefix &p, const Rpa::PrefixTable & pt, const VerifyTable & vt, bool sort) {
        auto vpt = pt.searchPrefix(p, sort);
        const auto [b, e] = p.range();
        Debug() << "checkTableLookup(sort=" << int(sort) << ") for prefix: " << p.value()
                << ", '" << p.toHex() << "', bits: " << p.getBits()
                << ", range: [" << b << ", " << e << "), vecSize: " << vpt.size();
        VerifyTable::mapped_type vvt;
        for (size_t i = b; i < e; ++i) {
            try {
                const auto & v = vt.at(i);
                vvt.insert(vvt.end(), v.begin(), v.end());
            } catch (const std::out_of_range &) {} // allow for missing keys, since that can happen randomly
        }
        if (sort) Util::sortAndUniqueify(vvt);
        if (vpt != vvt) throw Exception("Rpa::PrefixTable search yielded incorrect results");
    };
    Log() << "Testing PrefixTable search ...";
    for (const auto bits : {4u, 5u, 6u, 7u, 8u, 9u, 10u, 12u, /*16u*/}) {
        for (size_t i = 0; i < (0x1u << bits); ++i) {
            const Rpa::Prefix p(i, /* bits = */bits);
            if (0 == bits % 4) {
                // on even nybble boundaries, test toHex()
                if (auto opt = Rpa::Prefix::fromHex(p.toHex()); !opt || *opt != p)
                    throw Exception(QString("toHex/fromHex cycle yielded different results for prefix: %1 '%2' (bits = %3)")
                                        .arg(p.value()).arg(QString(p.toHex())).arg(p.getBits()));
                if (auto a = p.toHex(), b = QString::asprintf("%0*x", bits / 4, unsigned(i)).toUtf8(); a != b)
                    throw Exception(QString("Unexpected hex encoding for prefix %3 (%4): '%1' != '%2'").arg(a, b).arg(p.value()).arg(i));
            }

            checkTableLookup(p, prefixTable, verifyTable, false);
            checkTableLookup(p, prefixTable, verifyTable, true);
        }
    }

    Log() << "Testing PrefixTable row-level serialize / unserialize ...";
    for (size_t i = 0; i < prefixTable.numRows(); ++i) {
        const QByteArray serialized = prefixTable.serializeRow(i);
        PackedNumView<Rpa::SerializedTxIdxBits> pnv(serialized);
        Rpa::VecTxIdx vec;
        vec.insert(vec.end(), pnv.begin(), pnv.end());
        if (auto *ptr = prefixTable.getRowPtr(i); !ptr || vec != *ptr)
            throw Exception("Rpa::PrefixTable ser/deser cycle yielded inconsistent results");
    }

    Log() << "Testing PrefixTable table-level serialize / unserialize ...";
    {
        auto data = prefixTable.serialize();
        Rpa::PrefixTable p2(data);
        if (!p2.isReadOnly() || p2.isReadWrite()) throw Exception("Expected read-only table");
        if (p2.elementCount() != prefixTable.elementCount() || p2 != prefixTable) throw Exception("Unser test 1 fail");
        for (size_t i = 0; i < p2.numRows(); ++i) {
            const auto v1 = prefixTable.searchPrefix(Rpa::Prefix(i));
            const auto v2 = p2.searchPrefix(Rpa::Prefix(i));
            if (v1 != v2) throw Exception("Unser test 2 fail");
        }
        checkTableConsistency(p2, verifyTable); // run through entire table for belt-and-suspenders check
    }

    Log() << "Testing PrefixTable equality ...";
    {
        auto pft2 = prefixTable;
        if (prefixTable != pft2)
            throw Exception("Rpa::PrefixTable not equal");
        if (auto *p = const_cast</* HACK */ Rpa::VecTxIdx *>(pft2.getRowPtr(pft2.numRows() - 1)); p && ! p->empty()) {
            // invert the last element
            p->back() = ~p->back();
            // equality should fail
            if (prefixTable == pft2) throw Exception("Failed to break equality");
            p->back() = ~p->back();
            // restored the last element, equality preserved
            if (prefixTable != pft2) throw Exception("Failed to restore equality");
        } else Warning() << "EMPTY LAST ENTRY -- FIXME!";
        pft2.clear();
        if (!pft2.empty()) throw Exception(".clear() failed");
        if (prefixTable == pft2) throw Exception("operator== failed");
        // test ser/deser of empty table is empty
        const auto emptySer = pft2.serialize();
        const Rpa::PrefixTable pftEmpty(emptySer);
        if (!pftEmpty.empty() || pft2 != pftEmpty) throw Exception("Ser/deser cycle of an empty table failed");
    }

    Log() << "Testing PrefixTable remove ...";
    {
        auto prefixTable2 = prefixTable;
        auto verifyTable2 = verifyTable;
        size_t rmct = 0;
        for (size_t i = 0; i < 256u; ++i) {
            const Rpa::Prefix p(i << 8u, /* bits = */8u);
            rmct += prefixTable.removeForPrefix(p);
            const auto [b, e] = p.range();
            for (size_t j = b; j < e; ++j) verifyTable[j].clear();
            if (i > 0u && i % 10u == 0u) {
                checkTableConsistency(prefixTable, verifyTable);
                if (prefixTable == prefixTable2) throw Exception("Equality check failed");
                if (prefixTable.elementCount() + rmct != prefixTable2.elementCount()) throw Exception("Counts check failed");
            }
        }
        checkTableConsistency(prefixTable, verifyTable);
        checkTableConsistency(prefixTable2, verifyTable2);
        auto checkNotEqualsTable = [&](const auto &arg1, const auto &arg2) {
            try {
                checkTableConsistency(arg1, arg2);
            } catch (const CheckFail &) {
                return;
            }
            throw CheckFail("Inequality check failed!");
        };
        checkNotEqualsTable(prefixTable2, verifyTable);
        checkNotEqualsTable(prefixTable, verifyTable2);
    }

    Log() << "Testing Rpa::Hash (from CTxIn) ...";
    // perform serialization of a bitcoin input; this is used to verify the faster Rpa::Hash(const CTxIn &)
    auto serializeInputSlow = [](const bitcoin::CTxIn& input) -> Rpa::Hash {
        const auto serInput = BTC::Serialize(input);
        Rpa::Hash rhash{BTC::Hash(serInput, false)}; // double sha2
        return rhash;
    };
    std::vector<QByteArray> txStrs = {{
        "0100000001751ac11802cc3e4efc8aaaee87ca818482be9140dd6623f69db2c3af5c0b0ede01000000644161e02824b2ad3e24b19"
        "67ecd2e1bbcb53ca2b7c990802865b7f0f55e861849f7821daff5e78964346b1f7d16e5ce522d3354ca3cc1f6f4cba4ca0e57725a"
        "f59e412102c986f0b3d6f4f8c765469fe0118cf973d676862f358e62a14104fae7d43f3032feffffff02e8030000000000001976a"
        "914ed707a5dbba9f4c117086c547fdc4e1e7a5ba40088accc550100000000001976a914e32151fdef9bc46cbb11514a84f54d8f51"
        "a905e588ac747a0a00",
        "010000000a80042cde613152c5e77bada9a32567816286ef4cc5db92f39c8c385fa8d8c51300000000844110a19868da36f8cbf94"
        "23e7b8943cb76a18e9098a61973747198a358a1e3bf015f50e4609b240fe741da08da2317bfd6a8357e8126be278e509df7ed2f36"
        "001e414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa"
        "7f456634e1bdb11485dbbc9db20cb669dfeffffff6aa672caf2cc24751835cef735020c5e09e593a6e537a4819a7ef316fd99a714"
        "0100000084419d3102d640a5061a8e73dfa7ab2f0d72057d34cad4eb77720fc5a5d3990a79fc831fcf971bebce36b7be12ae7a494"
        "edc2d2e9c694840c641e47c64f50ab88c08414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa3886429"
        "72aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffffdc55076ed9e6f5bad08fa05be0bcded16"
        "9bb8a91dd3c2df0a3a5d741e4d87f280000000084413a0343b34d81b9403b9830f485376a799e10410bcdaa0c0351bb29e8b473dd"
        "40ce20749d049b8f655a8929a883d24e14d9f4f49084c271de53ec09b8e6469607414104e8806002111e3dfb6944e63a424618324"
        "37f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff9f"
        "a13f0698fc362d188fcae4e15d9b3967ef523c0b2d010f76a366b2e5a5773100000000844195dd906186f703505c095e89b06a97e"
        "3c5ec770ac89c721ad15432f0b1a6df5cbd872e23ca8016d7b2411ba7ffaa385f2b70c1d3c16525d342b0db11a35b83b0414104e8"
        "806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bd"
        "b11485dbbc9db20cb669dfeffffff6a49ee1b6fb4a528fb1ceeebc9930662dbe34dce6faa6256300ac263d3dbfd6b070000008441"
        "c421a57150ba601c7238cc9561f1178569f2c4bf471ad8d4b40683fcdebb06fe5e0fd8ae23002fdef975f950aa7df4a0c9edf1b2f"
        "447c99640fba268e8f7ac1f414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcd"
        "c2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff467d33729a55b1afd8556b201667c324b29fb9bcebbc3"
        "11912aecff58b4f9884000000008441d055f348d001335405280134e5ef90b90851ef1dd8a03f4bc4173b0dd1c12ed71a7020e1a1"
        "7e9129640cf2292ad12ce7926778676450bb1f8aebbea153459040414104e8806002111e3dfb6944e63a42461832437f2bbd616fa"
        "cc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff58654b4278c983"
        "119c66f0333dd3528f125c8269de977353a28fb1f46fdfca8e000000008441b7406309983640d6e04fc54709abb5e67f6ee272be2"
        "3242b92a737953d277dff73e2ea9287016f03cc62c099cdf590a6f3a54b91e4708210a7ee653d9e387352414104e8806002111e3d"
        "fb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9d"
        "b20cb669dfeffffff633293fdcdd1a735f31f243d64facd9279d6fa1ae5297db8e9b96010378ec0a00000000084411b7c298f0a4c"
        "238bb57e2d421599fc7f1b150a4d37bc8d1e89aebe840d5224d2167dcb7e34084c4181fae6f2d4ac358302a66d6ecb354335b4d2a"
        "1568ea3c0f8414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e"
        "7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff2ede1f74c36962315a67593f615028faa57335300518029e52593767e"
        "30bcceb0000000084414f93062b38e50e636907d99463aa7439113ad618c2d2b9051ec7a108057169141c0f5532b1211f88bbd8a8"
        "734d667ef863910e9e3bf2f8a2114aa799496f6e22414104e8806002111e3dfb6944e63a42461832437f2bbd616facc26910becfa"
        "388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfeffffff3bfa6654a76ac12cec72dbc742"
        "be17f4c965b62fea2caf6b7241e14b163290f7010000008441d25525cf580724567390e0ab039011015be2ddab7296631fab5f20f"
        "e03d3eee63888527d9729ebd7060fdbb1b94e85abdcbfcc8518539237d62371d69ae11893414104e8806002111e3dfb6944e63a42"
        "461832437f2bbd616facc26910becfa388642972aaf555ffcdc2cdc07a248e7881efa7f456634e1bdb11485dbbc9db20cb669dfef"
        "fffff01174d7037000000001976a9147ee7b62fa98a985c5553ff66120a91b8189f658188ac931a0900",
        // The below txn is from BTC and happens to have 2 inputs that hash to the same 2-byte Prefix!
        "0100000004e0c845704a4201358eb2f6a2173a321c0e9722f252fdd6244d993fffc86f534a010000006b483045022100a3989d8b0"
        "05b5bb55663dfca323f5bc27f1215831da1576cdd75d74c0034acdb022004ee8cf26bdf72c3dcfca6ef911ad74d3e50c423e61f64"
        "254dc33b2671dc5e8a0121021e8499afed086ffeae1679ce16c57b420b8adebce9130e0751523e71fbcf95edffffffff20332b007"
        "22ffdca13236adf614858780eb8e4845a7a674fe29c385f70d98d70010000006b483045022100faa12bb2f3800b1c40e286bcd59a"
        "49d47772ce90d95ec211f7a5df00970ce8c102206935fb331b54cb3d394d9c0af5ce6bae31d2ab547446f2e20fb305228b1bcc8d0"
        "1210208115f44ee63999b51908b5778eac110f5d7d8b46449ec2d2ad647b1b6eeaf20ffffffffe7c85556b64babcf8b5d9f1c8e7e"
        "fc07c9d9785787866e0d6eeb0b9b9fe3daa2010000006b483045022100c0c8879496f09449171023e1ffcdc0cf5b6cc7710bd86f0"
        "1b2e7a881e15fcce2022001b1bb33f64f0877907c620e1db2ca6faa4620fcc9dddcf6b64a7353bc831531012102761a0c6e5dff0a"
        "6249e5e2db56716a5697a21e067f3b4c82a07597d9fd299628fffffffff26cf9fa7c57086264fb567ff0eeeb711d808dff55c4c85"
        "eda6814c939288ff30a0000006b483045022100c1aed8959296a1c176bbe012deba674fbcc05852083a4fbb8d709db035d4a4eb02"
        "204d9072cc6b18f1beb1caddf06d9d018e425992bca9a413695fbe43a3dceacfad01210317b950d383d8888ebbd027bb5e0350665"
        "7768d2b5308cc04c6699e083ab10fb6ffffffff02a8530300000000001976a9141a21eced4e43d1252b5fcec8562e793cfe1daf1f"
        "88ac45413000000000001976a9141ecd8b1242f4a562ad925d8db94243bf9fff68e188ac00000000",
    }};
    const std::unordered_set<size_t> allowSegWitForTheseIndices(std::initializer_list<size_t>{2u});
    const auto dupeTxIdx= 2u; // this txn has inputs that happen to be dupes
    Rpa::MempoolPrefixTable mpt;
    if (!mpt.empty() || mpt.numRows() != Rpa::PrefixTableSize) throw Exception("MempoolPrefixTable default constructed object not as expected");
    using TxHash2Prefix = std::map<TxHash, std::unordered_set<Rpa::Prefix, Rpa::Prefix::Hasher>>;
    using Prefix2TxHash = std::unordered_map<Rpa::Prefix, std::set<TxHash>, Rpa::Prefix::Hasher>;
    TxHash2Prefix txhash2prefix;
    Prefix2TxHash prefix2txhash;
    for (const auto prefixBits : {16, 8}) {
        for (size_t i = 0; i < txStrs.size(); ++i) {
            const auto & txStr = txStrs[i];
            bitcoin::CMutableTransaction tx;
            BTC::Deserialize(tx, Util::ParseHexFast(txStr), 0, allowSegWitForTheseIndices.count(i));

            const TxHash txHash = BTC::Hash2ByteArrayRev(tx.GetHash());
            const auto mptSizeBefore = mpt.elementCount();
            for (size_t n = 0, sz = tx.vin.size(); n < sz; ++n) {
                const auto & input = tx.vin[n];
                const Rpa::Hash rHash{input};
                const Rpa::Hash rHashSlow = serializeInputSlow(input);
                if (rHash != rHashSlow) throw Exception("Fast serializeInput does not match the slow version!");
                const auto prefix = Rpa::Prefix(Rpa::Hash{rHash.left(prefixBits / 8u)});
                const auto prefix2 = Rpa::Prefix::fromHex(rHash.toHex().left(prefixBits / 4u)).value();
                if (prefix != prefix2 || prefix.toHex() != prefix2.toHex()) throw Exception(QString("Prefix equality error: %1 != %2").arg(prefix.toHex(), prefix2.toHex()));
                QByteArray prefixHex = prefix.toHex();
                const auto rHashHex = Util::ToHexFast(rHash);
                Debug() << "   Txid: " << tx.GetId().ToString() << ":" << n
                        << " Rpa::Hash: " << Util::ToHexFast(rHash)
                        << " Prefix: " << prefixHex
                        << " Prefix bits: " << prefix.getBits();
                if (! rHashHex.startsWith(prefixHex))
                    throw Exception("Prefix is not as expected.");
                if (prefixBits == 16) {
                    // add to mempool table as we would in production with the full 16-bit prefix
                    mpt.addForPrefix(prefix, txHash);
                    txhash2prefix[txHash].insert(prefix);
                    prefix2txhash[prefix].insert(txHash);
                }
            }
            if (prefixBits == 16) {
                if (mpt.elementCount() != mptSizeBefore + tx.vin.size() - unsigned(i == dupeTxIdx))
                    throw Exception("MempoolPrefixTable check 1 failed");
            }
        }
    }

    Log() << "Testing MempoolPrefixTable ...";
    auto checkMPT = [](const Rpa::MempoolPrefixTable &mpt, const Prefix2TxHash & prefix2txhash, const TxHash2Prefix & txhash2prefix) {
        // check MempoolPrefixTable sanity: by prefix
        size_t ct = 0;
        for (const auto & [prefix, hashSet] : prefix2txhash) {
            ct += hashSet.size();
            if (Util::toVec(hashSet) != mpt.searchPrefix(prefix, true))
                throw Exception("MempoolPrefixTable check 2 failed");
        }
        if (mpt.elementCount() != ct)
            throw Exception("MempoolPrefixTable check 3 failed");
        // check MempoolPrefixTable sanity: by txHash
        for (const auto & [txHash, prefixSet] : txhash2prefix) {
            for (const auto & prefix : prefixSet) {
                const auto vec = mpt.searchPrefix(prefix, true);
                if (std::find(vec.begin(), vec.end(), txHash) == vec.end())
                    throw Exception("MempoolPrefixTable check 4 failed");
            }
        }
    };
    checkMPT(mpt, prefix2txhash, txhash2prefix);
    // test: remove by individual txHash <-> prefix association
    const auto mpt_Saved = mpt;
    const auto prefix2txhash_Saved = prefix2txhash;
    const auto txhash2prefix_Saved = txhash2prefix;
    for (auto it = txhash2prefix.begin(); it != txhash2prefix.end(); /**/) {
        const auto txHash = it->first;
        auto & prefixSet = it->second;
        for (auto it2 = prefixSet.begin(); it2 != prefixSet.end(); /**/) {
            const auto prefix = *it2;
            const auto sizeBefore = mpt.elementCount();
            const auto rmct = mpt.removeForPrefixAndHash(prefix, txHash);
            if (rmct != 1 || sizeBefore != mpt.elementCount() + 1u) throw Exception("MempoolPrefixTable check 5 failed");
            it2 = prefixSet.erase(it2);
            auto & txHashSet = prefix2txhash[prefix];
            txHashSet.erase(txHash);
            if (txHashSet.empty()) prefix2txhash.erase(prefix);
            if (!prefixSet.empty())
                checkMPT(mpt, prefix2txhash, txhash2prefix); // check table again
        }
        if (prefixSet.empty()) {
            it = txhash2prefix.erase(it);
        } else ++it;
        checkMPT(mpt, prefix2txhash, txhash2prefix); // check table again
    }
    checkMPT(mpt, prefix2txhash, txhash2prefix); // check table again
    if (!mpt.empty()) throw Exception(QString("MempoolPrefixTable check 6 failed, elementCount: %1").arg(mpt.elementCount()));
    // test: remove, by prefix
    mpt = mpt_Saved;
    prefix2txhash = prefix2txhash_Saved;
    txhash2prefix = txhash2prefix_Saved;
    for (auto it = prefix2txhash.begin(); it != prefix2txhash.end(); /**/) {
        const auto prefix = it->first;
        const auto txHashSet = it->second;
        const auto sizeBefore = mpt.elementCount();
        const size_t rmct = mpt.removeForPrefix(prefix);
        if (rmct != txHashSet.size() || sizeBefore != mpt.elementCount() + rmct) throw Exception("MempoolPrefixTable check 7 failed");
        for (const auto & txHash : txHashSet) {
            txhash2prefix[txHash].erase(prefix);
            if (txhash2prefix[txHash].empty()) txhash2prefix.erase(txHash);
        }
        it = prefix2txhash.erase(it);
        checkMPT(mpt, prefix2txhash, txhash2prefix);
    }
    if (!mpt.empty()) throw Exception(QString("MempoolPrefixTable check 7 failed, elementCount: %1").arg(mpt.elementCount()));
    // Test: clear() and operator=, operator==, operator!=
    mpt.clear();
    if (mpt == mpt_Saved || !mpt.empty()) throw Exception("MempoolPrefixTable check 8 failed");
    mpt = mpt_Saved;
    if (mpt != mpt_Saved || mpt.empty() || mpt.elementCount() != mpt_Saved.elementCount()) throw Exception("MempoolPrefixTable check 9 failed");
    mpt.clear();
    if (mpt == mpt_Saved || !mpt.empty()) throw Exception("MempoolPrefixTable check 10 failed");

    [&checkTableConsistency]{
        Log() << "Testing on block 833705 ...";
        const QString path = ":testdata/bch_block_833705.bin";
        QFile f(path);
        if (!f.open(QFile::ReadOnly)) throw Exception("Unable to open resource: " + path);
        const QByteArray blockData = f.readAll();
        const auto block = BTC::Deserialize<bitcoin::CBlock>(blockData, 0, false, false, true, true);
        Rpa::PrefixTable pft;
        VerifyTable vt;

        size_t elementCount = 0;
        for (size_t txIdx = 1; txIdx < block.vtx.size(); ++txIdx) {
            const auto &tx = block.vtx[txIdx];
            unsigned inNum = 0;
            for (const auto & in : tx->vin) {
                if (inNum >= Rpa::InputIndexLimit) break; // spec limit, up to 30 inputs per tx get indexed
                const auto hash = Rpa::Hash(in);
                const auto prefix = Rpa::Prefix(hash);
                pft.addForPrefix(prefix, txIdx);
                bool ok;
                const auto verifyPrefix = hash.left(2).toHex().toUInt(&ok, 16 /* base 16 */);
                if (!ok) throw Exception(QString("Unexpected -- unable to parse %1 as hex").arg(QString(hash.left(2).toHex())));
                if (auto & r = vt[verifyPrefix]; r.empty() || r.back() != txIdx) {
                    r.push_back(txIdx);
                    ++elementCount;
                }
                ++inNum;
            }
        }
        checkTableConsistency(pft, vt); // ensure a table built from a real block checks out

        const Rpa::VecTxIdx expected_9430(1, 297); // single value
        Rpa::Prefix pfx(uint16_t(9430));
        if (Rpa::VecTxIdx v; expected_9430 != (v = pft.searchPrefix(pfx))) {
            Debug l;
            l << "For prefix " << pfx.toHex() << ", got: ";
            for (auto i : v) l << i << ", ";
            throw Exception("Table `pft` not as expected (check 1)");
        }
        const Rpa::VecTxIdx expected_0x04{{
            24, 39, 47, 49, 52, 58, 60, 66, 70, 85, 87, 88, 91, 94, 95, 97, 105, 107, 118, 121, 126, 139, 148, 152, 154,
            161, 172, 175, 183, 205, 235, 254, 258, 267, 269, 273, 274, 276, 283, 288, 293, 297, 305, 306, 310, 319, 323,
            333, 334, 337, 351, 355,
        }};
        // Do prefix search for a short, 4-bit prefix
        pfx = Rpa::Prefix(0x4, 4);
        if (Rpa::VecTxIdx v; expected_0x04 != (v = pft.searchPrefix(pfx, true))) {
            Debug l;
            l << "For prefix " << pfx.toHex() << ", got: ";
            for (auto i : v) l << i << ", ";
            throw Exception("Table `pft` not as expected (check 2)");
        }
        Tic t0;
        const Rpa::PrefixTable pft2(pft.serialize());
        Log() << "Ser/deser cycle for PrefixTable with " << elementCount << " items took " << t0.msecStr() << " msec";
        if (!pft2.isReadOnly()) throw Exception("Deserialized table is not ReadOnly as expected");
        if (pft2 != pft) throw Exception("Ser/deser cycle yielded a different table that is not equal to the original!");
        if (expected_9430 != pft2.searchPrefix(Rpa::Prefix(uint16_t(9430)))) throw Exception("Table `pft2` not as expected (check 1)");
        if (expected_0x04 != pft2.searchPrefix(Rpa::Prefix(0x04, 4), true)) throw Exception("Table `pft2` not as expected (check 2)");
    }();

    Log(Log::Color::BrightWhite) << "All Rpa unit tests passed!";
}

static const auto test_ = App::registerTest("rpa", &test);

}
#endif
