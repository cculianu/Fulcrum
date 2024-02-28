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
#pragma once

#include "ByteView.h"
#include "Span.h"

#include "bitcoin/crypto/endian.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memset, std::memcpy
#include <functional> // for std::less, std::greater, etc
#include <iterator>
#include <stdexcept>
#include <type_traits>

/// A read-only view into an array of bytes that are interpreted as unsigned ints. The backing ints are "packed" in
/// that they may be of a fixed length that is not of the usual int size (such as 3, 5, or 6 bytes each). Each int
/// must be of the same size though. Methods `find` and `lower_bound` require that the backing array be sorted for them
/// to work properly.
///
/// The backing store ints may also be of any endianness (template arg: `LittleEndian` controls this).
template<unsigned BITS, bool LittleEndian = true>
class PackedNumView {
    static_assert(BITS >= 24u && BITS < 64u && BITS % 8u == 0u,
                  "BITS must be in the range [24, 64), must be a multiple of 8.");

    ByteView buf;

public:
    static constexpr size_t bytesPerElement = BITS / 8u;

    using UInt = std::conditional_t<BITS <= 32u, uint32_t, /* fall-back to 64-bit of anything >32 */ uint64_t>;

    static constexpr UInt min() { return 0u; }
    static constexpr UInt max() { return static_cast<UInt>((uint64_t{1u} << BITS) - 1u); }

    /// Default c'tor constructs a PackedNumView for with .isNull() == true
    PackedNumView() = default;

    PackedNumView(ByteView packedBuffer, bool throwIfJunkAtEnd = true) : buf(packedBuffer) {
        if (throwIfJunkAtEnd && buf.size() % bytesPerElement != 0u) {
            throw std::invalid_argument("packedBuffer must have a length that is a multiple of bytesPerElement!");
        }
    }

    size_t size() const { return buf.size() / bytesPerElement; }

    bool isNull() const { return buf.data() == nullptr; }

    UInt at(size_t i) const {
        if (i >= size()) throw std::out_of_range("Index exceeds size of array");
        return this->operator[](i);
    }

    size_t byteOffsetOf(size_t index) const { return bytesPerElement * index; }
    ByteView viewForElement(size_t index) const { return buf.substr(byteOffsetOf(index), bytesPerElement); }

    UInt operator[](size_t i) const {
        const ByteView ebytes = viewForElement(i);
        UInt ret{}; // 0-init
        static_assert(sizeof(UInt) >= bytesPerElement);
        std::byte *cpy_pos = reinterpret_cast<std::byte *>(&ret);
        if constexpr (!LittleEndian && bytesPerElement < sizeof(UInt)) {
            // If the backing store is big endian, and if the packing is such that we sacrificed high order byte(s),
            // then we must offset where we write into `ret` such that we write into the first high-order byte that we
            // have data for.
            cpy_pos += sizeof(UInt) - bytesPerElement;
        }
        std::memcpy(cpy_pos, ebytes.data(), bytesPerElement);
        // At this point `ret` is in backing store byte order; convert to machine byte order.
        // The below optimizes to a no-op if backing store and machine byte order match.
        static_assert(std::is_same_v<UInt, uint32_t> || std::is_same_v<UInt, uint64_t>,
                      "The code below assumes UInt is either uint32_t or uint64_t.");
        if constexpr (LittleEndian) {
            if constexpr (std::is_same_v<UInt, uint64_t>)
                ret = bitcoin::le64toh(ret);
            else
                ret = bitcoin::le32toh(ret);
        } else {
            if constexpr (std::is_same_v<UInt, uint64_t>)
                ret = bitcoin::be64toh(ret);
            else
                ret = bitcoin::be32toh(ret);
        }
        return ret; // value is now in machine byte order
    }

    const ByteView & rawBytes() const { return buf; }

    /// Fills outBuffer with the ints from srcInts, and returns the read-only view into the resulting buffer.
    /// Note that outBuffer must be a multiple of `bytesPerElement`, else an exception is thrown.
    template <typename NumT, std::enable_if_t<std::is_integral_v<std::remove_cv_t<NumT>> && std::is_unsigned_v<std::remove_cv_t<NumT>>, void *> = nullptr>
    static PackedNumView Make(Span<uint8_t> outBuffer, const Span<NumT> & srcInts, bool allowLongerOutputBuffer = false) {
        if (outBuffer.size() % bytesPerElement != 0u)
            throw std::invalid_argument("outBuffer's size must be a multiple of bytesPerElement!");

        const size_t nOutputElems = outBuffer.size() / bytesPerElement;
        if (!allowLongerOutputBuffer && nOutputElems > srcInts.size())
            throw std::invalid_argument("outputBuffer's size is larger than what srcInts requires");
        const size_t nIters = std::min(nOutputElems, srcInts.size());

        size_t i;
        for (i = 0u; i < nIters; ++i) {
            Span<uint8_t> sp = outBuffer.subspan(i * bytesPerElement, bytesPerElement);
            UInt packed = static_cast<UInt>(srcInts[i]); // read source uint, maybe truncating to our supported range.
            const std::byte *src_byte = reinterpret_cast<std::byte *>(&packed);
            // byteswap based on endianness, if necessary
            static_assert(std::is_same_v<UInt, uint32_t> || std::is_same_v<UInt, uint64_t>,
                          "The code below assumes UInt is either uint32_t or uint64_t.");
            if constexpr (LittleEndian) { // destination is little endian
                if constexpr (std::is_same_v<UInt, uint64_t>)
                    packed = bitcoin::htole64(packed);
                else
                    packed = bitcoin::htole32(packed);
            } else { // destination is big endian
                if constexpr (std::is_same_v<UInt, uint64_t>)
                    packed = bitcoin::htobe64(packed);
                else
                    packed = bitcoin::htobe32(packed);
                // if destination data is big endian, we maybe need to offset where we read from to omit truncated
                // high-order bytes
                if constexpr (bytesPerElement < sizeof(UInt))
                    src_byte += sizeof(UInt) - bytesPerElement;
            }
            // At this point, `packed` is in destination byte order, not host byte order, and src_byte points
            // to either byte 0 of `packed` if destination is LittlEndian, or it points to some possibly-offset-from-0
            // byte of `packed` (iff our packing necessarily omits high order bytes).
            std::memcpy(sp.data(), src_byte, bytesPerElement);
        }
        // if any bytes remain, fill them with 0's (branch only taken if allowLongerOutputBuffer == true)
        if (i < nOutputElems) {
            Span<uint8_t> remainingBytes = outBuffer.subspan(i * bytesPerElement);
            std::memset(remainingBytes.data(), 0, remainingBytes.size());
        }

        return PackedNumView(outBuffer, true);
    }

    // -- STL-compat --

    class Iterator {
        friend class PackedNumView;
        const PackedNumView *pnv;
        ptrdiff_t pos;
        Iterator(const PackedNumView *pnv_, size_t pos_) : pnv(pnv_), pos(pos_) {}
    public:
        using difference_type = ptrdiff_t;
        using value_type = UInt;
        using pointer = void;
        using reference = const value_type &;
        using iterator_category = std::random_access_iterator_tag;

        Iterator(const Iterator &) = default;
        Iterator & operator=(const Iterator &) = default;

        UInt operator*() const { return pnv->operator[](pos); }
        Iterator & operator++() { pos += 1; return *this; }
        Iterator operator++(int) {
            Iterator ret(*this);
            pos += 1;
            return ret;
        }
        Iterator & operator--() { pos -= 1; return *this; }
        Iterator operator--(int) {
            Iterator ret(*this);
            pos -= 1;
            return ret;
        }
        friend Iterator operator+(const Iterator &lhs, ptrdiff_t offset) {
            Iterator ret = lhs;
            ret.pos += offset;
            return ret;
        }
        friend Iterator operator-(const Iterator &lhs, ptrdiff_t offset) {
            Iterator ret = lhs;
            ret.pos -= offset;
            return ret;
        }
        friend ptrdiff_t operator-(const Iterator &lhs, const Iterator &rhs) {
            return lhs.pos - rhs.pos;
        }

        ptrdiff_t index() const { return pos; }

        bool valid() const { return pos >= 0 && pnv != nullptr && static_cast<size_t>(pos) < pnv->size(); }

        Iterator & operator+=(ptrdiff_t offset) { pos += offset; return *this; }
        Iterator & operator-=(ptrdiff_t offset) { pos -= offset; return *this; }

        bool operator==(const Iterator &o) const { return pnv == o.pnv && pos == o.pos; }
        bool operator!=(const Iterator &o) const { return ! this->operator==(o); }
        bool operator<(const Iterator &o) const { return pnv == o.pnv && pos < o.pos; }
        bool operator<=(const Iterator &o) const { return this->operator<(o) || this->operator==(o); }
        bool operator>(const Iterator &o) const { return ! this->operator<=(o); }
        bool operator>=(const Iterator &o) const { return ! this->operator<(o); }
    };

    Iterator begin() const { return Iterator(this, 0); }
    Iterator end() const { return Iterator(this, size()); }

    UInt front() const { return *begin(); }
    UInt back() const { return *(end() - 1); }
    bool empty() const { return size() == 0; }

    using value_type = UInt;
    using iterator = Iterator;
    using const_iterator = Iterator;
    using size_type = size_t;

    /// Binary search based find; this assumes the backing ints are sorted, otherwise this will return unspecified results.
    Iterator find(UInt val, bool isReverseSorted = false) const {
        auto it = lower_bound(val, isReverseSorted); // search for >= val
        if (auto e = end(); it != e && *it != val) it = e; // if != val, set result to end
        return it;
    }

    /// Binary search based lower_bound; returns the first element >= `val` (or <= `val` if reverse sorted),
    /// or end() if no such element exists.
    ///
    /// This assumes the backing ints are sorted, otherwise this will return unspecified results
    Iterator lower_bound(UInt val, bool isReverseSorted = false) const {
        if (isReverseSorted) {
            return std::lower_bound(begin(), end(), val, std::greater<UInt>{});
        } else {
            return std::lower_bound(begin(), end(), val);
        }
    }

    bool operator==(const PackedNumView &o) const { return buf == o.buf; }
    bool operator!=(const PackedNumView &o) const { return buf != o.buf; }
};
