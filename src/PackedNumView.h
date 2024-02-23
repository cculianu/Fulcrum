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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memset
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

    PackedNumView() = default;

    PackedNumView(ByteView packedBuffer, bool throwIfJunkAtEnd = true) : buf(packedBuffer) {
        if (throwIfJunkAtEnd && buf.size() % bytesPerElement != 0u) {
            throw std::invalid_argument("packedBuffer must have a length that is a multiple of bytesPerElement!");
        }
    }

    size_t size() const { return buf.size() / bytesPerElement; }

    UInt at(size_t i) const {
        if (i >= size()) throw std::out_of_range("Index exceeds size of array");
        return this->operator[](i);
    }

    size_t byteOffsetOf(size_t index) const { return bytesPerElement * index; }
    ByteView viewForElement(size_t index) const { return buf.substr(byteOffsetOf(index), bytesPerElement); }

    UInt operator[](size_t i) const {
        const ByteView ebytes = viewForElement(i);
        UInt ret{}; // 0-init
        for (size_t bnum = 0; bnum < bytesPerElement; ++bnum) {
            const uint8_t byteVal = static_cast<uint8_t>(ebytes[bnum]);
            if constexpr (LittleEndian) {
                // backing store is little endian, convert to machine byte order
                const UInt val = static_cast<UInt>(byteVal & 0xffu) << (8u * bnum);
                ret += val;
            } else {
                // backing store is big endian, convert to machine byte order
                const UInt val = static_cast<UInt>(byteVal & 0xffu) << ((bytesPerElement - (bnum + 1u)) * 8u);
                ret += val;
            }
        }
        return ret; // value is now in machine byte order
    }

    const ByteView & rawBytes() const { return buf; }

    /// Fills outBuffer with the ints from srcInts, and returns the read-only view into the resulting buffer.
    /// Note that outBuffer must be a multiple of `bytesPerElement`, else an exception is thrown.
    template <typename NumT, std::enable_if_t<std::is_integral_v<std::remove_cv_t<NumT>> && std::is_unsigned_v<std::remove_cv_t<NumT>>, void *> = nullptr>
    static PackedNumView Make(Span<uint8_t> outBuffer, const Span<NumT> & srcInts, bool allowLongerOutputBuffer = false) {
        using Num = std::remove_cv_t<NumT>;
        if (outBuffer.size() % bytesPerElement != 0u)
            throw std::invalid_argument("outBuffer's size must be a multiple of bytesPerElement!");

        const size_t nOutputElems = outBuffer.size() / bytesPerElement;
        if (!allowLongerOutputBuffer && nOutputElems > srcInts.size())
            throw std::invalid_argument("outputBuffer's size is larger than what srcInts requires");
        const size_t nIters = std::min(nOutputElems, srcInts.size());

        size_t i;
        for (i = 0u; i < nIters; ++i) {
            Span<uint8_t> sp = outBuffer.subspan(i * bytesPerElement, bytesPerElement);
            using Val = std::conditional_t<sizeof(UInt) >= sizeof(Num), UInt, Num>; // `Val` is the larger of the two types
            const Val val = static_cast<Val>(srcInts[i]);
            for (size_t bnum = 0u; bnum < bytesPerElement; ++bnum) {
                if constexpr (LittleEndian) {
                    // little endian output - store lsb first
                    const auto shift = bnum * 8u;
                    sp[bnum] = static_cast<uint8_t>((val >> shift) & 0xffu);
                } else {
                    // big endian output - store msb first
                    const auto shift = (bytesPerElement - (bnum + 1u)) * 8u;
                    sp[bnum] = static_cast<uint8_t>((val >> shift) & 0xffu);
                }
            }
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
