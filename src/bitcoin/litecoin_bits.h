//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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

// This file contains some helpers used mainly to grok litecoin
// mimble-wimble data in transactions and blocks.

#include "heapoptional.h"
#include "serialize.h"
#include "streams.h"

#include <limits>

namespace bitcoin {
namespace litecoin_bits {

    using MimbleBlobPtr = HeapOptional<std::vector<uint8_t>>;

    namespace detail {
        template <typename Stream>
        struct Eater {
            Stream & s;
            MimbleBlobPtr::element_type & data;

            using value_type = MimbleBlobPtr::element_type::value_type;
            static_assert(sizeof(value_type) == 1 && std::is_trivial_v<value_type>);

            Eater(Stream & s_, MimbleBlobPtr::element_type & data_) : s(s_), data(data_) {}

            const value_type * RdWr(size_t nbytes) {
                const auto pos = data.size();
                if (nbytes) {
                    data.resize(pos + nbytes);
                    s.read(reinterpret_cast<char *>(data.data()) + pos, nbytes);
                }
                return std::as_const(data).data() + pos;
            }

            uint64_t RdWrSz() {
                const uint64_t sz = ReadCompactSize(s);
                GenericVectorWriter vw(s.GetType(), s.GetVersion(), data, data.size());
                WriteCompactSize(vw, sz); // put it to output buf
                return sz;
            }

            uint64_t RdWrByteVector() {
                const auto nbytes = RdWrSz();
                RdWr(nbytes);
                return nbytes;
            }

            template<typename Stream2, typename I>
            static void WriteVarInt(Stream2 &os, I n) {
                // hack to make this code compatible with updated serialize.h from BCHN sources
                bitcoin::WriteVarInt<Stream2, VarIntMode::DEFAULT>(os, n);
            }

            uint64_t RdWrVarInt() {
                const auto vi = ReadVarInt<Stream, VarIntMode::DEFAULT, uint64_t>(s);
                GenericVectorWriter vw(s.GetType(), s.GetVersion(), data, data.size());
                this->WriteVarInt(vw, vi);
                return vi;
            }

            int32_t RdWrHeight() {
                const auto nHeight = RdWrVarInt();
                if (nHeight > std::numeric_limits<int32_t>::max() || int32_t(nHeight) < 0)
                    throw std::ios_base::failure("mimble: Height is out of range");
                return nHeight;
            }

            int64_t RdWrAmount() {
                const auto nAmount = RdWrVarInt();
                if (nAmount > std::numeric_limits<int64_t>::max() || int64_t(nAmount) < 0)
                    throw std::ios_base::failure("mimble: Amount is out of range");
                return nAmount;
            }

            void EatTxBody() {
                uint64_t n;

                // read std::vector<Input>
                n = RdWrSz(); // compactSize
                for (uint64_t i = 0; i < n; ++i) {
                    // class Input
                    const auto features = *RdWr(1); // 1 byte features
                    RdWr(32 + 33 + 33); // 32-byte outputID + 33-byte commitment + 33-byte output public key
                    if (features & 0x1) {
                        RdWr(33); // optional input public key
                    }
                    if (features & 0x2) { // extraData (variable size vector of uint8_t)
                        RdWrByteVector();
                    }
                    RdWr(64); // 64-byte signature
                }

                // read std::vector<Output>
                n = RdWrSz(); // compactSize
                for (uint64_t i = 0; i < n; ++i) {
                    // class Output
                    RdWr(33 + 33 + 33); // 33-byte commitment + 33-byte sender public key + 33-byte receiver public key
                    { // class OutputMessage
                        const auto features = *RdWr(1);
                        if (features & 0x1) { // standard fields feature bit
                            RdWr(33 + 1 + 8 + 16); // 33-byte key_exchange_pubkey + 1 byte view_tag + 8-byte masked_value + 16-byte masked_nonce
                        }
                        if (features & 0x2) { // extended data feature bit
                            RdWrByteVector();
                        }
                    }
                    RdWr(675 + 64); // 675-byte RangeProof  + 64-byte signature
                }

                // read std::vector<Kernel>
                n = RdWrSz();
                for (uint64_t i = 0; i < n; ++i) {
                    // class Kernel
                    const auto features = *RdWr(1);
                    if (features & 0x1) RdWrAmount(); // FEE_FEATURE_BIT
                    if (features & 0x2) RdWrAmount(); // PEGIN_FEATURE_BIT
                    if (features & 0x4) { // PEGOUT_FEATURE_BIT
                        // std::vector<PegOutCoin>
                        const auto n2 = RdWrSz();
                        for (uint64_t j = 0; j < n2; ++j) {
                            // class PegOutCoin
                            RdWrAmount(); // amount
                            const bool spkSz = RdWrByteVector(); // scriptPubKey
                            if (!spkSz) throw std::ios_base::failure("mimble: Pegout scriptPubKey must not be empty");
                        }
                    }
                    if (features & 0x8) { // HEIGHT_LOCK_FEATURE_BIT
                        RdWrHeight();
                    }
                    if (features & 0x10) { // STEALTH_EXCESS_FEATURE_BIT
                        RdWr(33); // 33-byte public key
                    }
                    if (features & 0x20) { // EXTRA_DATA_FEATURE_BIT
                        RdWrByteVector(); // extraData (variable length byte vector)
                    }

                    RdWr(33 + 64); // 33-byte commitment + 64-byte signature
                }
            }
        }; // struct Eater
    } // namespace detail

    /// Eat the mimblewimble data from stream s for a tx, returning a byte blob (as a MimbleBlobPtr)
    template <typename TxType, typename Stream>
    MimbleBlobPtr EatTxMimbleBlob(const TxType &tx, Stream &s) {
        MimbleBlobPtr ret;
        ret.emplace();
        auto & data = *ret;

        detail::Eater eater(s, data);

        // read the opt byte, if 0, return the 1-byte buffer
        if (*eater.RdWr(1) == 0) {
            if (tx.vout.empty()) {
                /* It's illegal to include a HogEx with no outputs. */
                throw std::ios_base::failure("mimble: Missing HogEx output");
            }
            return ret;
        }

        eater.RdWr(32 + 32); // 32-bytes for kernelOffset BlindingFactor + 32-bytes for stealthOffset BlindingFactor
        eater.EatTxBody();

        return ret;
    }

    template <typename Stream>
    MimbleBlobPtr EatBlockMimbleBlob(Stream &s) {
        MimbleBlobPtr ret{};
        ret.emplace();
        auto & data = *ret;

        detail::Eater eater(s, data);

        // read the opt byte, if 0, return the 1-byte buffer
        if (*eater.RdWr(1) == 0) {
            return ret;
        }

        // class Header
        eater.RdWrHeight(); // m_height
        eater.RdWr(32 * 5); // 32-bytes each for: outputRoot, kernelRoot, leafsetRoot, kernelOffset, stealthOffset
        eater.RdWrVarInt(); // m_outputMMRSize
        eater.RdWrVarInt(); // m_kernelMMRSize

        // TxBody
        eater.EatTxBody();

        return ret;
    }

} // namespace litecoin_bits
} // namespace bitcoin
