//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2022 Calin A. Culianu <calin.culianu@gmail.com>
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
// mimble-wimble data in transactions.

#include "copyable_ptr.h"
#include "serialize.h"
#include "streams.h"

#include <limits>

namespace bitcoin {
namespace litecoin_bits {

    using MimbleBlobPtr = CopyablePtr<std::vector<uint8_t>>;

    /// Eat the mimblewimble data from stream s for a tx, returning a byte blob (as an MwTxBlobPtr)
    template <typename TxType, typename Stream>
    MimbleBlobPtr EatMimbleBlob(const TxType &tx, Stream &s) {
        MimbleBlobPtr ret = MimbleBlobPtr::Make();
        auto & data = *ret;

        auto RdWr = [&data, &s](size_t n) {
            const auto pos = data.size();
            if (n) {
                data.resize(pos + n);
                s.read(reinterpret_cast<char *>(data.data() + pos), n);
            }
            return std::as_const(data).data() + pos;
        };

        // read the opt byte, if 0, return the 1-byte buffer
        if (*RdWr(1) == 0) {
            if (tx.vout.empty()) {
                /* It's illegal to include a HogEx with no outputs. */
                throw std::ios_base::failure("mimble: Missing HogEx output");
            }
            return ret;
        }

        auto RdWrSz = [&data, &s] {
            const uint64_t sz = ReadCompactSize(s);
            GenericVectorWriter vw(s.GetType(), s.GetVersion(), data, data.size());
            WriteCompactSize(vw, sz); // put it to output buf
            return sz;
        };
        auto RdWrByteVector = [&RdWr, &RdWrSz] {
            const auto nbytes = RdWrSz();
            RdWr(nbytes);
            return nbytes;
        };
        auto RdWrVarInt = [&data, &s] {
              const auto vi = ReadVarInt<Stream, uint64_t>(s);
              GenericVectorWriter vw(s.GetType(), s.GetVersion(), data, data.size());
              WriteVarInt(vw, vi);
              return vi;
        };

        data.reserve(data.size() + 64);
        RdWr(32 + 32); // 32-bytes for kernelOffset BlindingFactor + 32-bytes for stealthOffset BlindingFactor

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
            if (features & 0x1) RdWrVarInt(); // FEE_FEATURE_BIT
            if (features & 0x2) RdWrVarInt(); // PEGIN_FEATURE_BIT
            if (features & 0x4) { // PEGOUT_FEATURE_BIT
                // std::vector<PegOutCoin>
                const auto n2 = RdWrSz();
                for (uint64_t j = 0; j < n2; ++j) {
                    // class PegOutCoin
                    RdWrVarInt(); // amount
                    const bool spkSz = RdWrByteVector(); // scriptPubKey
                    if (!spkSz) throw std::ios_base::failure("mimble: Pegout scriptPubKey must not be empty");
                }
            }
            if (features & 0x8) { // HEIGHT_LOCK_FEATURE_BIT
                const auto nHeight = RdWrVarInt();
                if (nHeight > std::numeric_limits<int32_t>::max()) throw std::ios_base::failure("mimble: Lock height is out of range");
            }
            if (features & 0x10) { // STEALTH_EXCESS_FEATURE_BIT
                RdWr(33); // 33-byte public key
            }
            if (features & 0x20) { // EXTRA_DATA_FEATURE_BIT
                RdWrByteVector(); // extraData (variable length byte vector)
            }

            RdWr(33 + 64); // 33-byte commitment + 64-byte signature
        }
        return ret;
    }
} // namespace litecoin_bits
} // namespace bitcoin
