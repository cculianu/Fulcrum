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
#pragma once

#include "BlockProcTypes.h"
#include "BTC.h"
#include "Compat.h"  // for QByteArray operator<=>
#include "TXO_Compact.h"

#include <QString>

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash
#include <limits>
#include <optional>
#include <tuple> // for std::tie
#include <type_traits> // for std::has_unique_object_representations_v

/// A transaction output; A txHash:outN pair.
struct TXO {
    TxHash txHash;
    IONum  outN = 0;

    bool isValid() const { return txHash.length() == HashLen;  }
    QString toString() const;

    bool operator==(const TXO &o) const noexcept { return std::tie(outN, txHash) == std::tie(o.outN, o.txHash); /* cheaper to compare the outNs first */ }
    auto operator<=>(const TXO &o) const noexcept { return std::tie(txHash, outN) <=> std::tie(o.txHash, o.outN); }

    // Serialization. Note that the resulting buffer may be 34 or 35 bytes, depending on whether IONum's value > 65535.
    // If wide == true, then resulting buffer is always maxSize() bytes (35).
    QByteArray toBytes(bool wide) const {
        QByteArray ret(static_cast<QByteArray::size_type>(serializedSize(wide)), Qt::Uninitialized);
        if (UNLIKELY(!isValid())) { ret.clear(); return ret; }
        std::memcpy(ret.data(), txHash.constData(), HashLen);
        std::byte * const buf = reinterpret_cast<std::byte *>(ret.data() + HashLen);
        buf[0] = std::byte(outN >> 0u & 0xff);
        buf[1] = std::byte(outN >> 8u & 0xff);
        if (ret.size() == static_cast<QByteArray::size_type>(maxSize()))
            buf[2] = std::byte(outN >> 16u & 0xff); // may be 0 if serializing wide==true
        return ret;
    }

    /// 34
    static constexpr size_t minSize() noexcept { return HashLen + 2; }
    /// 35
    static constexpr size_t maxSize() noexcept { return HashLen + 3; }

    // Deserialization.  The input buffer must be *exactly* 34 or 35 bytes.
    // If 35 bytes, outN is deserialized as a 24-bit value (otherwise 16-bit value).
    static TXO fromBytes(const QByteArray &ba) {
        TXO ret;
        const size_t baLen = size_t(ba.length());
        static_assert (maxSize() - minSize() == 1, "Assumption here is that maxSize() and minSize() differ by 1");
        if (baLen != minSize() && baLen != maxSize())
            return ret;
        ret.txHash = QByteArray(ba.constData(), HashLen);
        const std::byte * const buf = reinterpret_cast<const std::byte *>(ba.constData() + HashLen);
        ret.outN = IONum(buf[0]) << 0u | IONum(buf[1]) << 8u;
        if (baLen == maxSize())  // 3-byte IONum (for values beyond 65535)
            ret.outN |= IONum(buf[2]) << 16u;
        return ret;
    }

private:
    size_t serializedSize(bool wide) const noexcept { return wide || outN > IONum16Max ? maxSize() : minSize(); }
};

static_assert(std::three_way_comparable<TXO, std::strong_ordering>);

/// specialization of std::hash to be able to add struct TXO to any unordered_set or unordered_map as a key
template<> struct std::hash<TXO> {
    std::size_t operator()(const TXO &txo) const noexcept {
        const auto val1 = HashHasher{}(txo.txHash);
        const auto val2 = txo.outN;
        static_assert(std::has_unique_object_representations_v<decltype(val1)>
                      && std::has_unique_object_representations_v<decltype(val2)>);
        // We must copy the hash bytes and the ionum to a temporary buffer and hash that.
        // Previously, we put these two items in a struct but it didn't have a unique
        // objected repr and that led to bugs.  See Fulcrum issue #47 on GitHub.
        std::array<std::byte, sizeof(val1) + sizeof(val2)> buf;
        std::memcpy(buf.data()               , reinterpret_cast<const char *>(&val1), sizeof(val1));
        std::memcpy(buf.data() + sizeof(val1), reinterpret_cast<const char *>(&val2), sizeof(val2));
        // on 32-bit: below hashes the above 8-byte buffer using MurMur3
        // on 64-bit: below hashes the above 12-byte buffer using CityHash64
        return Util::hashForStd(buf);
    }
};

/// Spend info for a txo. Amount, scripthash, txNum, and possibly confirmedHeight
struct TXOInfo {
    bitcoin::Amount amount;
    HashX hashX; ///< the scripthash this output is sent to.  Note in most cases this can be compactified to be a shallow-copy of existing data (such that dupes point to the same underlying data in eg UTXOSet).
    std::optional<BlockHeight> confirmedHeight; ///< if unset, is mempool tx
    TxNum txNum = 0; ///< the globally mapped txNum (one for each TxHash). This is used to be able to delete the CompactTXO from the hashX's scripthash_unspent table
    bitcoin::token::OutputDataPtr tokenDataPtr; ///< may be null, if not-null, output has token data on it

    bool isValid() const { return amount / bitcoin::Amount::satoshi() >= 0 && hashX.length() == HashLen; }

    /// for debug, etc
    bool operator==(const TXOInfo &o) const {
        return     std::tie(  amount,   hashX,   confirmedHeight,   txNum,   tokenDataPtr)
                == std::tie(o.amount, o.hashX, o.confirmedHeight, o.txNum, o.tokenDataPtr);
    }

private:
    static inline constexpr BlockHeight kNoBlockHeight = -1; // 0xffffffff; prevous code used int32_t(-1) to indicate no conf height
    static_assert(std::numeric_limits<BlockHeight>::max() == std::numeric_limits<uint32_t>::max()
                  && kNoBlockHeight == std::numeric_limits<BlockHeight>::max(), "Ser/Deser assumes this");

public:
    QByteArray toBytes() const {
        QByteArray ret;
        using QBASz = QByteArray::size_type;
        if (!isValid()) return ret;
        const uint64_t amt_sats_le = Util::hToLe64(amount / bitcoin::Amount::satoshi());
        const uint32_t cheight_le = Util::hToLe32(confirmedHeight.value_or(kNoBlockHeight)); // NB: earlier version of this code used int32_t(-1) here to indicate no cheight.
        const QBASz minSize = static_cast<QBASz>(minSerSize());
        const QBASz rsvSize = minSize + (tokenDataPtr ? 1 + static_cast<QBASz>(tokenDataPtr->EstimatedSerialSize()) : 0);
        ret.reserve(rsvSize);
        ret.resize(minSize);
        char *cur = ret.data();
        std::memcpy(cur, &amt_sats_le, sizeof(amt_sats_le));
        cur += sizeof(amt_sats_le);
        std::memcpy(cur, &cheight_le, sizeof(cheight_le));
        cur += sizeof(cheight_le);
        CompactTXO::txNumToCompactBytes(reinterpret_cast<std::byte *>(cur), txNum, /*bigEndian=*/false);
        cur += CompactTXO::compactTxNumSize(); // always 6
        std::memcpy(cur, hashX.constData(), size_t(hashX.length())); // always 32 (enforced by isValid() check above)
        // NOTE: `cur` may be invalidated below
        BTC::SerializeTokenDataWithPrefix(ret, tokenDataPtr.get());
        return ret;
    }

    /// `ba` must only contain the valid bytes for this object. Will not tolerate junk bytes at the end.
    static TXOInfo fromBytes(const QByteArray &ba) {
        TXOInfo ret;
        if (size_t(ba.length()) < minSerSize()) {
            return ret;
        }
        uint64_t amt_le;
        uint32_t cheight_le;
        const char *cur = ba.constData();
        std::memcpy(&amt_le, cur, sizeof(amt_le));
        cur += sizeof(amt_le);
        std::memcpy(&cheight_le, cur, sizeof(cheight_le));
        cur += sizeof(cheight_le);
        ret.txNum = CompactTXO::txNumFromCompactBytes(reinterpret_cast<const std::byte *>(cur), /*bigEndian=*/false);
        cur += CompactTXO::compactTxNumSize(); // always 6
        ret.hashX = QByteArray(cur, HashLen);
        cur += HashLen;
        ret.amount = static_cast<int64_t>(Util::le64ToH(amt_le)) * bitcoin::Amount::satoshi();
        const uint32_t cheight = Util::le32ToH(cheight_le);
        if (cheight != kNoBlockHeight) // NB: earlier version of this code used int32_t(-1) here to indicate no cheight, which is the same as uint32_t(-1) byte-wise
            ret.confirmedHeight.emplace(cheight);
        try {
            ret.tokenDataPtr = BTC::DeserializeTokenDataWithPrefix(ba, cur - ba.constData());
            if constexpr (false) // Left-in for debugging purposes
                if (ret.tokenDataPtr) Debug() << "Deserialized token data: " << ret.tokenDataPtr->ToString(true).c_str();
        } catch (const std::exception &e) {
            // This should never happen. Indicate serious error.
            Error() << "Got exception deserializing token data: " << e.what() << " (bytearray hex: " << ba.toHex() << ")";
            ret = TXOInfo{};
        }
        return ret;
    }

    static constexpr size_t minSerSize() noexcept { return sizeof(int64_t) + sizeof(uint32_t) + CompactTXO::compactTxNumSize() + HashLen; }
};
