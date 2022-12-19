//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "TXO_Compact.h"

#include <QString>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash
#include <optional>
#include <tuple> // for std::tie

/// A transaction output; A txHash:outN pair.
struct TXO {
    TxHash txHash;
    IONum  outN = 0;

    bool isValid() const { return txHash.length() == HashLen;  }
    QString toString() const;

    bool operator==(const TXO &o) const noexcept { return std::tie(outN, txHash) == std::tie(o.outN, o.txHash); /* cheaper to compare the outNs first */ }
    bool operator<(const TXO &o) const noexcept { return std::tie(txHash, outN) < std::tie(o.txHash, o.outN); }


    // Serialization. Note that the resulting buffer may be 34 or 35 bytes, depending on whether IONum's value > 65535.
    // If wide == true, then resulting buffer is always maxSize() bytes (35).
    QByteArray toBytes(bool wide) const {
        QByteArray ret(int(serializedSize(wide)), Qt::Uninitialized);
        if (UNLIKELY(!isValid())) { ret.clear(); return ret; }
        std::memcpy(ret.data(), txHash.constData(), HashLen);
        std::byte * const buf = reinterpret_cast<std::byte *>(ret.data() + HashLen);
        buf[0] = std::byte(outN >> 0u & 0xff);
        buf[1] = std::byte(outN >> 8u & 0xff);
        if (ret.size() == int(maxSize()))
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


/// specialization of std::hash to be able to add struct TXO to any unordered_set or unordered_map as a key
template<> struct std::hash<TXO> {
    std::size_t operator()(const TXO &txo) const noexcept {
        const auto val1 = BTC::QByteArrayHashHasher{}(txo.txHash);
        const auto val2 = txo.outN;
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
    std::optional<unsigned> confirmedHeight; ///< if unset, is mempool tx
    TxNum txNum = 0; ///< the globally mapped txNum (one for each TxHash). This is used to be able to delete the CompactTXO from the hashX's scripthash_unspent table
    bitcoin::token::OutputDataPtr tokenDataPtr; ///< may be null, if not-null, output has token data on it

    bool isValid() const { return amount / bitcoin::Amount::satoshi() >= 0 && hashX.length() == HashLen; }

    /// for debug, etc
    bool operator==(const TXOInfo &o) const {
        return     std::tie(  amount,   hashX,   confirmedHeight,   txNum,   tokenDataPtr)
                == std::tie(o.amount, o.hashX, o.confirmedHeight, o.txNum, o.tokenDataPtr);
    }
    bool operator!=(const TXOInfo &o) const { return !(*this == o); }

    QByteArray toBytes() const {
        QByteArray ret;
        if (!isValid()) return ret;
        const int64_t amt_sats = amount / bitcoin::Amount::satoshi();
        const int32_t cheight = confirmedHeight.has_value() ? int(*confirmedHeight) : -1;
        const int minSize = int(minSerSize());
        const int rsvSize = minSize + (tokenDataPtr ? 1 + int(tokenDataPtr->EstimatedSerialSize()) : 0);
        ret.reserve(rsvSize);
        ret.resize(minSize);
        char *cur = ret.data();
        std::memcpy(cur, &amt_sats, sizeof(amt_sats));
        cur += sizeof(amt_sats);
        std::memcpy(cur, &cheight, sizeof(cheight));
        cur += sizeof(cheight);
        CompactTXO::txNumToCompactBytes(reinterpret_cast<std::byte *>(cur), txNum);
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
        int64_t amt;
        int32_t cheight;
        const char *cur = ba.constData();
        std::memcpy(&amt, cur, sizeof(amt));
        cur += sizeof(amt);
        std::memcpy(&cheight, cur, sizeof(cheight));
        cur += sizeof(cheight);
        ret.txNum = CompactTXO::txNumFromCompactBytes(reinterpret_cast<const std::byte *>(cur));
        cur += CompactTXO::compactTxNumSize(); // always 6
        ret.hashX = QByteArray(cur, HashLen);
        cur += HashLen;
        ret.amount = amt * bitcoin::Amount::satoshi();
        if (cheight > -1)
            ret.confirmedHeight.emplace(unsigned(cheight));
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

    static constexpr size_t minSerSize() noexcept { return sizeof(int64_t) + sizeof(int32_t) + CompactTXO::compactTxNumSize() + HashLen; }
};
