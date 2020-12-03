//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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

#include "robin_hood/robin_hood.h"

#include <QString>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash
#include <optional>

/// A transaction output; A txHash:outN pair.
struct TXO {
    TxHash txHash;
    IONum  outN = 0;

    bool isValid() const { return txHash.length() == HashLen;  }
    QString toString() const;

    bool operator==(const TXO &o) const noexcept { return txHash == o.txHash && outN == o.outN; }
    bool operator<(const TXO &o) const noexcept { return txHash < o.txHash && outN < o.outN; }


    // serialization/deserialization
    QByteArray toBytes() const noexcept {
        QByteArray ret;
        if (!isValid()) return ret;
        const int hlen = txHash.length();
        ret.resize(int(serSize()));
        std::memcpy(ret.data(), txHash.data(), size_t(hlen));
        std::memcpy(ret.data() + hlen, reinterpret_cast<const char *>(&outN), sizeof(outN));
        return ret;
    }

    static TXO fromBytes(const QByteArray &ba) noexcept {
        TXO ret;
        if (ba.length() != int(serSize())) return ret;
        ret.txHash = QByteArray(ba.data(), HashLen);
        // we memcpy rather than reinterpret_cast in order to guard against unaligned access
        std::memcpy(reinterpret_cast<char *>(&ret.outN), ba.data()+HashLen, sizeof(ret.outN));
        return ret;
    }

    static constexpr size_t serSize() noexcept { return HashLen + sizeof(IONum); }
};


namespace std {
/// specialization of std::hash to be able to add struct TXO to any unordered_set or unordered_map as a key
template<> struct hash<TXO> {
    size_t operator()(const TXO &txo) const noexcept {
        const auto val1 = BTC::QByteArrayHashHasher{}(txo.txHash);
        const auto val2 = txo.outN;
        // We must copy the hash bytes and the ionum to a temporary buffer and hash that.
        // Previously, we put these two items in a struct but it didn't have a unique
        // objected repr and that led to bugs.  See Fulcrum issue #47 on GitHub.
        std::array<std::byte, sizeof(val1) + sizeof(val2)> buf;
        std::memcpy(buf.data()               , reinterpret_cast<const char *>(&val1), sizeof(val1));
        std::memcpy(buf.data() + sizeof(val1), reinterpret_cast<const char *>(&val2), sizeof(val2));
        // on 32-bit: below hashes the above 6-byte buffer using MurMur3
        // on 64-bit: below hashes the above 10-byte buffer using CityHash64
        return Util::hashForStd(buf);
    }
};
} // namespace std

/// Spend info for a txo. Amount, scripthash, txNum, and possibly confirmedHeight
struct TXOInfo {
    bitcoin::Amount amount;
    HashX hashX; ///< the scripthash this output is sent to.  Note in most cases this can be compactified to be a shallow-copy of existing data (such that dupes point to the same underlying data in eg UTXOSet).
    std::optional<unsigned> confirmedHeight; ///< if unset, is mempool tx
    TxNum txNum = 0; ///< the globally mapped txNum (one for each TxHash). This is used to be able to delete the CompactTXO from the hashX's scripthash_unspent table

    bool isValid() const { return amount / bitcoin::Amount::satoshi() >= 0 && hashX.length() == HashLen; }

    /// for debug, etc
    bool operator==(const TXOInfo &o) const
        { return amount == o.amount && hashX == o.hashX && confirmedHeight == o.confirmedHeight && txNum == o.txNum; }
    bool operator!=(const TXOInfo &o) const { return !(*this == o); }

    QByteArray toBytes() const noexcept {
        QByteArray ret;
        if (!isValid()) return ret;
        const auto amt_sats = amount / bitcoin::Amount::satoshi();
        const int cheight = confirmedHeight.has_value() ? int(*confirmedHeight) : -1;
        ret.resize(int(serSize()));
        char *cur = ret.data();
        std::memcpy(cur, &amt_sats, sizeof(amt_sats));
        cur += sizeof(amt_sats);
        std::memcpy(cur, &cheight, sizeof(cheight));
        cur += sizeof(cheight);
        CompactTXO::txNumToCompactBytes(reinterpret_cast<std::byte *>(cur), txNum);
        cur += CompactTXO::compactTxNumSize();
        std::memcpy(cur, hashX.constData(), size_t(hashX.length()));
        return ret;
    }
    static TXOInfo fromBytes(const QByteArray &ba) {
        TXOInfo ret;
        if (size_t(ba.length()) != serSize()) {
            return ret;
        }
        int64_t amt;
        int cheight;
        const char *cur = ba.constData();
        std::memcpy(&amt, cur, sizeof(amt));
        cur += sizeof(amt);
        std::memcpy(&cheight, cur, sizeof(cheight));
        cur += sizeof(cheight);
        ret.txNum = CompactTXO::txNumFromCompactBytes(reinterpret_cast<const std::byte *>(cur));
        cur += CompactTXO::compactTxNumSize();
        ret.hashX = QByteArray(cur, HashLen);
        ret.amount = amt * bitcoin::Amount::satoshi();
        if (cheight > -1)
            ret.confirmedHeight.emplace(unsigned(cheight));
        return ret;
    }

    static constexpr size_t serSize() noexcept { return sizeof(int64_t) + sizeof(int) + CompactTXO::compactTxNumSize() + HashLen; }
};

