#pragma once

#include "BlockProcTypes.h"

#include "robin_hood/robin_hood.h"

#include <QString>

#include <cstdint>
#include <cstring> // for std::memcpy
#include <functional> // for std::hash
#include <optional>


/// WIP
struct TXO {
    TxHash prevoutHash;
    IONum  prevoutN = 0;

    bool isValid() const { return prevoutHash.length() == HashLen;  }
    QString toString() const { return isValid() ? QString("%1:%2").arg(QString(prevoutHash.toHex())).arg(prevoutN) : "<txo_invalid>"; }

    bool operator==(const TXO &o) const noexcept { return prevoutHash == o.prevoutHash && prevoutN == o.prevoutN; }
    bool operator<(const TXO &o) const noexcept { return prevoutHash < o.prevoutHash && prevoutN < o.prevoutN; }
};

namespace std {
    /// specialization of std::hash to be able to add struct TXO to any unordered_set or unordered_map as a key
    template<> struct hash<TXO> {
        size_t operator()(const TXO &txo) const noexcept {
            if (txo.prevoutHash.length() >= int(sizeof(size_t)))
                return *reinterpret_cast<const size_t *>(txo.prevoutHash.constData()) + size_t(txo.prevoutN);
            using h1 = std::hash<uint>;
            using h2 = std::hash<IONum>;
            return h1()(qHash(txo.prevoutHash)) + h2()(txo.prevoutN);
        }
    };
}

/// WIP -- Spend info for a txo.
struct TXOInfo {
    bitcoin::Amount amount;
    HashX hashX; ///< the scripthash this output is sent to.  Note in most cases this can be compactified to be a shallow-copy of existing data (such that dupes point to the same underlying data in eg UTXOSet).
    std::optional<unsigned> confirmedHeight; ///< if unset, is mempool tx

    bool isValid() const { return amount / bitcoin::Amount::satoshi() >= 0 && hashX.length() == HashLen; }

    QByteArray toBytes() const noexcept {
        QByteArray ret;
        if (!isValid()) return ret;
        const auto amt_sats = amount / bitcoin::Amount::satoshi();
        const int cheight = confirmedHeight.has_value() ? int(confirmedHeight.value()) : -1;
        ret.resize(int(sizeof(amt_sats)) + int(sizeof(cheight)) + HashLen);
        char *cur = ret.data();
        std::memcpy(cur, &amt_sats, sizeof(amt_sats));
        cur += sizeof(amt_sats);
        std::memcpy(cur, &cheight, sizeof(cheight));
        cur += sizeof(cheight);
        std::memcpy(cur, hashX.constData(), size_t(hashX.length()));
        return ret;
    }
    static TXOInfo fromBytes(const QByteArray &ba) {
        TXOInfo ret;
        if (size_t(ba.length()) != sizeof(int64_t) + sizeof(int) + HashLen) {
            return ret;
        }
        int64_t amt;
        int cheight;
        const char *cur = ba.constData();
        std::memcpy(&amt, cur, sizeof(amt));
        cur += sizeof(amt);
        std::memcpy(&cheight, cur, sizeof(cheight));
        cur += sizeof(cheight);
        ret.hashX = QByteArray(cur, HashLen);
        ret.amount = amt * bitcoin::Amount::satoshi();
        if (cheight > -1)
            ret.confirmedHeight.emplace(unsigned(cheight));
        return ret;
    }
};

using UTXOSet = robin_hood::unordered_flat_map<TXO, TXOInfo, std::hash<TXO>>; ///< TXO -> Info






// -------------------------------------------------------------------------------------------------------------------
// ----- Some storage helper classes below.. (safe to ignore in rest of codebase outside of Storage.h / Storage.cpp)
// -------------------------------------------------------------------------------------------------------------------
#   ifdef __GNUC__
#   pragma pack(push, 1)
#   endif
/// Stogage subsystem "compact txo"
/// This is used internally by the "Storage" subsystem for storing TxNum <-> txhash associations on disk
struct CompactTXO {
    static constexpr std::uint64_t initval = ~0ULL; ///< indicates !isValid()
    // pack paranoia -- not strictly needed since this packs anyway the way we want on gcc and/or clang.
    union {
        struct {
            /// tx index in the global tx table. First tx in blockchain is txNum 0, and so on (mapping of unique number to a txid hash, stored in db).
            /// Note this is really a 48 bit value covering the range [0, 17592186044415]
            std::uint64_t txNum : 48;
            /// The the 'N' (output index) for the tx itself as per bitcoin tx format
            std::uint16_t n;
        } prevout;
        std::uint64_t asU64 = initval;
    } u;
    CompactTXO() = default;
    CompactTXO(TxNum txNum, IONum n) { u.prevout.txNum = txNum; u.prevout.n = n; }
    CompactTXO(const CompactTXO & o) { *this = o; }
    CompactTXO & operator=(const CompactTXO & o) noexcept { u.asU64 = o.u.asU64; return *this; }
    /// for most container types
    bool operator==(const CompactTXO &o) const noexcept { return u.asU64 == o.u.asU64; }
    /// for ordered sets
    bool operator<(const CompactTXO &o) const noexcept  { return u.prevout.txNum < o.u.prevout.txNum && u.prevout.n < o.u.prevout.n; }
    // convenience
    TxNum txNum() const noexcept { return TxNum(u.prevout.txNum); }
    // convenience
    IONum N() const noexcept { return IONum(u.prevout.n); }
    bool isValid() const { return u.asU64 != initval; }
    QString toString() const { return isValid() ? QString("%1:%2").arg(txNum()).arg(N()) : "<compact_txo_invalid>"; }
    QByteArray toBytesTmp() const { return QByteArray::fromRawData(reinterpret_cast<const char *>(&u.asU64), int(sizeof(u.asU64))); }
    QByteArray toBytesCpy() const { return QByteArray(reinterpret_cast<const char *>(&u.asU64), int(sizeof(u.asU64))); }
    static CompactTXO fromBytes(const QByteArray &b) {
        CompactTXO ret;
        if (b.length() >= int(sizeof(ret.u.asU64)))
            ret.u.asU64 = *reinterpret_cast<const uint64_t *>(b.constData());
        return ret;
    }
};
#   ifdef __GNUC__
#   pragma pack(pop)
#   endif

namespace std {
/// specialization of std::hash to be able to add struct CompactTXO to any unordered_set or unordered_map
template<> struct hash<CompactTXO> {
        size_t operator()(const CompactTXO &txo) const noexcept {
            if constexpr (sizeof(txo.u.asU64) <= sizeof(size_t) && sizeof(txo.u.prevout) >= 8
                          && sizeof(txo.u.prevout) == sizeof(txo.u.asU64))
                return txo.u.asU64; // just return the packed txNum:n value as this is guaranteed to be unique
            return (txo.u.prevout.txNum<<16) | size_t(txo.u.prevout.n&0xffff);
        }
};
} // namespace std
