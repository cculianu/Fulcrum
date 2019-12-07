#pragma once

#include "BlockProcTypes.h"

#include "robin_hood/robin_hood.h"

#include <QString>

#include <cstdint>
#include <functional> // for std::hash
#include <optional>


/// WIP
struct TXO {
    TxHash prevoutHash;
    IONum  prevoutN = 0;

    bool isValid() const { return prevoutHash.length() == HashLen;  }
    QString toString() const { return isValid() ? QString("%1:%2").arg(QString(prevoutHash.toHex())).arg(prevoutN) : "<txo_invalid>"; }
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
};


using UTXOSet = robin_hood::unordered_flat_map<TXO, TXOInfo, std::hash<TXO>>; ///< TXO -> Info
