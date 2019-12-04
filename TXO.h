#pragma once

#include "HashX.h"

#include "bitcoin/amount.h"

#include <cstdint>
#include <functional> // for std::hash
#include <optional>
#include <unordered_map>

/// WIP
struct TXO {
    // pack paranoia -- not strictly needed since this packs anyway the way we want on gcc and/or clang.
#   ifdef __GNUC__
#   pragma pack(push, 1)
#   endif
    union {
        struct {
            /// tx index in the global tx table. First tx in blockchain is txNum 0, and so on (mapping of unique number to a txid hash, stored in db).
            /// Note this is really a 48 bit value covering the range [0, 17592186044415]
            std::uint64_t txNum : 48;
            /// The the 'N' (output index) for the tx itself as per bitcoin tx format
            std::uint16_t n;
        } prevout;
        std::uint64_t asU64;
    } u;
#   ifdef __GNUC__
#   pragma pack(pop)
#   endif
};

namespace std {
    // specialization of std::hash to be able to add struct UTXO to any unordered_set or unordered_map
    template<> struct hash<TXO> {
        std::size_t operator()(const TXO &txo) const noexcept {
            static_assert (sizeof(txo.u.asU64) <= sizeof(std::size_t) && sizeof(txo.u.prevout) >= 8 && sizeof(txo.u.prevout) == sizeof(txo.u.asU64),
                           "Possible non-64-bit platform detected or other struct packing weirdness on this compiler. Please compile with a 64-bit compiler.");
            return txo.u.asU64; // just return the packed txNum:n value as this is guaranteed to be unique
        }
    };
}

/// WIP -- Spend info for a txo.
struct TXOInfo {
    bitcoin::Amount amount;
    HashX hashX; ///< the scripthash this output is sent to.  Note in most cases this can be compactified to be a shallow-copy of existing data (such that dupes point to the same underlying data in eg UTXOSet).
    std::optional<unsigned> confirmedHeight; ///< if unset, is mempool tx
};


using UTXOSet = std::unordered_map<TXO, TXOInfo>; ///< TXO -> Info
