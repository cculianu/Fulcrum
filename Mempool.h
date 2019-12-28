#pragma once

#include "BlockProcTypes.h"
#include "TXO.h"

#include "bitcoin/amount.h"
#include "robin_hood/robin_hood.h"

#include <list>
#include <map>
#include <memory>
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>


/// Models the mempool -- WIP
struct Mempool
{

    /// This info, with the exception of `hashXs` comes from bitcoind via the "getrawmempool true" RPC call.
    /// Very much a WIP; I am not yet not sure what info we need and/or how most efficiently to orgnaize it just yet.
    struct Tx
    {
        TxHash hash; ///< in reverse bitcoind order (ready for hex encode), fixed value.
        unsigned sizeBytes = 0;
        bitcoin::Amount fee;
        int64_t time = 0; ///< fixed (does not change during lifetime of instance)
        BlockHeight height = 0; ///< is usually == chain tip height, but not always; fixed (does not change during lifetime of instance)
        unsigned descendantCount = 1; ///< In-mempool descentant count, including this. Is always at least 1. May increase as mempool gets refreshed.
        unsigned ancestorCount = 1; ///< In-mempool ancestor count, including this. Is always at least 1. This is fixed.

        /// May be empty. In-mempool ancestors & descendant txid's. All hashes are in reverse memory order (hex encode order).
        std::unordered_set<TxHash, HashHasher> depends, ///< this is fixed
                                               spentBy; ///< this may change as we refresh the mempool

        ///< these are all the txos in this tx. Once set-up, this doesn't change (unlike IOInfo.utxo)
        std::map<IONum, TXOInfo> txos;

        struct IOInfo {
            /// spends. .confirmedSpends here affects get_balance.
            robin_hood::unordered_flat_map<TXO, TXOInfo, std::hash<TXO>>
                /// Spends of txo's from the db (confirmed) utxoset.
                /// - Items here get _subtracted_ from the "unconfirmed" in RPC get_balance.
                confirmedSpends,
                /// spends of mempool ancestor txos. Items appearing here will not appear in the ancestor's
                /// IOInfo::utxo map (their insertion here accompanies a deletion of those ancestor items).
                unconfirmedSpends;
            /// UNSPENT outs, this is used to modify listunspent and get_balance. This map may get items deleted as
            /// the mempool evolves if new descendants appear that spend these txos (those descendants will list the
            /// item that gets deleted from here in their own IOInfo::unconfirmedSpends map).
            /// + Items here get _added_ to the "unconfirmed" balance in RPC get_balance.
            std::set<IONum> utxo; ///< ordered IONums pointing into the txos map declared above
        };

        bool operator<(const Tx &o) const {
            // NOTE: These 4 fields: ancestorCount, height, time, and hash should remain unchanged throughout the lifetime
            // of a Tx
            if (ancestorCount != o.ancestorCount)
                return ancestorCount < o.ancestorCount;
            else if (height != o.height)
                return height < o.height;
            else if (time != o.time)
                return time < o.time;
            return hash < o.hash;
        }

        robin_hood::unordered_node_map<HashX, IOInfo, HashHasher> hashXs;
    };

    using TxRef = std::shared_ptr<Tx>;
    /// master mapping of TxHash -> TxRef
    using TxMap = robin_hood::unordered_flat_map<TxHash, TxRef, HashHasher>;
    /// ensures an ordering of TxRefs for the set below that are from fewest ancestors -> most ancestors
    struct TxRefOrdering {
        bool operator()(const TxRef &a, const TxRef &b) const {
            if (a && b)
                return *a < *b;
            else if (!a && b)
                return true;
            return false;
        }
    };
    /// note: the TxRefs here here point to the same object as the mapped_type in the TxMap above
    using HashXTxMap = robin_hood::unordered_node_map<HashX, std::set<TxRef, TxRefOrdering>, HashHasher>;


    // -- Data members of struct Mempool --
    TxMap txs;
    HashXTxMap hashXTxs;

    inline void clear() { txs.clear(); hashXTxs.clear(); }
};
