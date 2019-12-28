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
        unsigned ordinal = 0; ///< used to keep track of the order this tx appeared in the mempool from bitcoind. Not particularly useful.
        unsigned sizeBytes = 0;
        bitcoin::Amount fee;
        int64_t time = 0; ///< fixed (does not change during lifetime of a Tx instance)
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
            /*if (ordinal != o.ordinal) // <-- this doesn't seem to do anything useful, so disabled.
                return ordinal < o.ordinal;
            else*/
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
    unsigned nextOrdinal = 0; ///< used to keep track of the order of new tx's appearing from bitcoind for possible sorting based on natural bitcoind order

    inline void clear() { txs.clear(); hashXTxs.clear(); nextOrdinal = 0; }
};
