//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Util.h"

#include <QByteArray>

#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <vector>

/// We wrap QByteArray with this type for type safety; so as to not confuse TxHash with DspHash
struct DspHash {
    QByteArray bytes; ///< should always have .size() == HashLen!

    bool operator==(const DspHash &o) const { return bytes == o.bytes; }
    bool operator!=(const DspHash &o) const { return bytes != o.bytes; }

    struct Hasher { std::size_t operator()(const DspHash &d) const { return HashHasher{}(d.bytes); } };
};

struct DSProof {
    DspHash hash; ///< big endian memory order (ready for Json)
    QByteArray serializedProof; ///< raw proof bytes (as retrieved from bitcoind getdsproof RPC)
    TXO txo; ///< the coin that was double-spent (spent in txHash)

    TxHash txHash; ///< the tx that this proof goes with (big endian memory order, ready for Json)

    using TxHashSet = std::unordered_set<TxHash, HashHasher>;
    TxHashSet descendants; ///< all tx's affected by this dsproof (includes txHash)

    DSProof() = default;
};

/// Maintains association between DSProofs and their descendant tx's for quick lookup. Ideally we would use a boost
/// multi-indexed container here, but since we don't want to bring in boost as a dependency, we must roll our own.
struct DSPs {
    using DspHashSet = std::unordered_set<DspHash, DspHash::Hasher>;

private:
    std::unordered_map<TxHash, DspHashSet, HashHasher> txDspsMap; ///< set of dsproofs that affect a particular tx (we call it "linked" below)
    std::unordered_map<DspHash, DSProof, DspHash::Hasher> dsproofs;

    DSProof * get(const DspHash &hash);

public:
    /// Adds a dsp by move construction. All of the descendants in its descendant set are also added to the txDspsMap.
    /// The dsp is expected to be valid, have a dspHash, a txHash, and a valid descendants set.
    /// @returns true on success. Note that if the object already exists this does nothing and will return false.
    /// @exceptions BadArgs if the supplied dsp argument is bad/invalid/missing txHash/missing descendants.
    bool add(DSProof && dsp);
    /// @returns a valid pointer to a dsp in `dsproofs` on success, nullptr if hash is not found.
    const DSProof * get(const DspHash &hash) const;
    /// Removes a dsp. Unlinks all the tx's linked to it.
    /// @returns the number of tx's that were previously linked with this dsp.
    std::size_t rm(const DspHash &hash);
    /// Links a txHash to an existing dspHash. Updates its DSProof::descendants set to include txHash.
    /// @returns false if dspHash does not exist, of if txHash is not 32 bytes
    bool addTx(const DspHash &dspHash, const TxHash &txHash);
    /// Unlinks a tx from all its dsps. If txHash is the actual double-spend tx for any dsps, and not a descendant,
    /// all such dsps will be removed as well.
    /// @returns The number of dsps that were associated with this tx, or 0 if not found.
    std::size_t rmTx(const TxHash &txHash);

    /// @returns a pointer to the internal set of all of the DspHashes linked to a TxHash, or nullptr if txHash has
    /// no associated dsps.
    const DspHashSet * dspHashesForTx(const TxHash &txHash) const;

    /// @returns a vector of pointers to all the actual proofs linked with a txHash, or an empty vector if none were found.
    std::vector<const DSProof *> proofsLinkedToTx(const TxHash &txHash) const;

    /// @returns a pointer to the primary proof associated with a txHash. A primary proof is a proof for the tx itself,
    ///     rather than one of its ancestors.
    const DSProof * proofForTx(const TxHash &txHash) const;
};
