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
#include "BTC.h"
#include "TXO.h"
#include "Util.h"

#include <QByteArray>
#include <QVariantMap>

#include <cstdint>
#include <tuple> // for std::tie
#include <unordered_set>
#include <unordered_map>
#include <vector>

/// We wrap QByteArray with this type for type safety; so as to not confuse TxHash with DspHash
struct DspHash {
    QByteArray bytes; ///< In big-endian memory order (for Json). Should always have .size() == HashLen, otherwise is not considered valid.

    static DspHash fromSerializedProof(const QByteArray &serdata) { return DspHash{!serdata.isEmpty() ? BTC::HashRev(serdata) : QByteArray()}; }
    static DspHash fromHex(const QByteArray &hex) {
        DspHash ret{Util::ParseHexFast(hex)};
        if (!ret.isValid()) ret = DspHash{}; // ensure empty if invalid
        return ret;
    }
    static DspHash fromHex(const QString &hexString) { return fromHex(hexString.toUtf8()); }

    bool isValid() const { return bytes.size() == HashLen; }
    QByteArray toHex() const { return Util::ToHexFast(bytes); } // conveneience, faster than bytes.toHex()

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
    bool operator==(const DSProof &o) const {
        return     std::tie(  hash,   serializedProof,   txo,   txHash,   descendants)
                == std::tie(o.hash, o.serializedProof, o.txo, o.txHash, o.descendants);
    }
    bool operator!=(const DSProof &o) const { return !(*this == o); }

    bool isComplete() const {
        return hash.isValid() && txo.isValid() && !serializedProof.isEmpty() && !descendants.empty() && txHash.length() == HashLen;
    }

    bool isEmpty() const; ///< true iff *this is equivalent to a default constructed value

    QVariantMap toVarMap() const; ///< for serializing to json
};

/// Maintains association between DSProofs and their descendant tx's for quick lookup. Ideally we would use a boost
/// multi-indexed container here, but since we don't want to bring in boost as a dependency, we must roll our own.
struct DSPs {
    using DspHashSet = std::unordered_set<DspHash, DspHash::Hasher>;
    using DspMap = std::unordered_map<DspHash, DSProof, DspHash::Hasher>;
    using TxDspsMap = std::unordered_map<TxHash, DspHashSet, HashHasher>;

private:
    TxDspsMap txDspsMap; ///< set of dsproofs that affect a particular tx (we call it "linked" below)
    DspMap dsproofs;

    DSProof * getMutable(const DspHash &hash);

public:
    /// @returns a const reference to the internal map. Useful for iteration to list all known proofs for e.g. /stats.
    const DspMap & getAll() const { return dsproofs; }

    bool empty() const { return dsproofs.empty(); }
    auto size() const { return dsproofs.size(); }
    void clear() { *this = DSPs(); /* <--- this clears & rehashes both tables to default bucket_count */ }
    void shrink_to_fit(); ///< reclaim memory (causes a rehash, invalidates iterators, pointers, etc)
    float load_factor() const { return (txDspsMap.load_factor() + dsproofs.load_factor()) / 2.f; }

    /// @returns the total number of TxHash <-> DSProof "links" or associations in this data-structure.
    std::size_t numTxDspLinks() const;

    bool operator==(const DSPs &o) const { return std::tie(txDspsMap, dsproofs) == std::tie(o.txDspsMap, o.dsproofs); }
    bool operator!=(const DSPs &o) const { return !(*this == o); }

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
    /// @returns false if dspHash does not exist, of if txHash is not 32 bytes, or if the txHash was already linked to
    ///     dspHash; true otherwise.
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

    /// @returns a pointer to the primary proof associated with a txHash, or the "best" proof if there is no primary.
    ///     A primary proof is a proof for the tx itself, rather than one of its ancestors. A "best" proof is one that
    ///     has the smallest descendants set containing txHash (and thus is likely "closest" in terms of ancestry to
    ///     txHash). If txHash has no proofs, nullptr is returned.
    ///
    ///     About primary proofs: Note that currently in BCHN, a tx may only have one and only 1 primary proof. However
    ///     nothing in these data structures enforces that. If a tx has more than one primary proof, only the first one
    ///     encountered in the internal set is returned.
    const DSProof * bestProofForTx(const TxHash &txHash) const;
};
