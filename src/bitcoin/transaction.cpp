// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <type_traits>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif
namespace bitcoin {

std::string COutPoint::ToString(bool fVerbose) const {
    const std::string::size_type cutoff = fVerbose ? std::string::npos : 10;
    return strprintf("COutPoint(%s, %u)", txid.ToString().substr(0, cutoff), n);
}

std::string CTxIn::ToString(bool fVerbose) const {
    const std::string::size_type cutoff = fVerbose ? std::string::npos : 24;
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString(fVerbose);
    if (prevout.IsNull()) {
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    } else {
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, cutoff));
    }
    if (nSequence != SEQUENCE_FINAL) {
        str += strprintf(", nSequence=%u", nSequence);
    }
    str += ")";
    return str;
}

std::string CTxOut::ToString(bool fVerbose) const {
    const std::string::size_type cutoff = fVerbose ? std::string::npos : 30;
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s%s)", nValue / COIN,
                     (nValue % COIN) / SATOSHI,
                     HexStr(scriptPubKey).substr(0, cutoff),
                     tokenDataPtr ? (" " + tokenDataPtr->ToString(fVerbose)) : "");
}

template <class Derived>
uint256 CTransactionBase<Derived>::ComputeHash(bool segwit) const {
    return SerializeHash(tx(), SER_GETHASH, segwit ? SERIALIZE_TRANSACTION_USE_WITNESS : 0);
}

template <class Derived>
size_t CTransactionBase<Derived>::GetTotalSize(const bool segwit, const bool mweb) const {
    return GetSerializeSize(tx(), PROTOCOL_VERSION
                                      | (segwit ? SERIALIZE_TRANSACTION_USE_WITNESS : 0)
                                      | (mweb ? SERIALIZE_TRANSACTION_USE_MWEB : 0));
}

template <class Derived>
size_t CTransactionBase<Derived>::GetVirtualSize(const std::optional<size_t> unstrippedSizeIfKnown) const {
    constexpr size_t WITNESS_SCALE_FACTOR = 4; // Taken from Core consensus/consensus.h, added by Calin here.

    // The weight = (stripped_size * 4) + witness_size formula, using only serialization with and without witness data.
    // As witness_size is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.

    size_t weight = tx().GetTotalSize(false, false) * (WITNESS_SCALE_FACTOR - 1); // stripped of segwit and/or mweb

    if (unstrippedSizeIfKnown.has_value()) {
        weight += *unstrippedSizeIfKnown;
    } else {
        weight += tx().GetTotalSize(true, true); // add unstripped size (include segwit and/or mweb data)
    }

    return weight / WITNESS_SCALE_FACTOR; // vsize = weight / 4
}

template <class Derived>
Amount CTransactionBase<Derived>::GetValueOut() const {
    const auto &vout = tx().vout;
    Amount nValueOut = Amount::zero();
    for (const auto &tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut)) {
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }
    return nValueOut;
}

template <class Derived>
std::string CTransactionBase<Derived>::ToString(bool fVerbose) const {
    const std::string::size_type cutoff = fVerbose ? std::string::npos : 10;
    const auto &me = tx();
    std::string str;
    const std::string classname = std::is_same_v<Derived, CMutableTransaction> ? "CMutableTransaction" : "CTransaction";
    str += strprintf("%s(txid=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
                     classname, me.GetId().ToString().substr(0, cutoff), me.nVersion, me.vin.size(),
                     me.vout.size(), me.nLockTime);
    for (const auto &nVin : me.vin) {
        str += "    " + nVin.ToString(fVerbose) + "\n";
    }
    for (const auto &nVout : me.vout) {
        str += "    " + nVout.ToString(fVerbose) + "\n";
    }
    return str;
}

// Explicit template instantiations (required)
template class CTransactionBase<CTransaction>;
template class CTransactionBase<CMutableTransaction>;


CMutableTransaction::CMutableTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}

CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), mw_blob(tx.mw_blob) {}

TxId CMutableTransaction::GetId() const { return TxId(ComputeHash(false)); }
TxHash CMutableTransaction::GetHash() const { return TxHash(ComputeHash(false)); }

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), mw_blob{}, hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), mw_blob(tx.mw_blob),
      hash(ComputeHash(false)) {}
CTransaction::CTransaction(CMutableTransaction &&tx)
    : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime),
      mw_blob(std::move(tx.mw_blob)), hash(ComputeHash(false)) {}

} // end namespace bitcoin
#ifdef __clang__
#pragma clang diagnostic pop
#endif
