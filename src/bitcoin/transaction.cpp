// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transaction.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

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

CMutableTransaction::CMutableTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout),
      nLockTime(tx.nLockTime), mw_blob(tx.mw_blob) {}

static uint256 ComputeCMutableTransactionHash(const CMutableTransaction &tx) {
    return SerializeHash(tx, SER_GETHASH, 0);
}

static uint256 ComputeCMutableTransactionWitnessHash(const CMutableTransaction &tx) {
    return SerializeHash(tx, SER_GETHASH, SERIALIZE_TRANSACTION_USE_WITNESS);
}

TxId CMutableTransaction::GetId() const {
    return TxId(ComputeCMutableTransactionHash(*this));
}

TxHash CMutableTransaction::GetHash() const {
    return TxHash(ComputeCMutableTransactionHash(*this));
}

TxHash CMutableTransaction::GetWitnessHash() const {
    return TxHash(ComputeCMutableTransactionWitnessHash(*this));
}

uint256 CTransaction::ComputeHash() const {
    return SerializeHash(*this, SER_GETHASH, 0);
}

uint256 CTransaction::ComputeWitnessHash() const {
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_USE_WITNESS);
}

/**
 * For backward compatibility, the hash is initialized to 0.
 * TODO: remove the need for this default constructor entirely.
 */
CTransaction::CTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0),
      mw_blob{}, hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx)
    : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout),
      nLockTime(tx.nLockTime), mw_blob(tx.mw_blob), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx)
    : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)),
      nLockTime(tx.nLockTime), mw_blob(std::move(tx.mw_blob)), hash(ComputeHash()) {}

Amount CTransaction::GetValueOut() const {
    Amount nValueOut = Amount::zero();
    for (const auto &tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut)) {
            throw std::runtime_error(std::string(__func__) +
                                     ": value out of range");
        }
    }
    return nValueOut;
}

template <typename TxType>
size_t GetTotalSizeCommon(const TxType &tx, bool segwit, bool mweb) {
    static_assert(std::is_same_v<TxType, CTransaction> || std::is_same_v<TxType, CMutableTransaction>);
    return GetSerializeSize(tx, PROTOCOL_VERSION
                                    | (segwit ? SERIALIZE_TRANSACTION_USE_WITNESS : 0)
                                    | (mweb ? SERIALIZE_TRANSACTION_USE_MWEB : 0));
}

size_t CTransaction::GetTotalSize(bool segwit, bool mweb) const { return GetTotalSizeCommon(*this, segwit, mweb); }
size_t CMutableTransaction::GetTotalSize(bool segwit, bool mweb) const { return GetTotalSizeCommon(*this, segwit, mweb); }

std::string CTransaction::ToString(bool fVerbose) const {
    const std::string::size_type cutoff = fVerbose ? std::string::npos : 10;
    std::string str;
    str += strprintf("CTransaction(txid=%s, ver=%d, vin.size=%u, vout.size=%u, "
                     "nLockTime=%u)\n",
                     GetId().ToString().substr(0, cutoff), nVersion, vin.size(),
                     vout.size(), nLockTime);
    for (const auto &nVin : vin) {
        str += "    " + nVin.ToString(fVerbose) + "\n";
    }
    for (const auto &nVout : vout) {
        str += "    " + nVout.ToString(fVerbose) + "\n";
    }
    return str;
}

} // end namespace bitcoin
#ifdef __clang__
#pragma clang diagnostic pop
#endif
