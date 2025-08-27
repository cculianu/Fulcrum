// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "transaction.h"
#include "pubkey.h"
#include "script.h"
#include "script_flags.h"
#include "sigencoding.h"
#include "uint256.h"

#include <cassert>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Wtautological-unsigned-enum-zero-compare"
#pragma clang diagnostic ignored "-Wstring-conversion"
#pragma clang diagnostic ignored "-Wunreachable-code-break"
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

namespace bitcoin {

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    //!< reference to the spending transaction (the one being serialized)
    const CTransaction &txTo;
    //!< output script being consumed
    const CScript &scriptCode;
    //!< input index of txTo being signed
    const unsigned int nIn;
    //!< container for hashtype flags
    const SigHashType sigHashType;

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn,
                                    const CScript &scriptCodeIn,
                                    unsigned int nInIn,
                                    SigHashType sigHashTypeIn)
        : txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
          sigHashType(sigHashTypeIn) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template <typename S> void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                nCodeSeparators++;
            }
        }
        bitcoin::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char *)&itBegin[0], it - itBegin - 1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end()) {
            s.write((char *)&itBegin[0], it - itBegin);
        }
    }

    /** Serialize an input of txTo */
    template <typename S> void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is
        // serialized
        if (sigHashType.hasAnyoneCanPay()) {
            nInput = nIn;
        }
        // Serialize the prevout
        bitcoin::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn) {
            // Blank out other inputs' signatures
            bitcoin::Serialize(s, CScript());
        } else {
            SerializeScriptCode(s);
        }
        // Serialize the nSequence
        if (nInput != nIn &&
            (sigHashType.getBaseType() == BaseSigHashType::SINGLE ||
             sigHashType.getBaseType() == BaseSigHashType::NONE)) {
            // let the others update at will
            bitcoin::Serialize(s, (int)0);
        } else {
            bitcoin::Serialize(s, txTo.vin[nInput].nSequence);
        }
    }

    /** Serialize an output of txTo */
    template <typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (sigHashType.getBaseType() == BaseSigHashType::SINGLE &&
            nOutput != nIn) {
            // Do not lock-in the txout payee at other indices as txin
           bitcoin ::Serialize(s, CTxOut());
        } else {
            bitcoin::Serialize(s, txTo.vout[nOutput]);
        }
    }

    /** Serialize txTo */
    template <typename S> void Serialize(S &s) const {
        // Serialize nVersion
        bitcoin::Serialize(s, txTo.nVersion);
        // Serialize vin
        unsigned int nInputs =
            sigHashType.hasAnyoneCanPay() ? 1 : txTo.vin.size();
        bitcoin::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++) {
            SerializeInput(s, nInput);
        }
        // Serialize vout
        unsigned int nOutputs =
            (sigHashType.getBaseType() == BaseSigHashType::NONE)
                ? 0
                : ((sigHashType.getBaseType() == BaseSigHashType::SINGLE)
                       ? nIn + 1
                       : txTo.vout.size());
        bitcoin::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++) {
            SerializeOutput(s, nOutput);
        }
        // Serialize nLockTime
        bitcoin::Serialize(s, txTo.nLockTime);
    }
};

uint256 GetPrevoutHash(const CTransaction &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (size_t n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (size_t n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction &txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (size_t n = 0; n < txTo.vout.size(); n++) {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

} // namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction &txTo) {
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
}

uint256 SignatureHash(const CScript &scriptCode, const CTransaction &txTo,
                      unsigned int nIn, SigHashType sigHashType,
                      const Amount amount,
                      const PrecomputedTransactionData *cache, uint32_t flags) {
    if (sigHashType.hasFork() && (flags & SCRIPT_ENABLE_SIGHASH_FORKID)) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;

        if (!sigHashType.hasAnyoneCanPay()) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!sigHashType.hasAnyoneCanPay() &&
            (sigHashType.getBaseType() != BaseSigHashType::SINGLE) &&
            (sigHashType.getBaseType() != BaseSigHashType::NONE)) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }

        if ((sigHashType.getBaseType() != BaseSigHashType::SINGLE) &&
            (sigHashType.getBaseType() != BaseSigHashType::NONE)) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        } else if ((sigHashType.getBaseType() == BaseSigHashType::SINGLE) &&
                   (nIn < txTo.vout.size())) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode +
        // amount). The prevout may already be contained in hashPrevout, and the
        // nSequence may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << scriptCode;
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << sigHashType;

        return ss.GetHash();
    }

    static const uint256 one(uint256S(
        "0000000000000000000000000000000000000000000000000000000000000001"));
    if (nIn >= txTo.vin.size()) {
        //  nIn out of range
        return one;
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((sigHashType.getBaseType() == BaseSigHashType::SINGLE) &&
        (nIn >= txTo.vout.size())) {
        //  nOut out of range
        return one;
    }

    // Wrapper to serialize only the necessary parts of the transaction being
    // signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, sigHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << sigHashType;
    return ss.GetHash();
}

bool BaseSignatureChecker::VerifySignature(const std::vector<uint8_t> &vchSig,
                                           const CPubKey &pubkey,
                                           const uint256 &sighash,
                                           uint32_t flags) const {
    if (vchSig.size() == 64) {
        return pubkey.VerifySchnorr(sighash, vchSig);
    } else {
        return pubkey.VerifyECDSA(sighash, vchSig);
    }
}

bool TransactionSignatureChecker::CheckSig(
    const std::vector<uint8_t> &vchSigIn, const std::vector<uint8_t> &vchPubKey,
    const CScript &scriptCode, uint32_t flags) const {
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid()) {
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    std::vector<uint8_t> vchSig(vchSigIn);
    if (vchSig.empty()) {
        return false;
    }
    SigHashType sigHashType = GetHashType(vchSig);
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, sigHashType, amount,
                                    this->txdata, flags);

    if (!VerifySignature(vchSig, pubkey, sighash, flags)) {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(
    const CScriptNum &nLockTime) const {
    // There are two kinds of nLockTime: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nLockTime <
    // LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nLockTime being tested is the same as the nLockTime in the
    // transaction.
    if (!((txTo->nLockTime < LOCKTIME_THRESHOLD &&
           nLockTime < LOCKTIME_THRESHOLD) ||
          (txTo->nLockTime >= LOCKTIME_THRESHOLD &&
           nLockTime >= LOCKTIME_THRESHOLD))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nLockTime > int64_t(txTo->nLockTime)) {
        return false;
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
    // nSequence to maxint. The transaction would be allowed into the
    // blockchain, making the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to prevent this condition.
    // Alternatively we could test all inputs, but testing just this input
    // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
    // execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence) {
        return false;
    }

    return true;
}

bool TransactionSignatureChecker::CheckSequence(
    const CScriptNum &nSequence) const {
    // Relative lock times are supported by comparing the passed in operand to
    // the sequence number of the input.
    const int64_t txToSequence = int64_t(txTo->vin[nIn].nSequence);

    // Fail if the transaction's version number is not set high enough to
    // trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2) {
        return false;
    }

    // Sequence numbers with their most significant bit set are not consensus
    // constrained. Testing that the transaction's sequence number do not have
    // this bit set prevents using this property to get around a
    // CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
        return false;
    }

    // Mask off any bits that do not have consensus-enforced meaning before
    // doing the integer comparisons
    const uint32_t nLockTimeMask =
        CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nSequenceMasked <
    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nSequenceMasked being tested is the same as the nSequenceMasked in the
    // transaction.
    if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
           nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nSequenceMasked > txToSequenceMasked) {
        return false;
    }

    return true;
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
