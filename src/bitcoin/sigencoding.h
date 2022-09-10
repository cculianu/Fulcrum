// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "script_error.h"
#include "sighashtype.h"

#include <cstdint>
#include <vector>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

namespace bitcoin {

using valtype = std::vector<uint8_t>;

inline SigHashType GetHashType(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return SigHashType(0);
    }

    return SigHashType(vchSig[vchSig.size() - 1]);
}

/**
 * Check that the signature provided on some data is properly encoded.
 * Signatures passed to OP_CHECKDATASIG and its verify variant must be checked
 * using this function.
 */
bool CheckDataSignatureEncoding(const valtype &vchSig, uint32_t flags,
                                ScriptError *serror);

/**
 * Check that the signature provided to authentify a transaction is properly
 * encoded. Signatures passed to OP_CHECKSIG and its verify variant must be
 * checked using this function.
 */
bool CheckTransactionSignatureEncoding(const valtype &vchSig, uint32_t flags,
                                       ScriptError *serror);

/**
 * Check that the signature provided to authentify a transaction is properly
 * encoded ECDSA signature. Signatures passed to OP_CHECKMULTISIG and its verify
 * variant must be checked using this function.
 */
bool CheckTransactionECDSASignatureEncoding(const valtype &vchSig,
                                            uint32_t flags,
                                            ScriptError *serror);

/**
 * Check that the signature provided to authentify a transaction is properly
 * encoded Schnorr signature (or null). Signatures passed to the new-mode
 * OP_CHECKMULTISIG and its verify variant must be checked using this function.
 */
bool CheckTransactionSchnorrSignatureEncoding(const valtype &vchSig,
                                              uint32_t flags,
                                              ScriptError *serror);

/**
 * Check that a public key is encoded properly.
 */
bool CheckPubKeyEncoding(const valtype &vchPubKey, uint32_t flags,
                         ScriptError *serror);

} // end namespace bitcoin


#ifdef __clang__
#pragma clang diagnostic pop
#endif
