// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

#include "pubkey.h"

#include <cassert>

#ifndef DISABLE_SECP256K1
#include "secp256k1/secp256k1.h"
#include "secp256k1/secp256k1_recovery.h"
#include "secp256k1/secp256k1_schnorr.h"
#else
// Added by Calin: if we aren't on a platform where our custom embedded secp256k1 is known to compile ok,
// then we will use a "fake" implementation that throws. This is ok since we don't actually use the functions
// that call into secp256k1 yet in Fulcrum.
#include "Common.h"
#include "tinyformat.h"
#include <stdexcept>
using secp256k1_context = void*;
using secp256k1_ecdsa_signature = void*;
using secp256k1_pubkey = void*;
using secp256k1_ecdsa_recoverable_signature = void*;
enum { SECP256K1_EC_UNCOMPRESSED, SECP256K1_EC_COMPRESSED, SECP256K1_CONTEXT_VERIFY };
#define THROW_UNIMPLEMENTED throw std::runtime_error(strprintf("%s is not compiled-in to %s on this platform", __func__, APPNAME))
#define UNIMPLEMENTED(func) void** func(...) { THROW_UNIMPLEMENTED; }
UNIMPLEMENTED(secp256k1_ecdsa_signature_parse_compact)
UNIMPLEMENTED(secp256k1_ecdsa_signature_normalize)
UNIMPLEMENTED(secp256k1_ec_pubkey_parse)
UNIMPLEMENTED(secp256k1_ecdsa_verify)
UNIMPLEMENTED(secp256k1_schnorr_verify)
UNIMPLEMENTED(secp256k1_ecdsa_recoverable_signature_parse_compact)
UNIMPLEMENTED(secp256k1_ecdsa_recover)
UNIMPLEMENTED(secp256k1_ec_pubkey_serialize)
UNIMPLEMENTED(secp256k1_ec_pubkey_tweak_add)
UNIMPLEMENTED(secp256k1_context_create)
UNIMPLEMENTED(secp256k1_context_destroy)
#endif

namespace bitcoin {
namespace {
/* Global secp256k1_context object used for verification. */
secp256k1_context *secp256k1_context_verify = nullptr;
} // namespace

/**
 * This function is taken from the libsecp256k1 distribution and implements DER
 * parsing for ECDSA signatures, while supporting an arbitrary subset of format
 * violations.
 *
 * Supported violations include negative integers, excessive padding, garbage at
 * the end, and overly long length descriptors. This is safe to use in Bitcoin
 * because since the activation of BIP66, signatures are verified to be strict
 * DER before being passed to this module, and we know it supports all
 * violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context *ctx,
                                         secp256k1_ecdsa_signature *sig,
                                         const uint8_t *input,
                                         size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    uint8_t tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

bool CPubKey::VerifyECDSA(const uint256 &hash,
                          const std::vector<uint8_t> &vchSig) const {
    if (!IsValid()) {
        return false;
    }

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, vch,
                                   size())) {
        return false;
    }
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig,
                                       vchSig.data(), vchSig.size())) {
        return false;
    }
    /**
     * libsecp256k1's ECDSA verification requires lower-S signatures, which have
     * not historically been enforced in Bitcoin, so normalize them first.
     */
    secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
    return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, hash.begin(),
                                  &pubkey);
}

bool CPubKey::VerifySchnorr(const uint256 &hash,
                            const std::vector<uint8_t> &vchSig) const {
    if (!IsValid()) {
        return false;
    }

    if (vchSig.size() != 64) {
        return false;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey,
                                   &(*this)[0], size())) {
        return false;
    }

    return secp256k1_schnorr_verify(secp256k1_context_verify, &vchSig[0],
                                    hash.begin(), &pubkey);
}

bool CPubKey::RecoverCompact(const uint256 &hash,
                             const std::vector<uint8_t> &vchSig) {
    if (vchSig.size() != COMPACT_SIGNATURE_SIZE) {
        return false;
    }

    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_verify, &sig, &vchSig[1], recid)) {
        return false;
    }
    if (!secp256k1_ecdsa_recover(secp256k1_context_verify, &pubkey, &sig,
                                 hash.begin())) {
        return false;
    }
    uint8_t pub[PUBLIC_KEY_SIZE];
    size_t publen = PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(
        secp256k1_context_verify, pub, &publen, &pubkey,
        fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    Set(pub, pub + publen);
    return true;
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid()) {
        return false;
    }
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, vch,
                                     size());
}

bool CPubKey::Decompress() {
    if (!IsValid()) {
        return false;
    }
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, vch,
                                   size())) {
        return false;
    }
    uint8_t pub[PUBLIC_KEY_SIZE];
    size_t publen = PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen,
                                  &pubkey, SECP256K1_EC_UNCOMPRESSED);
    Set(pub, pub + publen);
    return true;
}

bool CPubKey::Derive(CPubKey &pubkeyChild, ChainCode &ccChild,
                     unsigned int nChild, const ChainCode &cc) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(size() == COMPRESSED_PUBLIC_KEY_SIZE);
    uint8_t out[64];
    BIP32Hash(cc, nChild, *begin(), begin() + 1, out);
    memcpy(ccChild.begin(), out + 32, 32);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, vch,
                                   size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_verify, &pubkey,
                                       out)) {
        return false;
    }
    uint8_t pub[COMPRESSED_PUBLIC_KEY_SIZE];
    size_t publen = COMPRESSED_PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_verify, pub, &publen,
                                  &pubkey, SECP256K1_EC_COMPRESSED);
    pubkeyChild.Set(pub, pub + publen);
    return true;
}

void CExtPubKey::Encode(uint8_t code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code + 1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF;
    code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >> 8) & 0xFF;
    code[8] = (nChild >> 0) & 0xFF;
    memcpy(code + 9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
    memcpy(code + 41, pubkey.begin(), CPubKey::COMPRESSED_PUBLIC_KEY_SIZE);
}

void CExtPubKey::Decode(const uint8_t code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code + 1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code + 9, 32);
    pubkey.Set(code + 41, code + BIP32_EXTKEY_SIZE);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}

bool CPubKey::CheckLowS(const Span<const uint8_t> &vchSig) {
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig,
                                       vchSig.data(), vchSig.size())) {
        return false;
    }
    return (!secp256k1_ecdsa_signature_normalize(secp256k1_context_verify,
                                                 nullptr, &sig));
}

/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle() {
    if (refcount == 0) {
        assert(secp256k1_context_verify == nullptr);
        secp256k1_context_verify =
            secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        assert(secp256k1_context_verify != nullptr);
    }
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle() {
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_verify != nullptr);
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = nullptr;
    }
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
