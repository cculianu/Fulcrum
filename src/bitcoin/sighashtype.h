// Copyright (c) 2017-2018 Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "serialize.h"

#include <cstdint>
#include <stdexcept>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif

namespace bitcoin {

/** Signature hash types/flags */
enum {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_UTXOS = 0x20, ///< New in Upgrade9 (May 2023), must only be accepted if flags & SCRIPT_ENABLE_TOKENS
    SIGHASH_FORKID = 0x40,
    SIGHASH_ANYONECANPAY = 0x80,
};

/**
 * Base signature hash types
 * Base sig hash types not defined in this enum may be used, but they will be
 * represented as UNSUPPORTED.  See transaction
 * c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73 for an
 * example where an unsupported base sig hash of 0 was used.
 */
enum class BaseSigHashType : uint8_t {
    UNSUPPORTED = 0,
    ALL = SIGHASH_ALL,
    NONE = SIGHASH_NONE,
    SINGLE = SIGHASH_SINGLE
};

/** Signature hash type wrapper class
 *
 * Be very careful with modifying/using this class, as it contains a big footgun
 * regarding the bit 0x20.
 * (see https://github.com/mit-dci/cash-disclosure/blob/master/bitcoin-cash-disclosure-04252018.txt )
 */
class SigHashType {
private:
    uint32_t sigHash;

public:
    explicit SigHashType() : sigHash(SIGHASH_ALL) {}

    explicit SigHashType(uint32_t sigHashIn) : sigHash(sigHashIn) {}

    // "base type" here refers to the lower FIVE bits of sighash
    SigHashType withBaseType(BaseSigHashType baseSigHashType) const {
        return SigHashType((sigHash & ~0x1f) | uint32_t(baseSigHashType));
    }

    SigHashType withFork(bool fork = true) const {
        return SigHashType((sigHash & ~SIGHASH_FORKID) |
                           (fork ? SIGHASH_FORKID : 0));
    }

    SigHashType withAnyoneCanPay(bool anyoneCanPay = true) const {
        return SigHashType((sigHash & ~SIGHASH_ANYONECANPAY) |
                           (anyoneCanPay ? SIGHASH_ANYONECANPAY : 0));
    }

    SigHashType withUtxos(bool utxos = true) const {
        return SigHashType((sigHash & ~SIGHASH_UTXOS) | (utxos ? SIGHASH_UTXOS : 0));
    }

    // "base type" here refers to the lower FIVE bits of sighash
    BaseSigHashType getBaseType() const {
        return BaseSigHashType(sigHash & 0x1f);
    }

    bool isDefined() const {
        const uint8_t validShFlags = SIGHASH_FORKID | SIGHASH_ANYONECANPAY | SIGHASH_UTXOS;
        // "base type" here refers to lower SIX bits of sighash
        const auto baseType = BaseSigHashType(sigHash & ~validShFlags);
        // If resulting value is anything other than 1, 2, or 3, it's not defined
        return baseType >= BaseSigHashType::ALL && baseType <= BaseSigHashType::SINGLE;
    }

    bool hasFork() const { return (sigHash & SIGHASH_FORKID) != 0; }

    bool hasAnyoneCanPay() const {
        return (sigHash & SIGHASH_ANYONECANPAY) != 0;
    }

    bool hasUtxos() const { return sigHash & SIGHASH_UTXOS; }

    uint32_t getRawSigHashType() const { return sigHash; }

    template <typename Stream> void Serialize(Stream &s) const {
        bitcoin::Serialize(s, getRawSigHashType());
    }

    template <typename Stream> void Unserialize(Stream &s) {
        bitcoin::Unserialize(s, sigHash);
    }

    /**
     * Handy operators.
     */
    friend constexpr bool operator==(const SigHashType &a,
                                     const SigHashType &b) {
        return a.sigHash == b.sigHash;
    }

    friend constexpr bool operator!=(const SigHashType &a,
                                     const SigHashType &b) {
        return !(a == b);
    }
};

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
