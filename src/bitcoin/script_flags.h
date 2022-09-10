// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

namespace bitcoin {

/** Script verification flags */
enum {
    SCRIPT_VERIFY_NONE = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    // Note: The Segwit Recovery feature is an exception to P2SH
    SCRIPT_VERIFY_P2SH = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a
    // checksig operation causes script failure. Evaluating a pubkey that is not
    // (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script
    // failure.
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script
    // failure (BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig
    // operation causes script failure
    // (BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S = (1U << 3),

    // Using a non-push operator in the scriptSig causes script failure
    // (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16,
    // OP_1NEGATE where possible, direct pushes up to 75 bytes, OP_PUSHDATA up
    // to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating any other
    // push causes the script to fail (BIP62 rule 3). In addition, whenever a
    // stack element is interpreted as a number, it must be of minimal length
    // (BIP62 rule 4).
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be a
    // mandatory flag applied to scripts in a block. NOPs that are not executed,
    // e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that only a single stack element remains after evaluation. This
    // changes the success criterion from "At least one stack element must
    // remain, and when interpreted as a boolean, it must be true" to "Exactly
    // one stack element must remain, and when interpreted as a boolean, it must
    // be true".
    // (BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    // Note: The Segwit Recovery feature is an exception to CLEANSTACK
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Do we accept signature using SIGHASH_FORKID
    //
    SCRIPT_ENABLE_SIGHASH_FORKID = (1U << 16),

    // The exception to CLEANSTACK and P2SH for the recovery of coins sent
    // to p2sh segwit addresses is not allowed.
    SCRIPT_DISALLOW_SEGWIT_RECOVERY = (1U << 20),

    // Whether to allow new OP_CHECKMULTISIG logic to trigger. (new multisig
    // logic verifies faster, and only allows Schnorr signatures)
    SCRIPT_ENABLE_SCHNORR_MULTISIG = (1U << 21),

    // Require the number of sigchecks in an input to satisfy a specific
    // bound, defined by scriptSig length.
    // Note: The Segwit Recovery feature is a (currently moot) exception to
    // VERIFY_INPUT_SIGCHECKS
    SCRIPT_VERIFY_INPUT_SIGCHECKS = (1U << 22),

    // A utility flag to decide whether we must enforce the per-tx consensus
    // sigcheck limit. It does not control the sigcheck limits in
    // policy/consensus.h .
    SCRIPT_ENFORCE_SIGCHECKS = (1U << 23),

    // Flag that allows us to determine if the script interpreter should allow
    // 64-bit integer arithmetic and the return of OP_MUL or use the previous
    // semantics.
    SCRIPT_64_BIT_INTEGERS = (1U << 24),

    // Native Introspection opcodes.
    SCRIPT_NATIVE_INTROSPECTION = (1U << 25),

    // Enable p2sh32 (uses OP_HASH256 rather than OP_HASH160)
    SCRIPT_ENABLE_P2SH_32 = (1U << 26),

    // Enable native tokens support, including all consensus rules & native
    // introspection op-codes related to them.
    SCRIPT_ENABLE_TOKENS = (1U << 27),
};

} // end namespace bitcoin
