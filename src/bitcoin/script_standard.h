// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "pubkey.h"
#include "script_flags.h"
#include "uint256.h"

#include <cstdint>
#include <variant> // C++17, added by Calin as boost::variant work-alike

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

inline constexpr bool DEFAULT_ACCEPT_DATACARRIER = true;

class CKeyID;
class CScript;

/** A reference to a CScript: the Hash160 or Hash256 of its serialization (see script.h) */
class ScriptID {
    std::variant<uint160, uint256> var;
public:
    ScriptID() noexcept : var{uint160()} {}
    ScriptID(const CScript &in, bool is32);
    ScriptID(const uint160 &in) noexcept : var{in} {}
    ScriptID(const uint256 &in) noexcept : var{in} {}

    ScriptID & operator=(const uint160 &in) noexcept { var = in; return *this; }
    ScriptID & operator=(const uint256 &in) noexcept { var = in; return *this; }

    bool operator==(const ScriptID &o) const { return var == o.var; }
    bool operator<(const ScriptID &o) const { return var < o.var; }
    bool operator==(const uint160 &o) const { return IsP2SH_20() && std::get<uint160>(var) == o; }
    bool operator==(const uint256 &o) const { return IsP2SH_32() && std::get<uint256>(var) == o; }

    uint8_t *begin() { return std::visit([](auto &&alt) { return alt.begin(); }, var); }
    uint8_t *end() { return std::visit([](auto &&alt) { return alt.end(); }, var); }
    uint8_t *data() { return std::visit([](auto &&alt) { return alt.data(); }, var); }
    const uint8_t *begin() const { return const_cast<ScriptID *>(this)->begin(); }
    const uint8_t *end() const { return const_cast<ScriptID *>(this)->end(); }
    const uint8_t *data() const { return const_cast<ScriptID *>(this)->data(); }

    size_t size() const { return end() - begin(); }
    uint8_t & operator[](size_t i) { return data()[i]; }
    const uint8_t & operator[](size_t i) const { return data()[i]; }

    bool IsP2SH_20() const { return std::holds_alternative<uint160>(var); }
    bool IsP2SH_32() const { return  std::holds_alternative<uint256>(var); }
};

//!< bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
inline constexpr unsigned int MAX_OP_RETURN_RELAY = 223;
extern bool fAcceptDatacarrier;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static const uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC |
    SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL;

enum txnouttype {
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
};

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) {
        return true;
    }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) {
        return true;
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * ScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
using CTxDestination = std::variant<CNoDestination, CKeyID, ScriptID>;

const char *GetTxnOutputType(txnouttype t);
bool IsValidDestination(const CTxDestination &dest);

bool Solver(const CScript &scriptPubKey, txnouttype &typeRet,
            std::vector<std::vector<uint8_t>> &vSolutionsRet);
bool ExtractDestination(const CScript &scriptPubKey,
                        CTxDestination &addressRet);
bool ExtractDestinations(const CScript &scriptPubKey, txnouttype &typeRet,
                         std::vector<CTxDestination> &addressRet,
                         int &nRequiredRet);

CScript GetScriptForDestination(const CTxDestination &dest);
CScript GetScriptForRawPubKey(const CPubKey &pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
