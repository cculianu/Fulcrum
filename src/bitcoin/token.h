// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "heapoptional.h"
#include "prevector.h"
#include "script.h"
#include "serialize.h"
#include "tinyformat.h"
#include "uint256.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <tuple>

namespace bitcoin {

/// This namespace captures the Token functionality for Bitcoin Cash.
/// See: CHIP-2022-02-CashTokens: Token Primitives for Bitcoin Cash
///      https://github.com/bitjson/cashtokens
namespace token {

// Declare serialization exceptions -- all of them inherit from std::ios_base::failure and are differentiated
// solely for our unit test vectors to catch specific failure reasons.
#define TOKEN_DECLARE_SER_EXC(name) \
    struct name : std::ios_base::failure { \
        using std::ios_base::failure::failure;  /* inherit c'tors */ \
        ~name() override; /* d'tor implemented in token.cpp file to prevent linker warnings on some platforms */ \
    }

TOKEN_DECLARE_SER_EXC(AmountOutOfRangeError);
TOKEN_DECLARE_SER_EXC(InvalidBitfieldError);
TOKEN_DECLARE_SER_EXC(AmountMustNotBeZeroError);
TOKEN_DECLARE_SER_EXC(CommitmentMustNotBeEmptyError);


/// Used as the first byte of the "wrapped" scriptPubKey to determine whether the output has token data
static constexpr uint8_t PREFIX_BYTE = opcodetype::SPECIAL_TOKEN_PREFIX;

/// A token Id is the identifier for a token (or "category" in spec terminology)
struct Id : uint256 {
    constexpr Id() noexcept : uint256() {}
    explicit constexpr Id(const uint256 &b) noexcept : uint256(b) {}
    explicit constexpr Id(Uninitialized_t u) noexcept : uint256(u) {}
};

/// High-order nibble of the token `bitfield` byte.  Describes what the structure of the token data payload that follows
/// is. These bitpatterns are bitwise-OR'd together to describe the data that follows in the token data payload.
/// This nibble may not be 0 or may not have the `Reserved` bit set.
enum class Structure : uint8_t {
    HasAmount = 0x10,           ///< The payload encodes an amount of fungible tokens.
    HasNFT = 0x20,              ///< The payload encodes a non-fungible token.
    HasCommitmentLength = 0x40, ///< The payload encodes a commitment-length and a commitment (HasNFT must also be set).

    Reserved = 0x80, ///< Must be unset.
};

/// Values for the low-order nibble of the token `bitfield` byte.  Must be `None` (0x0) for pure-fungible tokens.
/// Encodes the "permissions" that an NFT has.  Note that these 3 bitpatterns are the only acceptable values for this
/// nibble.
enum class Capability : uint8_t {
    None = 0x0,     ///< No capability – either a pure-fungible or a non-fungible token which is an immutable token.
    Mutable = 0x01, ///< The `mutable` capability – the encoded non-fungible token is a mutable token.
    Minting = 0x02, ///< The `minting` capability – the encoded non-fungible token is a minting token.
};

/// The NFT Commitment is a byte blob used to tag NFTs with data.
static constexpr size_t MAX_CONSENSUS_COMMITMENT_LENGTH = 40;

using NFTCommitmentBase = prevector<MAX_CONSENSUS_COMMITMENT_LENGTH, uint8_t>;

/// Implementation is essentially a prevector with 40 bytes preallocated, a custom lex-comparing operator<, and a custom
/// seriaizer that disallows (un)serialization of empties.
struct NFTCommitment : NFTCommitmentBase {
    using NFTCommitmentBase::NFTCommitmentBase;

    // We override prevector::operator< which does *not* do lexicographical comparison in favor of lex compare so that
    // the implementation of token::OutputData::operator< later in this file is easier on the eyes.
    bool operator<(const NFTCommitment &o) const {
        return std::lexicographical_compare(begin(), end(), o.begin(), o.end());
    }

    SERIALIZE_METHODS(NFTCommitment, obj) {
        // Read/write commitment as a standard prevector (CompactSize limited to 32MiB, followed by byte data)
        READWRITEAS(NFTCommitmentBase, obj);
        if (obj.empty()) {
            // As per spec, never (un)serialize an empty commitment (HasCommitmentLength bit controls presence/absence)
            throw CommitmentMustNotBeEmptyError("Serialized token commitment may not be empty");
        }
    }
};

/// SafeAmount leverages the `safeAdd` and `safeSub` functions from ScriptIntBase to detect overflow
struct SafeAmount : ScriptIntBase<SafeAmount> {
    using Base = ScriptIntBase<SafeAmount>;
    friend Base;

    SafeAmount() noexcept : SafeAmount(0) {}
    SafeAmount(const SafeAmount &) noexcept = default;
    SafeAmount & operator=(const SafeAmount &) noexcept = default;

    SERIALIZE_METHODS(SafeAmount, obj) {
        uint64_t val;
        SER_WRITE(obj, val = static_cast<uint64_t>(obj.value_));
        READWRITE(Using<CompactSizeFormatter<false /* no range check here */>>(val));
        if (val > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw AmountOutOfRangeError("Token amount out of range");
        } else if (val == 0u) {
            // as per spec, we refuse to (un)serialize an amount of `0`.
            throw AmountMustNotBeZeroError("Serialized token amount may not be 0");
        }
        SER_READ(obj, obj.value_ = static_cast<int64_t>(val));
    }

    // overrides base class, does additonal checks to disallow negative values
    static constexpr std::optional<SafeAmount> fromInt(int64_t x) noexcept {
        auto ret = Base::fromInt(x);
        if (ret && *ret < 0LL) ret.reset(); // all negative values are disallowed with this factory method
        return ret;
    }

private:
    explicit constexpr SafeAmount(int64_t x) noexcept : Base(x) {}
};

/// Data that gets serialized/deserialized to/from a scriptPubKey in a transaction output prefixed with PREFIX_BYTE
class OutputData {
    Id id;
    /// Token bitfield byte. High order nibble is one of the Structure enum values and low order nibble is Capability.
    uint8_t bitfield = 0;
    SafeAmount amount; ///< token amount (FT & NFT tokens). May not be negative.
    NFTCommitment commitment; ///< may be empty

public:
    OutputData() noexcept = default;
    OutputData(const Id &id_in, SafeAmount amt, const NFTCommitment &comm = {}, bool hasNFT = false,
               bool isMutableNFT = false, bool isMintingNFT = false, bool uncheckedNFT = false)
        : id(id_in) {
        SetAmount(amt, true);
        SetCommitment(comm, true);
        SetNFT(hasNFT, isMutableNFT, isMintingNFT, uncheckedNFT);
    }

    // Query bitfield
    uint8_t GetBitfieldByte() const { return bitfield; }
    Capability GetCapability() const { return static_cast<Capability>(bitfield & 0x0fu); }
    bool IsMintingNFT() const { return HasNFT() && GetCapability() == Capability::Minting; }
    //! Note that technically "Minting" also has the mutable capability, but in this low-level API we differentiate them
    bool IsMutableNFT() const { return HasNFT() && GetCapability() == Capability::Mutable; }
    bool IsImmutableNFT() const { return HasNFT() && GetCapability() == Capability::None; }
    bool IsFungibleOnly() const { return !HasNFT(); }
    bool HasNFT() const { return bitfield & uint8_t(Structure::HasNFT); }
    bool HasAmount() const { return bitfield & uint8_t(Structure::HasAmount); }
    bool HasCommitmentLength() const { return bitfield & uint8_t(Structure::HasCommitmentLength); }

    bool IsValidBitfield() const {
        // At least 1 bit must be set in the structure nibble, but the Structure::Reserved bit must not be set.
        if (const uint8_t s = bitfield & 0xf0u; s >= 0x80u || s == 0x00u) return false;
        // Capability nibble > 2 is invalid (that is, only valid bit-patterns for this nibble are: 0x00, 0x01, 0x02).
        if ((bitfield & 0x0fu) > 2u) return false;
        // A token prefix encoding no tokens (both HasNFT and HasAmount are unset) is invalid.
        if (!HasNFT() && !HasAmount()) return false;
        // A token prefix where HasNFT is unset must encode Capability nibble of 0x00.
        if (!HasNFT() && (bitfield & 0x0fu) != 0u) return false;
        // A token prefix encoding HasCommitmentLength without HasNFT is invalid.
        if (!HasNFT() && HasCommitmentLength()) return false;

        return true;
    }

    // Get Id, Amount & Commitment
    const Id & GetId() const { return id; }
    SafeAmount GetAmount() const { return amount; }
    const NFTCommitment & GetCommitment() const { return commitment; }

    // Setters: These should only be called when setting up CTxOuts for CMutableTransaction, and never on in-memory
    //          "Coin" instances e.g. from the coins cache.
    void SetId(const Id &idIn) { id = idIn; }
    void SetAmount(const SafeAmount &amt, bool autoSetBitfield = true) {
        amount = amt;
        if (autoSetBitfield) {
            bitfield = amount.getint64() != 0ll ? bitfield | uint8_t(Structure::HasAmount)
                                                : bitfield & ~uint8_t(Structure::HasAmount);
        }
    }
    void SetCommitment(const NFTCommitment &c, bool autoSetBitfield = true) {
        commitment = c;
        if (autoSetBitfield) {
            bitfield = !commitment.empty() ? bitfield | uint8_t(Structure::HasCommitmentLength)
                                           : bitfield & ~uint8_t(Structure::HasCommitmentLength);
        }
    }
    /// NB: param `unchecked` is for tests only and enforces no rules if true.
    void SetNFT(bool hasnft, bool ismutable = false, bool isminting = false, bool unchecked = false) {
        bitfield = hasnft ? (bitfield | uint8_t(Structure::HasNFT)) : (bitfield & ~uint8_t(Structure::HasNFT));
        if (!unchecked) {
            // enforce sanity if not using "unchecked" mode
            isminting = hasnft && isminting;
            ismutable = hasnft && ismutable && !isminting;
            bitfield &= 0xf0u; // clear low-order nibble now (will be set below)
        }
        bitfield = isminting ? bitfield | uint8_t(Capability::Minting) : (bitfield & ~uint8_t(Capability::Minting));
        bitfield = ismutable ? bitfield | uint8_t(Capability::Mutable) : (bitfield & ~uint8_t(Capability::Mutable));
    }

    /// Note: Supplied bitfield is *not* checked for correctness! (This is for tests only)
    void SetBitfieldUnchecked(uint8_t bf) { bitfield = bf; }

    SERIALIZE_METHODS(OutputData, obj) {
        READWRITE(obj.id); // 32-byte hash
        READWRITE(obj.bitfield);
        if ( ! obj.IsValidBitfield()) {
            throw InvalidBitfieldError(strprintf("Invalid token bitfield: 0x%02x", obj.bitfield));
        }

        if (obj.HasCommitmentLength()) {
            // This will throw if we are (un)serializing an empty vector. If the HasCommitmentLength bit is set, the
            // commitment itself cannot be empty
            READWRITE(obj.commitment);
        } else {
            // Skip commitment field if HasCommitment bit is not set, but ensure prevector is cleared if unserializing
            SER_READ(obj, obj.commitment.clear());
        }

        if (obj.HasAmount()) {
            READWRITE(obj.amount); // may throw if out of range, e.g. > INT64_MAX (negative), or if 0
        } else {
            // Skip amount field if HasAmount bit is not set, but ensure we clear it to 0 if unserializing
            SER_READ(obj, obj.amount = SafeAmount::fromInt(0).value());
        }
    }

    bool operator==(const OutputData &o) const {
        return amount == o.amount && bitfield == o.bitfield && id == o.id && commitment == o.commitment;
    }
    bool operator!=(const OutputData &o) const { return !this->operator==(o); }
    bool operator<(const OutputData &o) const {
        // Note this ordering is used for BIP69 sorting. See: https://github.com/bitjson/cashtokens
        return   std::tuple(  amount,   HasNFT(),   GetCapability(),   commitment,   id)
               < std::tuple(o.amount, o.HasNFT(), o.GetCapability(), o.commitment, o.id);
    }

    /// If fVerbose is true, print the full token id hex and commitment hex, otherwise print only the first
    /// 30 characters of each.
    std::string ToString(bool fVerbose = false) const;

    /// This is a rough estimate and actual size may be smaller in the average case or larger in some cases.
    static constexpr size_t EstimatedSerialSize() {
        return Id::size() + 1 /* bitfield */ + sizeof(int64_t) /* Amount */
                + 1 /* CompactSize */ + MAX_CONSENSUS_COMMITMENT_LENGTH;
    }

    /* Below three added by Calin */
    size_t GetSerialSize() const { return bitcoin::GetSerializeSize(*this); }
    size_t GetDynMemUsage() const { return commitment.capacity() > commitment.static_capacity() ? commitment.capacity() : 0u; }
    size_t GetMemSize() const { return sizeof(*this) + GetDynMemUsage(); }
};

using OutputDataPtr = HeapOptional<OutputData>;

/// A prevector intended to be used as a temporary byte blob object to which we serialize/unserialize the
/// tokenData + scriptPubKey before reading/writing it from/to a stream. It has considerable static (on-stack) size so
/// as to avoid allocations in the common case of: [PREFIX_BYTE token_data standard_spk].
using WrappedScriptPubKey = prevector<1 + OutputData::EstimatedSerialSize() + CScript::static_capacity(), uint8_t>;

/// Given a real scriptPubKey and token data, wrap the scriptPubKey into the "script + token data" blob
/// (which gets serialized to where the old txn format scriptPubKey used to live).
void WrapScriptPubKey(WrappedScriptPubKey &wspkOut, const OutputDataPtr &tokenData, const CScript &scriptPubKey,
                      int nVersion);

/// The inverse of the above. Note that a wrapped scriptPubKey may not respect the token format rules (out of range
/// amount, invalid capability byte, bad commitment length, etc), and if that happens this function will throw.
/// @throw if `throwIfUnparseableTokenData` is true, std::ios_base::failure, or one of its subclasses.
void UnwrapScriptPubKey(const WrappedScriptPubKey &wspk, OutputDataPtr &tokenDataOut, CScript &scriptPubKeyOut,
                        int nVersion, bool throwIfUnparseableTokenData = false /* set to true for (some) tests */);

extern thread_local std::optional<std::ios_base::failure> last_unwrap_exception; ///< used by tests

#undef TOKEN_DECLARE_SER_EXC

} // namespace token
} // namepsace bitcoin
