// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "amount.h"
#include "litecoin_bits.h"
#include "script.h"
#include "serialize.h"
#include "token.h"
#include "txid.h"

#include <algorithm>
#include <optional>
#include <utility>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wshift-sign-overflow"
#endif

namespace bitcoin {
/**
 * Flags that is ORed into the protocol version to designate that a transaction
 * should be (un)serialized with or without out witness data.
 * Make sure that this does not collide with any of the values in `version.h`
 * or with `ADDRV2_FORMAT`.
 */

static constexpr int SERIALIZE_TRANSACTION = 0x00;
// Added by Calin, imported from Core. Note in Core this flag has the *opposite* meaning
// (there it is called SERIALIZE_TRANSACTION_NO_WITNESS
static constexpr int SERIALIZE_TRANSACTION_USE_WITNESS = 0x40000000;
// Added by Calin, imported from Litecoin. Note in Litecoin this flag has the *opposite* meaning
// (there it is called SERIALIZE_NO_MWEB
static constexpr int SERIALIZE_TRANSACTION_USE_MWEB = 0x20000000;
// Added by Calin to optionally enable/disbale token ser/deser (BCH-specific)
static constexpr int SERIALIZE_TRANSACTION_USE_CASHTOKENS = 0x10000000;

static_assert (sizeof(int) >= 4);

/**
 * An outpoint - a combination of a transaction hash and an index n into its
 * vout.
 */
class COutPoint {
private:
    TxId txid;
    uint32_t n;

public:
    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint() : txid(), n(NULL_INDEX) {}
    COutPoint(TxId txidIn, uint32_t nIn) : txid(txidIn), n(nIn) {}

    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.txid, obj.n); }

    bool IsNull() const { return txid.IsNull() && n == NULL_INDEX; }

    const TxId &GetTxId() const { return txid; }
    uint32_t GetN() const { return n; }

    friend bool operator<(const COutPoint &a, const COutPoint &b) {
        int cmp = a.txid.Compare(b.txid);
        return cmp < 0 || (cmp == 0 && a.n < b.n);
    }

    friend bool operator==(const COutPoint &a, const COutPoint &b) {
        return (a.txid == b.txid && a.n == b.n);
    }

    friend bool operator!=(const COutPoint &a, const COutPoint &b) {
        return !(a == b);
    }

    std::string ToString(bool fVerbose = false) const;
};

/**
 * An input of a transaction. It contains the location of the previous
 * transaction's output that it claims and a signature that matches the output's
 * public key.
 */
class CTxIn {
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    // Added by Calin:
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    /**
     * Setting nSequence to this value for every input in a transaction disables
     * nLockTime.
     */
    static constexpr uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /**
     * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
     * lock-time.
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
     * the relative lock-time has units of 512 seconds, otherwise it specifies
     * blocks with a granularity of 1.
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
     * extract that lock-time from the sequence field.
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /**
     * In order to use the same number of bits to encode roughly the same
     * wall-clock duration, and because blocks are naturally limited to occur
     * every 600s on average, the minimum granularity for time-based relative
     * lock-time is fixed at 512 seconds. Converting from CTxIn::nSequence to
     * seconds is performed by multiplying by 512 = 2^9, or equivalently
     * shifting up by 9 bits.
     */
    static constexpr int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn() { nSequence = SEQUENCE_FINAL; }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(),
                   uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(prevoutIn), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}
    CTxIn(TxId prevTxId, uint32_t nOut, CScript scriptSigIn = CScript(),
          uint32_t nSequenceIn = SEQUENCE_FINAL)
        : CTxIn(COutPoint(prevTxId, nOut), scriptSigIn, nSequenceIn) {}

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn &a, const CTxIn &b) {
        return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

    std::string ToString(bool fVerbose = false) const;
};

/**
 * An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut {
public:
    Amount nValue;
    CScript scriptPubKey;
    token::OutputDataPtr tokenDataPtr; ///< may be null (indicates no token data for this output)

    CTxOut() { SetNull(); }

    CTxOut(Amount nValueIn, const CScript &scriptPubKeyIn, const token::OutputDataPtr &tokenDataIn = {})
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn), tokenDataPtr(tokenDataIn) {}

    CTxOut(Amount nValueIn, const CScript &scriptPubKeyIn, token::OutputDataPtr &&tokenDataIn)
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn), tokenDataPtr(std::move(tokenDataIn)) {}

    SERIALIZE_METHODS(CTxOut, obj) {
        READWRITE(obj.nValue);
        const bool shortPath =
                // Caller doesn't want to *read* CashTokens, so short-circuit out by just reading all
                // remaining data into scriptPubKey. Note that this GetVersion check can only apply if
                // reading. If serializing we don't rely on GetVersion() at all but instead must check
                // whether obj.tokenDataPtr is not null and instead just serialize normally since
                // sometimes SER_GETHASH will pass 0 for GetVersion() here... :/
                (ser_action.ForRead() && !(s.GetVersion() & SERIALIZE_TRANSACTION_USE_CASHTOKENS))
                // fast-path for writing with no token data, just write out the scriptPubKey directly
                || (!ser_action.ForRead() && !obj.tokenDataPtr);
        if (shortPath) {
            READWRITE(obj.scriptPubKey);
            // If acturally reading, ensure tokenDataPtr is cleared to ensure proper object state
            SER_READ(obj, obj.tokenDataPtr.reset());
        } else {
            token::WrappedScriptPubKey wspk;
            SER_WRITE(obj, token::WrapScriptPubKey(wspk, obj.tokenDataPtr, obj.scriptPubKey, s.GetVersion()));
            READWRITE(wspk);
            SER_READ(obj, token::UnwrapScriptPubKey(wspk, obj.tokenDataPtr, obj.scriptPubKey, s.GetVersion()));
        }
    }

    void SetNull() {
        nValue = -SATOSHI;
        scriptPubKey.clear();
        tokenDataPtr.reset();
    }

    bool IsNull() const { return nValue == -SATOSHI; }

    bool HasUnparseableTokenData() const {
        return !tokenDataPtr && !scriptPubKey.empty() && scriptPubKey[0] == token::PREFIX_BYTE;
    }

    friend bool operator==(const CTxOut &a, const CTxOut &b) {
        return a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey && a.tokenDataPtr == b.tokenDataPtr;
    }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) {
        return !(a == b);
    }

    std::string ToString(bool fVerbose = false) const;
};

class CMutableTransaction;

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CTxWitness wit;
 * - if (flags & 8):
 *   - MWEB::Tx (Litecoin only)
 * - uint32_t nLockTime
 */
template <typename Stream, typename TxType>
inline void UnserializeTransaction(TxType &tx, Stream &s) {
    // MODIFIED BY CALIN -- To allow for deserializing SegWit blocks as well as LTC MimbleWimble data
    const bool fAllowWitness = s.GetVersion() & SERIALIZE_TRANSACTION_USE_WITNESS;
    const bool fAllowMimble = s.GetVersion() & SERIALIZE_TRANSACTION_USE_MWEB;
    unsigned char flags = 0;
    s >> tx.nVersion;
    tx.vin.clear();
    tx.vout.clear();
    tx.mw_blob.reset();
    /* Try to read the vin. In case the dummy is there, this will be read as an
     * empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if (flags & 1 && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        bool hasWitness = false;
        for (auto &txin : tx.vin) {
            s >> txin.scriptWitness.stack;
            hasWitness = hasWitness || !txin.scriptWitness.stack.empty(); // added by Calin as a perf. improvement
        }
        if (!hasWitness) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags & 0x8 && fAllowMimble) {
        /* mweb data, Litecoin only.  We don't really process it, we just slurp up the binarry data for eventual
           serialization later. */
        flags ^= 0x8;
        tx.mw_blob = litecoin_bits::EatTxMimbleBlob(tx, s);
    }

    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template <typename Stream, typename TxType>
inline void SerializeTransaction(const TxType &tx, Stream &s) {
    /* // Original code:
    s << tx.nVersion;
    s << tx.vin;
    s << tx.vout;
    s << tx.nLockTime;*/
    // MODIFIED BY CALIN: Allow for SegWit support to be able to sync to BTC, as well as MimbleWimble for LTC
    const bool fAllowWitness = s.GetVersion() & SERIALIZE_TRANSACTION_USE_WITNESS;
    const bool fAllowMimble = s.GetVersion() & SERIALIZE_TRANSACTION_USE_MWEB;

    s << tx.nVersion;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (fAllowMimble) {
        // Litecoin only
        if (tx.mw_blob && !tx.mw_blob->empty()) {
            flags |= 0x8;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        const std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (const auto &txin : tx.vin)
            s << txin.scriptWitness.stack;
    }
    if (flags & 8) {
        // Litecoin only: write mimble-wimble data blob back out
        s.write(reinterpret_cast<const char *>(tx.mw_blob->data()), tx.mw_blob->size());
    }
    s << tx.nLockTime;
}

/**
 * A CRTP-based refactor by Calin to unify common methods and other logic here for both CTransaction and CMutableTransaction.
 */
template <class Derived>
class CTransactionBase {
    const Derived &tx() const { return *static_cast<const Derived *>(this); }

protected:
    uint256 ComputeHash(bool segwit = false) const;
    uint256 ComputeWitnessHash() const { return ComputeHash(true); }

public:
    template <typename Stream>
    void Serialize(Stream &s) const { SerializeTransaction(tx(), s); }

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes, with or without segwit and/or mweb data included
     */
    size_t GetTotalSize(bool segwit = false, bool mweb = false) const;

    // Added by Calin to calculate virtual size for a SegWit txn which is: (3 * stripped_size + total_size) / 4
    size_t GetVirtualSize(std::optional<size_t> unstrippedSizeIfKnown = std::nullopt) const;

    friend bool operator==(const Derived &a, const Derived &b) { return a.GetId() == b.GetId(); }
    friend bool operator!=(const Derived &a, const Derived &b) { return !(a == b); }

    bool IsNull() const { return tx().vin.empty() && tx().vout.empty(); }
    bool IsCoinBase() const { return tx().vin.size() == 1 && tx().vin[0].prevout.IsNull(); }

    // Return sum of txouts.
    Amount GetValueOut() const;
    // Note: GetValueIn() is a method on CCoinsViewCache, because inputs must be known to compute value in.

    /// Added by Calin to support Core
    bool HasWitness() const {
        return std::any_of(tx().vin.begin(), tx().vin.end(), [](const CTxIn & txin){ return !txin.scriptWitness.IsNull(); });
    }

    /// Added by Calin -- to support Core. Not cached, computed on-the-fly (this is not the case in Core code)
    TxHash GetWitnessHash() const { return TxHash{ComputeWitnessHash()}; }

    /// Added by Calin to support Litecoin
    bool HasMimble() const { return static_cast<bool>(tx().mw_blob); }
    /// Litecoin only: "IsHogEx" is defined as an "IsNull" but present mimble blob. This tells the block
    /// deserializer later to deserialize mimble block extention data at the end of the CBlock stream.
    bool IsHogEx() const { return HasMimble() && tx().mw_blob->size() == 1 && tx().mw_blob->front() == 0; }
    bool IsMWEBOnly() const { return HasMimble() && tx().mw_blob->size() > 1 && IsNull(); }

    std::string ToString(bool fVerbose = false) const;
};

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction : public CTransactionBase<CTransaction> {
public:
    // Default transaction version.
    static constexpr int32_t CURRENT_VERSION = 2;

    // Changing the default transaction version requires a two step process:
    // first adapting relay policy by bumping MAX_STANDARD_VERSION, and then
    // later date bumping the default CURRENT_VERSION at which point both
    // CURRENT_VERSION and MAX_STANDARD_VERSION will be equal.
    static constexpr int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;

    const litecoin_bits::MimbleBlobPtr mw_blob; //! Litecoin only

private:
    /** Memory only. */
    const uint256 hash;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);
    explicit CTransaction(CMutableTransaction &&tx);

    /**
     * This deserializing constructor is provided instead of an Unserialize
     * method. Unserialize is not possible, since it would require overwriting
     * const fields.
     */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    const TxId GetId() const { return TxId(hash); }
    const TxHash GetHash() const { return TxHash(hash); }
    /// added by Calin to avoid extra copying
    const uint256 &GetHashRef() const { return hash; }
    // See: base class GetWitnessHash() for an additional getter...
};

/**
 * A mutable version of CTransaction.
 */
class CMutableTransaction : public CTransactionBase<CMutableTransaction> {
public:
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    litecoin_bits::MimbleBlobPtr mw_blob; //! Litecoin only

    CMutableTransaction();
    CMutableTransaction(const CTransaction &tx);

    template <typename Stream>
    void Unserialize(Stream &s) { UnserializeTransaction(*this, s); }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s) { Unserialize(s); }

    /**
     * Compute the id and hash of this CMutableTransaction. This is computed on
     * the fly, as opposed to GetId() and GetHash() in CTransaction, which uses
     * a cached result.
     */
    TxId GetId() const;
    TxHash GetHash() const;
    // See: base class GetWitnessHash() for an additional getter...
};

using CTransactionRef = std::shared_ptr<const CTransaction>;
static inline CTransactionRef MakeTransactionRef() {
    return std::make_shared<const CTransaction>();
}
template <typename Tx>
static inline CTransactionRef MakeTransactionRef(Tx &&txIn) {
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}

/** Precompute sighash midstate to avoid quadratic hashing */
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;

    PrecomputedTransactionData()
        : hashPrevouts(), hashSequence(), hashOutputs() {}

    PrecomputedTransactionData(const PrecomputedTransactionData &txdata)
        : hashPrevouts(txdata.hashPrevouts), hashSequence(txdata.hashSequence),
          hashOutputs(txdata.hashOutputs) {}

    explicit PrecomputedTransactionData(const CTransaction &tx);
};

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
