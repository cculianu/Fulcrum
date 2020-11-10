// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "feerate.h"
#include "txid.h"
#include "script.h"
#include "serialize.h"

#ifdef USE_QT_IN_BITCOIN
#include <QString>
#endif

#include <algorithm>

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

inline constexpr int SERIALIZE_TRANSACTION = 0x00;
// Added by Calin, imported from Core. Note in Core this flag has the *opposite* meaning
// (there it is called SERIALIZE_TRANSACTION_NO_WITNESS
inline constexpr int SERIALIZE_TRANSACTION_USE_WITNESS = 0x40000000;
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
    COutPoint() : txid(), n(-1) {}
    COutPoint(uint256 txidIn, uint32_t nIn) : txid(TxId(txidIn)), n(nIn) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(txid);
        READWRITE(n);
    }

    bool IsNull() const { return txid.IsNull() && n == uint32_t(-1); }

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

    std::string ToString() const;
#ifdef USE_QT_IN_BITCOIN
    /// construct it from a QString of "prevousHash:N" e.g.: "ab126fe4c....41ab6:3"
    COutPoint(const QString &prevoutColonNString) { SetQString(prevoutColonNString); }
    /// set this from a prevout:n string
    COutPoint &SetQString(const QString &s);
    /// construct from prevout:n string
    static COutPoint FromQString(const QString &s) { return COutPoint(s); }
    /// return prevoutHashHex:n string
    QString ToQString() const;
    /// support for *this = "prevouthash:n"
    COutPoint &operator=(const QString &s) { SetQString(s); return *this; }
#endif
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

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    }

    friend bool operator==(const CTxIn &a, const CTxIn &b) {
        return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

    std::string ToString() const;
};

/**
 * An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut {
public:
    Amount nValue;
    CScript scriptPubKey;

    CTxOut() { SetNull(); }

    CTxOut(Amount nValueIn, CScript scriptPubKeyIn)
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    }

    void SetNull() {
        nValue = -SATOSHI;
        scriptPubKey.clear();
    }

    bool IsNull() const { return nValue == -SATOSHI; }

    Amount GetDustThreshold(const CFeeRate &minRelayTxFee) const {
        /**
         * "Dust" is defined in terms of CTransaction::minRelayTxFee, which has
         * units satoshis-per-kilobyte. If you'd pay more than 1/3 in fees to
         * spend something, then we consider it dust. A typical spendable
         * non-segwit txout is 34 bytes big, and will need a CTxIn of at least
         * 148 bytes to spend: so dust is a spendable txout less than
         * 546*minRelayTxFee/1000 (in satoshis). A typical spendable segwit
         * txout is 31 bytes big, and will need a CTxIn of at least 67 bytes to
         * spend: so dust is a spendable txout less than 294*minRelayTxFee/1000
         * (in satoshis).
         */
        if (scriptPubKey.IsUnspendable()) {
            return Amount::zero();
        }

        size_t nSize = GetSerializeSize(*this, SER_DISK, 0);

        // the 148 mentioned above
        nSize += (32 + 4 + 1 + 107 + 4);

        return 3 * minRelayTxFee.GetFee(nSize);
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CTxOut &a, const CTxOut &b) {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) {
        return !(a == b);
    }

    std::string ToString() const;
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
 * - uint32_t nLockTime
 */
template <typename Stream, typename TxType>
inline void UnserializeTransaction(TxType &tx, Stream &s) {
    // MODIFIED BY CALIN -- To allow for deserializing SegWit blocks
    const bool fAllowWitness = s.GetVersion() & SERIALIZE_TRANSACTION_USE_WITNESS;
    unsigned char flags = 0;
    s >> tx.nVersion;
    tx.vin.clear();
    tx.vout.clear();
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
    // MODIFIED BY CALIN: Allow for SegWit support to be able to sync to BTC
    const bool fAllowWitness = s.GetVersion() & SERIALIZE_TRANSACTION_USE_WITNESS;

    s << tx.nVersion;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
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
    s << tx.nLockTime;
}

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction {
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

private:
    /** Memory only. */
    const uint256 hash;

    uint256 ComputeHash() const;
    uint256 ComputeWitnessHash() const;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction &tx);
    explicit CTransaction(CMutableTransaction &&tx);

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    /**
     * This deserializing constructor is provided instead of an Unserialize
     * method. Unserialize is not possible, since it would require overwriting
     * const fields.
     */
    template <typename Stream>
    CTransaction(deserialize_type, Stream &s)
        : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const { return vin.empty() && vout.empty(); }

    const TxId GetId() const { return TxId(hash); }
    const TxHash GetHash() const { return TxHash(hash); }
    /// added by Calin to avoid extra copying
    const uint256 &GetHashRef() const { return hash; }
    /// Added by Calin -- to support Core. Not cached, computed on-the-fly (this is not the case in Core code)
    const TxHash GetWitnessHash() const { return TxHash{ComputeWitnessHash()}; }

    // Return sum of txouts.
    Amount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs,
                           unsigned int nTxSize = 0) const;

    // Compute modified tx size for priority calculation (optionally given tx
    // size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize = 0) const;

    // Computes an adjusted tx size so that the UTXIs are billed partially
    // upfront.
    size_t GetBillableSize() const;

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction &a, const CTransaction &b) {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction &a, const CTransaction &b) {
        return a.hash != b.hash;
    }

    std::string ToString() const;

    /// Added by Calin to support Core
    bool HasWitness() const {
        return std::any_of(vin.begin(), vin.end(), [](const CTxIn & txin){ return !txin.scriptWitness.IsNull(); });
    }
};

/**
 * A mutable version of CTransaction.
 */
class CMutableTransaction {
public:
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    CMutableTransaction();
    CMutableTransaction(const CTransaction &tx);

    template <typename Stream> inline void Serialize(Stream &s) const {
        SerializeTransaction(*this, s);
    }

    template <typename Stream> inline void Unserialize(Stream &s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream &s) {
        Unserialize(s);
    }

    /**
     * Compute the id and hash of this CMutableTransaction. This is computed on
     * the fly, as opposed to GetId() and GetHash() in CTransaction, which uses
     * a cached result.
     */
    TxId GetId() const;
    TxHash GetHash() const;
    TxHash GetWitnessHash() const; ///< Added by Calin to support Core

    friend bool operator==(const CMutableTransaction &a,
                           const CMutableTransaction &b) {
        return a.GetId() == b.GetId();
    }

    /// Added by Calin to support Core
    bool HasWitness() const {
        return std::any_of(vin.begin(), vin.end(), [](const CTxIn & txin){ return !txin.scriptWitness.IsNull(); });
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
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
#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
