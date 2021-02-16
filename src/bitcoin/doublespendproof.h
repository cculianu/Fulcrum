// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020-2021 Calin Culianu <calin.culianu@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_DSPROOF_DSPROOF_H
#define BITCOIN_DSPROOF_DSPROOF_H

#include "transaction.h"
#include "txid.h"
#include "script.h"
#include "serialize.h"

namespace bitcoin {

using DspId = uint256; ///< Originally was in dspid.h, declaration moved here.

class DoubleSpendProof
{
public:
    //! Limit for the size of a `pushData` vector below
    static constexpr size_t MaxPushDataSize = MAX_SCRIPT_ELEMENT_SIZE;

    //! Creates an empty DoubleSpendProof
    DoubleSpendProof() = default;

    //! Creates a DoubleSpendProof for tx1 and tx2 for the given prevout.
    //!
    //! Note that this will throw if tx1 or tx2 are invalid, contain invalid
    //! signatures, don't spend prevout, etc.
    //!
    //! Argument `txOut` is the actual previous outpoint's data (used for
    //! signature verification).  Specify nullptr here to disable signature
    //! verification (for unit tests).  If this argument is nullptr, the
    //! generated proof is not guaranteed valid since signatures aren't checked.
    //!
    //! Exceptions:
    //!     std::runtime_error if creation failed
    //!     std::invalid_argument if tx1.GetHash() == tx2.GetHash()
    //! (implemented in dsproof_create.cpp)
    // Note: removed by Calin as it's not needed in Fulcrum sources.
    //static DoubleSpendProof create(const CTransaction &tx1, const CTransaction &tx2,
    //                               const COutPoint &prevout, const CTxOut *txOut = nullptr);

    bool isEmpty() const;

    enum Validity {
        Valid,
        MissingTransaction,
        MissingUTXO,
        Invalid
    };

    const DspId & GetId() const { return m_hash; }

    const TxId & prevTxId() const { return m_outPoint.GetTxId(); }
    uint32_t prevOutIndex() const { return m_outPoint.GetN(); }
    const COutPoint & outPoint() const { return m_outPoint; }

    struct Spender {
        uint32_t txVersion = 0, outSequence = 0, lockTime = 0;
        uint256 hashPrevOutputs, hashSequence, hashOutputs;
        std::vector<std::vector<uint8_t>> pushData;
        bool operator==(const Spender &o) const {
            return txVersion == o.txVersion && outSequence == o.outSequence && lockTime == o.lockTime
                    && hashPrevOutputs == o.hashPrevOutputs && hashSequence == o.hashSequence && hashOutputs == o.hashOutputs
                    && pushData == o.pushData;
        }
        bool operator!=(const Spender &o) const { return !(*this == o); }
    };

    const Spender & spender1() const { return m_spender1; }
    const Spender & spender2() const { return m_spender2; }

    // old fashioned serialization.
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_outPoint);

        READWRITE(m_spender1.txVersion);
        READWRITE(m_spender1.outSequence);
        READWRITE(m_spender1.lockTime);
        READWRITE(m_spender1.hashPrevOutputs);
        READWRITE(m_spender1.hashSequence);
        READWRITE(m_spender1.hashOutputs);
        READWRITE(m_spender1.pushData);

        READWRITE(m_spender2.txVersion);
        READWRITE(m_spender2.outSequence);
        READWRITE(m_spender2.lockTime);
        READWRITE(m_spender2.hashPrevOutputs);
        READWRITE(m_spender2.hashSequence);
        READWRITE(m_spender2.hashOutputs);
        READWRITE(m_spender2.pushData);

        // Calculate and save hash (only necessary to do if we are deserializing)
        if (ser_action.ForRead())
            setHash();

        checkSanityOrThrow(); // this call added here by Calin
    }


    // -- Global enable/disable of the double spend proof subsystem.

    //! Returns true if this subsystem is enabled, false otherwise. The double spend proof subsystem can be disabled at
    //! startup by passing -doublespendproof=0 to bitcoind. Default is enabled.
    static bool IsEnabled() { return s_enabled; }

    //! Enable/disable the dsproof subsystem. Called by init.cpp at startup. Default is enabled. Note that this
    //! function is not thread-safe and should only be called once before threads are started to disable.
    static void SetEnabled(bool b) { s_enabled = b; }

    // Equality comparison supported
    bool operator==(const DoubleSpendProof &o) const {
        return m_outPoint == o.m_outPoint && m_spender1 == o.m_spender1 && m_spender2 == o.m_spender2
                && m_hash == o.m_hash;
    }
    bool operator!=(const DoubleSpendProof &o) const { return !(*this == o); }

private:
    COutPoint m_outPoint;           //! Serializable
    Spender m_spender1, m_spender2; //! Serializable

    DspId m_hash;                   //! In-memory only

    //! Recompute m_hash from serializable data members
    void setHash();

    /// Throws std::runtime_error if the proof breaks the sanity of:
    /// - isEmpty()
    /// - does not have exactly 1 pushData per spender vector
    /// - any pushData size >520 bytes
    /// Called from: `create()` and `validate()` (`validate()` won't throw but will return Invalid)
    void checkSanityOrThrow() const;

    //! Used by IsEnabled() and SetEnabled() static methods; default is: enabled (true)
    static bool s_enabled;
};

} // namespace bitcoin

#endif // BITCOIN_DSPROOF_DSPROOF_H
