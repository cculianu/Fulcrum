//
// Fulcrum - A fast & nimble SPV Server for Electron Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

/* BTC-related functions and classes we wrote for an earlier project (ShuffleUp server) that we don't currently use
 * in this app's codebase, but we are keeping around in case we need them, or in case we want to use similar concepts.
 *
 * These all live in BTC_unused.cpp but are not exposed in the regular BTC.h
 */

#include "BTC.h"

#include <QList>
#include <QMetaType>
#include <QPair>

#include <algorithm>
#include <array>
#include <cstring>
#include <type_traits>
#include <vector>

namespace BTC {
    using Byte = uint8_t;

    /// Helper class to glue QByteArray (which is very fast and efficient due to copy-on-write)
    /// to bitcoin's std::vector usage.
    /// This class also allows expressions like: ByteArray a = { opcode1, opcode2 } + somebytearray + { moreopcodes };
    /// Or: byteArray << OP_CODE1 << OP_CODE2 << someVal << etc...
    /// NB: Do not use this to operate on C strings as they may not always be nul terminated. For that,
    /// use QByteArray or QString.
    struct ByteArray : public std::vector<Byte>
    {
        ByteArray();
        ByteArray(const std::vector<Byte> &);
        ByteArray(std::vector<Byte> &&);
        // TO DO: see about removing some of this boilerplate using either C++ subtleties or templates.
        ByteArray(const QByteArray &);
        ByteArray(const QString &);
        ByteArray(const char *s) { *this = s; } ///< Note: the nul byte is NOT copied into the buffer.
        ByteArray(const std::initializer_list<Byte> &);

        ByteArray toHex() const; ///< returns Hex encoded (non-reversed)
        QByteArray toQHex() const; ///< returns Hex encoded (non-reversed)
        QString toHexStr() const { return QString(toQHex()); } ///< returns Hex encoded (non-reversed)
        static ByteArray fromHex(const QString &); ///< construct from Hex encoded (non-reversed)

        /// Convenienct to obtain a pointer to [0]. If not empty, points to the same
        /// place as .begin().  If empty, will return a pointer to a static buffer
        /// with a 0 in it. Thus, a valid pointer is always returned.
        /// As such, don't rely on this to always == .begin() (it won't if empty)
        Byte *data(); ///< unsafe.
        const Byte* constData() const; ///< same notes as .data()

        /// convenience interop -- note that there may not be a nul byte at the end!
        char *charData() { return reinterpret_cast<char *>(data()); }
        /// convenience interop -- note that there may not be a nul byte at the end!
        const char *constCharData() const { return reinterpret_cast<const char *>(constData()); }

        // compat with Qt's int lengths
        int length() const { return int(size()); }
        // compat with QByteArray
        bool isEmpty() const { return empty(); }

        // TO DO: see about removing some of this boilerplate using either C++ subtleties or templates.
        ByteArray operator+(const std::vector<Byte> & o) const;
        ByteArray operator+(const QByteArray & o) const;
        ByteArray operator+(const QString &) const;
        ByteArray operator+(const char *s) const { return *this + QByteArray(s); }
        ByteArray operator+(const std::initializer_list<Byte> &) const;
        ByteArray & operator+=(const std::vector<Byte> & b);
        ByteArray & operator+=(const QByteArray &);
        ByteArray & operator+=(const QString &);
        ByteArray & operator+=(const std::initializer_list<Byte> &);
        ByteArray & operator+=(const char *s) { return *this += QByteArray(s); } ///< C-string terminating nul byte is NOT copied into the buffer!
        ByteArray & operator=(const std::vector<Byte> &o);
        ByteArray & operator=(const QByteArray &);
        ByteArray & operator=(const QString &);
        ByteArray & operator=(const std::initializer_list<Byte> &);
        ByteArray & operator=(const char *s) { return *this = QByteArray(s); }
        template <typename T>
        ByteArray & operator<<(const T &t) { return (*this) += t; }
        ByteArray & operator<<(bitcoin::opcodetype c) { return (*this) << Byte(c); } ///< append an op-code to this array
        ByteArray & operator<<(Byte c); ///< append any byte to this array
        operator QByteArray() const; ///< convenienct cast to QByteArray. Involves a full copy.
    };

    struct UTXO {
        static constexpr int validTxidLength = (256/8)*2; ///< any txid not of this length (64) is immediately invalid.
        static constexpr quint32 invalidN = 0xffffffff;
    protected:
        /// hex encoded uint256 hash of its tx. (64 characters). Do not set these directly, instead use operator= etc below.
        QString _txid;
        quint32 _n = invalidN;
    public:
        inline const QString & txid() const { return _txid; }
        inline quint32 n() const { return _n; }

        /// construct an invalid utxo
        UTXO() {}
        /// construct a UTXO from a bitcoin::COutPoint
        UTXO(const bitcoin::COutPoint &cop) { *this = cop; }
        /// if hash is not 256 bit encoded hex, will be inValid()
        UTXO(const QString & prevoutHash, quint32 prevoutN) { setCheck(prevoutHash, prevoutN); }
        /// if "hash:N" is not "256 bit encoded hex:UInt", will be inValid()
        UTXO(const QString & prevoutHash_Colon_N) { setCheck(prevoutHash_Colon_N); }

        inline bool isValid() const { return _txid.length() == validTxidLength && _n != invalidN; }
        inline UTXO & clear() { _txid = QString(); _n = invalidN; return *this; }

        /// assign from a bitcoin::COutPoint. Not terribly efficient but fast enough for now.
        inline UTXO & operator=(const bitcoin::COutPoint & c) { return *this = c.ToQString(); }
        /// parses prevouthash:N, if ok, sets class to valid state and saves values, otherwise class becomes invalid.
        inline UTXO & operator=(const QString &prevOutN) { return setCheck(prevOutN); }

        inline bool operator<(const UTXO &b) const {
            if (isValid() && b.isValid()) {
                if (int cmp = _txid.compare(b._txid); cmp < 0)
                    return true;
                else if (0==cmp)
                    return _n < b._n;
                //else ...
            }
            return false;
        }
        inline bool operator<=(const UTXO &b) const { return *this < b || *this == b; }
        inline bool operator==(const UTXO &o) const { return _n == o._n && _txid == o._txid; }
        inline bool operator!=(const UTXO &o) const { return !(*this == o); }

        /// will only accept if the hash is valid hex, otherwise will leave this class in "Invalid" state
        UTXO & setCheck(const QString &prevoutHash, quint32 n);
        UTXO & setCheck(const QString &prevoutHash_Colon_N);

        bitcoin::COutPoint toCOutPoint() const;
        /// convert to prevouthash:N, returns a null string if !isValid()
        QString toString() const;

        static void test();
    };

    /// for Qt QSet support of type UTXO
    inline uint qHash(const UTXO &key, uint seed = 0) {
        if (key.isValid())
            return ::qHash(QPair<quint32, quint32>(key.txid().left(8).toUInt(nullptr, 16) , key.n()), seed);
            //return key.txid().left(8).toUInt(nullptr, 16) + key.n();
        return 0;
    }

    /// Make a bitcoin unsigned tx. Returns the total amount sent (sum of outputs). Note that
    /// no enforcement is done to make sure the tx is sane, so be sure to pass valid UTXO and Address values,
    /// as well as amounts >= 546 sats.  If any of the UTXOs !.isValid or any of the addresses !.isValid,
    /// or any of the outputs are below 546 sats, the resulting tx is empty and 0 is returned.
    extern
    int64_t MakeUnsignedTransaction(bitcoin::CMutableTransaction & tx,
                                    const QList<UTXO> & inputs, const QList<QPair<Address, int64_t> > & outputs,
                                    quint32 nLockTime = 0, ///< nLockTime can by anything in the present or past, but 0 is a good historical default
                                    int nVersion = 1,// nVersion will be set to this. 1=most tx's in the universe 2=some bip68 stuff i don't understand. we'll do nVersion=1 to be compatible with EC
                                    quint32 nSequence = 0xfffffffe);  // Should not be 0xffffffff

    /// Verify a tx signature for a specific input.  Returns true on verification success, false otherwise.
    /// *errorString is set to explain what went wrong (if not nullptr).
    ///
    /// Note the tx's signature script (if any) for the specified input is not at all inspected.
    ///
    /// Instead, a new signature script is constructed from the signature and the
    /// passed-in pubKey.  It is assumed later, after VerifyTxSignature succeeds, that callers of this
    /// function will use the signature that passed to generate a new valid signature script.
    ///
    /// As a convenience, the last parameter, `sigScript_out` may be passed-in to receive the valid
    /// signature script.  (Is only set if this function returns true, however.)
    ///
    /// `nInput` is which input to apply the check to (0, 1, 2, etc), and
    /// `inputValSatoshis` is required; it is the original UTXO value of the coin in question.
    extern
    bool VerifyTxSignature(const bitcoin::CMutableTransaction & tx,
                           const ByteArray & signature, const ByteArray & pubKey,
                           uint nInput, int64_t inputValSatoshis,
                           QString *errorString = nullptr,
                           bitcoin::CScript * scriptSig_out = nullptr);

    namespace Tests {
        void SigCheck();
        void CashAddr();
        bool Addr();
        void TestBlock();
        void HexParsers(const QString &jsonDataFileName);
    }
} // end namespace BTC

// Note to self: If we ever want to use any of the types above in a signal/slot do this here:
//
//Q_DECLARE_METATYPE(BTC::Address);
//
// And then in some .cpp file as part of app init do:
//
//    qRegisterMetaType<BTC::Address>();
