//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "BTC.h"
#include "Compat.h"

#include "bitcoin/cashaddrenc.h"  // for bitcoin::CashAddrType
#include "bitcoin/uint256.h"

#include <QByteArray>
#include <QMetaType>
#include <QString>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace BTC {
    struct Address
    {
        static constexpr std::size_t H160Len = bitcoin::uint160::width();

        enum Kind : Byte {
            Invalid = 0xff,
            P2PKH = bitcoin::CashAddrType::PUBKEY_TYPE,  // 0
            P2SH = bitcoin::CashAddrType::SCRIPT_TYPE    // 1
        };

        static constexpr Byte InvalidVerByte = 0xff;

        Address() noexcept = default;
        /// for the below 3 c'tors, the 'net' is auto-detected based on address.
        Address(const QString &legacyOrCashAddress) { *this = Address::fromString(legacyOrCashAddress); }
        Address(const char *legacyOrCashAddress) { *this = legacyOrCashAddress; }
        Address(const QByteArray &legacyOrCashAddress) { *this = legacyOrCashAddress; }

        static Address fromString(const QString &legacyOrCash); ///< auto-detects Net based on decoded address contents
        static Address fromPubKey(const Byte *pbegin, const Byte *pend, Kind, Net = MainNet);
        static Address fromPubKey(const QByteArray &pubKey, Kind kind, Net net = MainNet) { return fromPubKey(reinterpret_cast<const Byte *>(pubKey.constData()), reinterpret_cast<const Byte *>(pubKey.constData() + pubKey.length()), kind, net); }
        static Address fromPubKey(const std::vector<Byte> &pubKey, Kind kind, Net net = MainNet) { return fromPubKey(&*pubKey.begin(), &*pubKey.end(), kind, net); }

        const QByteArray & hash160() const noexcept { return h160; }

        Kind kind() const noexcept { return _kind; }
        Net net() const noexcept { return _net; }

        //! Returns true if this address is valid would be identical if encoded on network `net`.
        //! This is only true for TestNet, TestNet4, & ScaleNet which are interchangeable.
        bool isCompatibleWithNet(Net net) const;

        bool isTestNet() const noexcept { return _net == TestNet || _net == TestNet4; }
        bool isScaleNet() const noexcept { return _net == ScaleNet; }
        bool isRegTestNet() const noexcept { return _net == RegTestNet; }
        bool isMainNet() const noexcept { return _net == MainNet; }

        bool isValid() const noexcept {  return _kind != Kind::Invalid && h160.length() == H160Len && _net != Net::Invalid && verByte != InvalidVerByte; }

        /// test any string to see if it's a valid address for the specified network
        static bool isValid(const QString &legacyOrCashAddress, Net = MainNet);

        /// Returns the bitcoin script bytes as would be used in a spending transaction.
        /// for use with CTransaction et al in the txOut )
        bitcoin::CScript toCScript() const;
        /// Returns the bitcoin script bytes as would be used in a spending transaction,
        /// hashed once with sha256, as raw bytes. (in reversed memory order, as EX/Fulcrum would use for its HashX)
        QByteArray toHashX() const;

        /// If isValid, returns the address as a string (either cash address w/ prefix, or legacy address string).
        /// Returns an empty QString if !isValid.
        QString toString(bool legacy=false) const;

        /// If isValid, returns the address as a cash address string, without the bitcoincash: or bchtest:, etc, prefix.
        QString toShortString() const;

        /// Alias for toString(true)
        QString toLegacyString() const { return toString(true); }

        Address & operator=(const QString &legacyOrCash) { return (*this = Address::fromString(legacyOrCash)); }
        Address & operator=(const char *legacyOrCash) { return (*this = QString(legacyOrCash)); }
        Address & operator=(const QByteArray &legacyOrCash) { return (*this = QString(legacyOrCash)); }

        bool operator==(const Address & o) const noexcept { return !isValid() && !o.isValid() ? true : _net == o._net && verByte == o.verByte && _kind == o._kind && h160 == o.h160; }
        bool operator!=(const Address & o) const noexcept { return !(*this == o); }
        /// less operator: for map support and also so that it sorts like the text address would.
        /// All invalid addresses sort before valid ones.
        bool operator<(const Address & o) const noexcept {
            if (isValid() && o.isValid()) {
                // same h160, so compare net, verbyte, and kind
                const std::array<Byte, 3> a = { _net, verByte, _kind },
                                          b = { o._net, o.verByte, o._kind };
                int cmp = std::memcmp(a.data(), b.data(), 3); // first sort based on concatenation of: net + verbyte + kind bytes
                if (cmp == 0)
                    // next, sort based on h160
                    cmp = std::memcmp(h160.constData(), o.h160.constData(), std::min(size_t(h160.length()), size_t(o.h160.length())));
                return cmp < 0;
            }
            return int(isValid()) < int(o.isValid()); // invalid always sorts before valid
        }
        bool operator<=(const Address & o) const noexcept { return *this < o || *this == o; }
        bool operator>(const Address & o) const noexcept { return !(*this <= o); }
        bool operator>=(const Address & o) const noexcept { return *this > o || *this == o; }

    private:
        Net _net = BTC::Invalid;
        Byte verByte = InvalidVerByte;
        QByteArray h160;
        Kind _kind = Kind::Invalid;
        bool autosetKind();
#ifdef ENABLE_TESTS
    public:
        static bool test();
        static void bench();
#endif
    };

} // end namespace BTC

/// for std::hash support of type BTC::Address -- just take first 4/8 bytes of hash160
template <> struct std::hash<BTC::Address> {
    std::size_t operator()(const BTC::Address &a) const noexcept {
        if (a.isValid()) {
            // The below will produce a good value because isValid implies h160 length == 20
            return BTC::QByteArrayHashHasher{}(a.hash160());
        }
        // invalid will always hash to 0
        return 0;
    }
};

namespace BTC {
    /// for Qt QSet/QHash support of type BTC::Address (must be in BTC namespace for ADL lookup to work)
    inline Compat::qhuint qHash(const Address &key, Compat::qhuint seed = 0) {
        return ::qHash(std::hash<Address>{}(key), seed);
    }
} // namespace BTC

Q_DECLARE_METATYPE(BTC::Address);
