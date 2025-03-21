//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <array>
#include <compare>
#include <cstring>
#include <optional>
#include <tuple>
#include <vector>

namespace BTC {
    struct Address
    {
        static constexpr std::size_t H160Len = bitcoin::uint160::size();
        static constexpr std::size_t H256Len = bitcoin::uint256::size();

        enum Kind : Byte {
            Invalid = 0xff,
            P2PKH = bitcoin::CashAddrType::PUBKEY_TYPE,             // 0
            P2SH = bitcoin::CashAddrType::SCRIPT_TYPE,              // 1
            TOKEN_P2PKH = bitcoin::CashAddrType::TOKEN_PUBKEY_TYPE, // 2
            TOKEN_P2SH = bitcoin::CashAddrType::TOKEN_SCRIPT_TYPE,  // 3
        };

        static constexpr Byte InvalidVerByte = 0xff;

        Address() noexcept = default;
        /// for the below 3 c'tors, the 'net' is auto-detected based on address.
        Address(const QString &legacyOrCashAddress) { *this = Address::fromString(legacyOrCashAddress); }
        Address(const char *legacyOrCashAddress) { *this = legacyOrCashAddress; }
        Address(const QByteArray &legacyOrCashAddress) { *this = legacyOrCashAddress; }

        static Address fromString(const QString &legacyOrCash); ///< auto-detects Net based on decoded address contents
        /// Note that for fromPubKey, kind must be P2PKH or TOKEN_P2PKH
        static Address fromPubKey(const Byte *pbegin, const Byte *pend, Kind, Net = MainNet);
        static Address fromPubKey(const QByteArray &pubKey, Kind kind, Net net = MainNet) { return fromPubKey(reinterpret_cast<const Byte *>(pubKey.constData()), reinterpret_cast<const Byte *>(pubKey.constData() + pubKey.length()), kind, net); }
        static Address fromPubKey(const std::vector<Byte> &pubKey, Kind kind, Net net = MainNet) { return fromPubKey(&*pubKey.begin(), &*pubKey.end(), kind, net); }

        const QByteArray & hash() const noexcept { return _hash; }

        Kind kind() const noexcept { return _kind; }
        Net net() const noexcept { return _net; }

        //! Returns true if this address is valid would be identical if encoded on network `net`.
        //! This is only true for TestNet, TestNet4, & ScaleNet which are interchangeable.
        bool isCompatibleWithNet(Net net) const;

        bool isTestNet() const noexcept { return _net == TestNet || _net == TestNet4; }
        bool isChipNet() const noexcept { return _net == ChipNet; }
        bool isScaleNet() const noexcept { return _net == ScaleNet; }
        bool isRegTestNet() const noexcept { return _net == RegTestNet; }
        bool isMainNet() const noexcept { return _net == MainNet; }

        bool isValid() const noexcept {
            return _kind != Kind::Invalid && (_hash.length() == H160Len || _hash.length() == H256Len)
                    && _net != Net::Invalid && verByte != InvalidVerByte;
        }

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
        QString toString(bool legacy=false) const { return toString(legacy, std::nullopt); }

        /// If isValid, returns the address as a cash address string, without the bitcoincash: or bchtest:, etc, prefix.
        QString toShortString() const;

        /// Alias for toString(true)
        QString toLegacyString() const { return toString(true); }

        /// Hack to support converting any address to LTC TODO: Proper support for LTC addresses
        QString toLitecoinString() const;

        Address & operator=(const QString &legacyOrCash) { return (*this = Address::fromString(legacyOrCash)); }
        Address & operator=(const char *legacyOrCash) { return (*this = QString(legacyOrCash)); }
        Address & operator=(const QByteArray &legacyOrCash) { return (*this = QString(legacyOrCash)); }

        /// Comparison operator: for map support and also so that it sorts like the text address would.
        /// All invalid addresses sort before valid ones.
        auto operator<=>(const Address & o) const noexcept {
            if (isValid() && o.isValid()) {
                // lex-compare using 3-way tuple compare
                return std::tie(_net, verByte, _kind, _hash) <=> std::tie(o._net, o.verByte, o._kind, o._hash);
            } else if (const int vdiff = int(isValid()) - int(o.isValid()); vdiff < 0) {
                // invalid always sorts before valid
                return std::strong_ordering::less;
            } else if (vdiff > 0) {
                // we are valid, other is not, so we are greater
                return std::strong_ordering::greater;
            }
            // both invalid, all invalids are equal
            return std::strong_ordering::equal;
        }

        bool operator==(const Address & o) const noexcept { return this->operator<=>(o) == 0; }

    private:
        Net _net = BTC::Invalid;
        Byte verByte = InvalidVerByte;
        QByteArray _hash; // this holds either a p2pkh, p2sh, or a p2sh_32 payload
        Kind _kind = Kind::Invalid;
        bool autosetKind();

        QString toString(bool legacy, std::optional<Byte> verByteOverride) const;

#ifdef ENABLE_TESTS
    public:
        static bool test();
        static void bench();
#endif
    };

} // end namespace BTC

/// for std::hash support of type BTC::Address -- just take middle 4 or 8 bytes of a.hash()
template <> struct std::hash<BTC::Address> {
    std::size_t operator()(const BTC::Address &a) const noexcept {
        if (a.isValid()) {
            // The below will produce a good value because isValid implies hash() length is 20 or 32
            return BTC::QByteArrayHashHasher{}(a.hash());
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
