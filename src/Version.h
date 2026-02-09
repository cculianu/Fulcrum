//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "Common.h"

#include <QString>

#include <cstdint>
#include <tuple> // for std::tie

/* On some Linux setups, sys/sysmacros.h ends up here and clashes with these names. */
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif

/// A class that encapsulates a version, be it a protocol version or a bitcoind version. Basically something that
/// can compare "1.0" and "1.2.1" and come up with a lexical comparison (which is what the tuple can do, but if you
/// inherit from tuple you lose structured binding!) -- this is like a tuple basically, with added niceties like
/// defining an "invalid" version (0.0.0), and a .toString().  Can be used with C++17 structured binding, eg:
///     auto [major, minor, rev] = version;
struct Version
{
    unsigned major = 0, minor = 0, revision = 0;

    /// constructs an invalid version (0,0,0)
    constexpr Version() noexcept = default;

    constexpr Version(unsigned maj, unsigned min, unsigned rev) noexcept
        : major(maj), minor(min), revision(rev) {}

    /// used for c'tor that deserializes Bitcoin compact "version" field (CLIENT_VERSION)
    enum class BitcoinDCompact : std::uint32_t {};
    /// To explicitly construct an instance from the version number returned by bitcoind's getnetworkinfo RPC call
    /// e.g.: 200600 becomes -> 0.20.6. Possible usage syntax: Version v = Version::BitcoinDCompact(num);
    Version(BitcoinDCompact) noexcept;

    // unused
    //enum class BCHDCompact : std::uint32_t {};
    //Version(BCHDCompact) noexcept;

    /// Accepts e.g. "1.0" or "v1.7". Note that strings like "3.1.1.1" or "3.1.1CS" become "3,1,1"
    /// (extra stuff at the end is ignored).  An initial 'v' or 'V' character is also ok and simply ignored.
    /// Also note: If the string contains a '/' character, everything *after* the first '/' is parsed!
    Version(const QString & versionString);

    /// Returns the bitcoind compact representation (aka bitcoind CLIENT_VERSION representation).
    /// This is the inverse of the BitcoinDCompact c'tor. Note this can't store minor or revision fields >= 100.
    unsigned toCompact() const noexcept;

    /// back to e.g. "1.2.3".  Note that 1.0.0 is returned as simply "1.0" even if originally parsed from "1.0.0",
    /// unless alwaysIncludeRevEvenIfZero = true.
    QString toString(bool alwaysIncludeRevEvenIfZero = false) const;

    constexpr bool isValid() const noexcept { return major || minor || revision; }
    constexpr auto operator<=>(const Version & o) const noexcept = default;
};
