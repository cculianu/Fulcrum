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

#include "Version.h"

#include <QString>

namespace ServerMisc
{
    inline constexpr auto HashFunction = "sha256";

    /// Used in various places to rejects old clients or incompatible peers. Currently 1.4 and 1.5.0 respectively.
    extern const Version MinProtocolVersion, MaxProtocolVersion;
    /// The first version where we expect clients to be "token aware" and thus we return token_data to them by default
    /// in e.g. listunspent and get_balance: 1.4.6
    extern const Version MinTokenAwareProtocolVersion;

    extern const QString AppVersion,  ///< in string form suitable for sending in protocol or banner e.g. "1.0"
                         AppSubVersion; ///< e.g. "Fulcrum 1.0"

    /// The amount of time we wait before initiating auto-kick when the globalSubsLimitReached signal has been asserted by a Server instance.
    inline constexpr double kMaxSubsAutoKickDelaySecs = 0.25;
    /// The rate limit for suppression of dupe global "max subs" warnings to log.
    inline constexpr double kMaxSubsWarningsRateLimitSecs = 0.251;
    /// The rate limit for suppression of dupe per-IP "max subs" warnings to log.
    inline constexpr double kMaxSubsPerIPWarningsRateLimitSecs = 1.0;
    /// The rate limit for suppression of dupe per-IP "connection limit exceeded" warnings to log.
    inline constexpr double kMaxClientsPerIPWarningRateLimitSecs = 5.0;
    /// This key is used in the stats() map for each Server instance to save bloom filter info
    inline constexpr auto kBloomFiltersKey = "bloom filters";
}

