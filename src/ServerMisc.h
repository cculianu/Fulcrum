//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
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

#include "Version.h"

#include <QString>

namespace ServerMisc
{
    constexpr const char * const HashFunction = "sha256";

    /// Used in various places to rejects old clients or incompatible peers. Currently 1.4 and 1.4.2 respectively.
    extern const Version MinProtocolVersion, MaxProtocolVersion;

    extern const QString AppVersion,  ///< in string form suitable for sending in protocol or banner e.g. "1.0"
                         AppSubVersion; ///< e.g. "Fulcrum 1.0"
}

