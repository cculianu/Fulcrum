//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "BTC.h" // for BTC::QByteArrayHashHasher

#include "bitcoin/amount.h"  // for bitcoin::Amount
#include "bitcoin/uint256.h"

#include <QByteArray>

#include <limits>

using HashHasher = BTC::QByteArrayHashHasher;

using BlockHeight = std::uint32_t;
using TxNum = std::uint64_t; ///< this is used by the storage subsystem and also CompactTXO
using IONum = std::uint32_t;
inline constexpr IONum IONum16Max = std::numeric_limits<std::uint16_t>::max(); ///< IONums beyond this value get serialized as 3 bytes
inline constexpr IONum IONumMax = (IONum(0x1) << 24) - 1; ///< support up to 24-bit IONum
inline constexpr TxNum TxNumMax = (TxNum(0x1) << 48) - 1; ///< support up to 48-bit TxNum
using TxHash = QByteArray;
using HashX = QByteArray; ///< Note that despite the name, unlike in ElectrumX/ElectronX, our "HashX" is always the full 32-byte sha256 hash.
using BlockHash = QByteArray;
inline constexpr int HashLen = bitcoin::uint256::width();

