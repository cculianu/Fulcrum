#pragma once

#include "BTC.h" // for BTC::QByteArrayHashHasher

#include "bitcoin/amount.h"  // for bitcoin::Amount
#include "bitcoin/uint256.h"

#include <QByteArray>

using HashHasher = BTC::QByteArrayHashHasher;

using BlockHeight = std::uint32_t;
using TxNum = std::uint64_t; ///< this is used by the storage subsystem and also CompactTXO
using IONum = std::uint16_t;
using TxHash = QByteArray;
using HashX = QByteArray;
using BlockHash = QByteArray;
constexpr int HashLen = bitcoin::uint256::width();

