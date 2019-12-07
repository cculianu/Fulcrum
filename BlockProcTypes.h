#pragma once

#include "BTC.h" // for BTC::QByteArrayHashHasher

#include "bitcoin/amount.h"  // for bitcoin::Amount
#include "bitcoin/uint256.h"

#include <QByteArray>

using HashHasher = BTC::QByteArrayHashHasher;

using BlockHeight = std::uint32_t;
using IONum = std::uint16_t;
using TxHash = QByteArray;
using HashX = QByteArray;
static constexpr int HashLen = bitcoin::uint256::width();

