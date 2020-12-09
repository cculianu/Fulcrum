// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "tinyformat.h"

#include <mutex>
#include <shared_mutex>

namespace bitcoin {

// added by Calin
namespace {
std::string mutableCurrencyUnit = "BCH";
std::shared_mutex currencyUnitMut;
}
void SetCurrencyUnit(const std::string &unit) {
    std::unique_lock g(currencyUnitMut);
    mutableCurrencyUnit = unit;
}
std::string GetCurrencyUnit() {
    std::shared_lock g(currencyUnitMut);
    return mutableCurrencyUnit;
}
// /added by Calin

std::string Amount::ToString() const {
    // Modified by Calin to properly handle negative values
    const bool negative = *this < Amount::zero();
    const Amount absVal = negative ? -1 * *this : *this;
    return strprintf("%s%d.%08d %s", negative ? "-" : "", absVal / COIN, (absVal % COIN) / SATOSHI,
                     GetCurrencyUnit());
}

} // end namespace bitcoin
