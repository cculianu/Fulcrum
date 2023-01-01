// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Cashaddr is an address format inspired by bech32.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bitcoin {

namespace cashaddr {

/**
 * Encode a cashaddr string. Returns the empty string in case of failure.
 * @pre - The bytes in `values` must already be packed to contain only
 *        5 bits of data per byte, e.g. by a previous call to
 *        `PackCashAddrContent`. Violating this precondition will produce
 *        unspecified results.
 */
std::string Encode(const std::string &prefix,
                   const std::vector<uint8_t> &values);

/**
 * Decode a cashaddr string. Returns (prefix, data). Empty prefix means failure.
 * The returned data, if not-empty, will contain packed 5-bit values per byte
 * and must further be decoded in some way (e.g. using `ConvertBits`).
 */
std::pair<std::string, std::vector<uint8_t>>
Decode(const std::string &str, const std::string &default_prefix);

} // namespace cashaddr

} // end namespace bitcoin
