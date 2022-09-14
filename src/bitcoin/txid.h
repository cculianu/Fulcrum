// Copyright (c) 2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "uint256.h"

namespace bitcoin {


/**
 * A TxId is the identifier of a transaction. Currently identical to TxHash but
 * differentiated for type safety.
 */
struct TxId : public uint256 {
    explicit constexpr TxId() noexcept : uint256() {}
    explicit constexpr TxId(const uint256 &b) noexcept : uint256(b) {}
    explicit constexpr TxId(Uninitialized_t u) noexcept : uint256(u) {}
};

/**
 * A TxHash is the double sha256 hash of the full transaction data.
 */
struct TxHash : public uint256 {
    explicit constexpr TxHash() noexcept : uint256() {}
    explicit constexpr TxHash(const uint256 &b) noexcept : uint256(b) {}
    explicit constexpr TxHash(Uninitialized_t u) noexcept : uint256(u) {}
};

} // end namespace bitcoin
