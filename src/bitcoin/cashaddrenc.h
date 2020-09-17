// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CASHADDRENC_H
#define BITCOIN_CASHADDRENC_H

#include "script_standard.h"

#include <string>
#include <vector>

namespace bitcoin {

//class CChainParams;

// added by Calin to avoid pulling in the wold with the CChainParams
struct MinimalisticChainParamsAddedByCalin
{
    const std::string cashaddrPrefix; // e.g. "bitcoincash"

    const std::string & CashAddrPrefix() const noexcept { return cashaddrPrefix; }
};
using CChainParams = MinimalisticChainParamsAddedByCalin;
//! convenience added by Calin
extern const CChainParams TestNetChainParams, TestNet4ChainParams, ScaleNetChainParams, MainNetChainParams, RegTestNetChainParams;

enum CashAddrType : uint8_t { PUBKEY_TYPE = 0, SCRIPT_TYPE = 1 };

struct CashAddrContent {
    CashAddrType type;
    std::vector<uint8_t> hash;
};

std::string EncodeCashAddr(const CTxDestination &, const CChainParams &);
std::string EncodeCashAddr(const std::string &prefix,
                           const CashAddrContent &content);

CTxDestination DecodeCashAddr(const std::string &addr,
                              const CChainParams &params);
CashAddrContent DecodeCashAddrContent(const std::string &addr,
                                      const std::string &prefix);
CTxDestination DecodeCashAddrDestination(const CashAddrContent &content);

std::vector<uint8_t> PackCashAddrContent(const CashAddrContent &content);

} // end namespace bitcoin
#endif
