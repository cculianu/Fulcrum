// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

namespace bitcoin {
/**
 * network protocol versioning
 */
inline constexpr int PROTOCOL_VERSION = 70015;

//! initial proto version, to be increased after version/verack negotiation
inline constexpr int INIT_PROTO_VERSION = 209;

//! In this version, 'getheaders' was introduced.
inline constexpr int GETHEADERS_VERSION = 31800;

//! disconnect from peers older than this proto version
inline constexpr int MIN_PEER_PROTO_VERSION = GETHEADERS_VERSION;

//! nTime field added to CAddress, starting with this version;
//! if possible, avoid requesting addresses nodes older than this
inline constexpr int CADDR_TIME_VERSION = 31402;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
inline constexpr int BIP0031_VERSION = 60000;

//! "mempool" command, enhanced "getdata" behavior starts with this version
inline constexpr int MEMPOOL_GD_VERSION = 60002;

//! "filter*" commands are disabled without NODE_BLOOM after and including this
//! version
inline constexpr int NO_BLOOM_VERSION = 70011;

//! "sendheaders" command and announcing blocks with headers starts with this
//! version
inline constexpr int SENDHEADERS_VERSION = 70012;

//! "feefilter" tells peers to filter invs to you by fee starts with this
//! version
inline constexpr int FEEFILTER_VERSION = 70013;

//! short-id-based block download starts with this version
inline constexpr int SHORT_IDS_BLOCKS_VERSION = 70014;

//! not banning for invalid compact blocks starts with this version
inline constexpr int INVALID_CB_NO_BAN_VERSION = 70015;

} // end namespace bitcoin
