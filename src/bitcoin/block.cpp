// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "hash.h"
#include "tinyformat.h"

namespace bitcoin {

BlockHash CBlockHeader::GetHash() const {
    CHashWriter layer3(SER_GETHASH, 0);
    layer3 << nHeaderVersion;
    layer3 << vSize;
    layer3 << nHeight;
    layer3 << hashEpochBlock;
    layer3 << hashMerkleRoot;
    layer3 << hashExtendedMetadata;
    CHashWriter layer2(SER_GETHASH, 0);
    layer2 << nBits;
    layer2 << vTime;
    layer2 << nReserved;
    layer2 << nNonce;
    layer2 << layer3.GetSHA256();
    CHashWriter layer1(SER_GETHASH, 0);
    layer1 << hashPrevBlock;
    layer1 << layer2.GetSHA256();
    return BlockHash(layer1.GetSHA256());
}

std::string CBlock::ToString() const {
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, hashPrevBlock=%s, bits=0x%08x, time=%u, "
        "nonce=%u, headerversion=%u, size=%u, height=%d, hashEpochBlock=%s, "
        "hashMerkleRoot=%s, hashExtendedMetadata=%s, vtx=%u)\n",
        GetHash().ToString(), hashPrevBlock.ToString(), nBits, GetBlockTime(),
        nNonce, nHeaderVersion, GetSize(), nHeight, hashEpochBlock.ToString(),
        hashMerkleRoot.ToString(), hashExtendedMetadata.ToString(), vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
}
