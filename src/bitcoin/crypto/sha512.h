// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <cstdlib>

namespace bitcoin {

/** A hasher class for SHA-512. */
class CSHA512 {
private:
    uint64_t s[8];
    uint8_t buf[128];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 64;

    CSHA512();
    CSHA512 &Write(const uint8_t *data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CSHA512 &Reset();
};

} // end namespace bitcoin
