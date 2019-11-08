// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cleanse.h"
#include <cstring>
//#include <openssl/crypto.h>
namespace bitcoin {

void memory_cleanse(void *ptr, size_t len) {
    //OPENSSL_cleanse(ptr, len);
	std::memset(ptr, 0, len);
}

} // end namepsace
