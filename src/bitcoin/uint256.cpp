// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include "utilstrencodings.h"

#include <cstdio>
#include <cstring>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif

namespace bitcoin {

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<uint8_t> &vch) noexcept {
    assert(vch.size() == sizeof(m_data));
    memcpy(m_data, &vch[0], sizeof(m_data));
}

template <unsigned int BITS> std::string base_blob<BITS>::GetHex() const {
    return HexStr(std::reverse_iterator<const uint8_t *>(m_data + sizeof(m_data)),
                  std::reverse_iterator<const uint8_t *>(m_data));
}

template <unsigned int BITS> void base_blob<BITS>::SetHex(const char *psz) {
    memset(m_data, 0, sizeof(m_data));

    // skip leading spaces
    while (IsSpace(*psz)) {
        psz++;
    }

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x') {
        psz += 2;
    }

    // hex string to uint
    const char *pbegin = psz;
    while (bitcoin::HexDigit(*psz) != -1) {
        psz++;
    }

    psz--;
    uint8_t *p1 = (uint8_t *)m_data;
    uint8_t *pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = bitcoin::HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= uint8_t(bitcoin::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string &str) {
    SetHex(str.c_str());
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<uint8_t> &);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char *);
template void base_blob<160>::SetHex(const std::string &);

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<uint8_t> &);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char *);
template void base_blob<256>::SetHex(const std::string &);

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif

