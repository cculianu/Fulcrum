// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "cashaddrenc.h"

#include "cashaddr.h"
#include "pubkey.h"
#include "utilstrencodings.h"

#include "Span.h"

#include <algorithm>
#include <variant>
#ifdef USE_QT_IN_BITCOIN
#include <QtCore>
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif

namespace bitcoin {

/// convenient work-alike added by Calin
const CChainParams TestNetChainParams    = { "bchtest" },
                   TestNet4ChainParams   = { "bchtest" },
                   ScaleNetChainParams   = { "bchtest" },
                   ChipNetChainParams    = { "bchtest" },
                   RegTestNetChainParams = { "bchreg" },
                   MainNetChainParams    = { "bitcoincash" };

namespace {

// Convert the data part to a 5 bit representation.
template <class T>
std::vector<uint8_t> PackAddrData(const T &id, uint8_t type) {
    uint8_t version_byte(type << 3);
    size_t size = id.size();
    uint8_t encoded_size = 0;
    switch (size * 8) {
        case 160:
            encoded_size = 0;
            break;
        case 192:
            encoded_size = 1;
            break;
        case 224:
            encoded_size = 2;
            break;
        case 256:
            encoded_size = 3;
            break;
        case 320:
            encoded_size = 4;
            break;
        case 384:
            encoded_size = 5;
            break;
        case 448:
            encoded_size = 6;
            break;
        case 512:
            encoded_size = 7;
            break;
        default:
            throw std::runtime_error(
                "Error packing cashaddr: invalid address length");
    }
    version_byte |= encoded_size;
    std::vector<uint8_t> data = {version_byte};
    data.insert(data.end(), std::begin(id), std::end(id));

    std::vector<uint8_t> converted;
    // Reserve the number of bytes required for a 5-bit packed version of a
    // hash, with version byte.  Add half a byte(4) so integer math provides
    // the next multiple-of-5 that would fit all the data.
    converted.reserve(((size + 1) * 8 + 4) / 5);
    ConvertBits<8, 5, true>(converted, std::begin(data), std::end(data));

    return converted;
}

// Implements encoding of CTxDestination using cashaddr.
class CashAddrEncoder /*: public boost::static_visitor<std::string>*/ {
public:
    CashAddrEncoder(const CChainParams &p) : params(p) {}

    std::string operator()(const CKeyID &id) const {
        std::vector<uint8_t> data = PackAddrData(id, PUBKEY_TYPE);
        return cashaddr::Encode(params.CashAddrPrefix(), data);
    }

    std::string operator()(const ScriptID &id) const {
        std::vector<uint8_t> data = PackAddrData(id, SCRIPT_TYPE);
        return cashaddr::Encode(params.CashAddrPrefix(), data);
    }

    std::string operator()(const CNoDestination &) const { return ""; }

private:
    const CChainParams &params;
};

} // namespace

std::string EncodeCashAddr(const CTxDestination &dst,
                           const CChainParams &params) {
    //return boost::apply_visitor(CashAddrEncoder(params), dst);
    // Below added by Calin as a boost work-alike to avoid depending on boost
    std::string ret;
    try {
        ret = std::visit(CashAddrEncoder(params), dst); // cheap rvalue ref copy assign
    } catch (const std::bad_variant_access & e) {
#ifdef USE_QT_IN_BITCOIN
        qCritical("%s: Caught exception bad_variant_access: %s", __func__, e.what());
#endif
        // ignore..
        ret.clear();
    }
    return ret;
}

std::string EncodeCashAddr(const std::string &prefix,
                           const CashAddrContent &content) {
    std::vector<uint8_t> data = PackAddrData(content.hash, content.type);
    return cashaddr::Encode(prefix, data);
}

CTxDestination DecodeCashAddr(const std::string &addr,
                              const CChainParams &params) {
    CashAddrContent content =
        DecodeCashAddrContent(addr, params.CashAddrPrefix());
    if (content.hash.size() == 0) {
        return CNoDestination{};
    }

    return DecodeCashAddrDestination(content);
}

CashAddrContent DecodeCashAddrContent(const std::string &addr,
                                      const std::string &expectedPrefix) {
    std::string prefix;
    std::vector<uint8_t> payload;
    std::tie(prefix, payload) = cashaddr::Decode(addr, expectedPrefix);

    if (prefix != expectedPrefix) {
        return {};
    }

    if (payload.empty()) {
        return {};
    }

    // Check that the padding is zero.
    size_t extrabits = payload.size() * 5 % 8;
    if (extrabits >= 5) {
        // We have more padding than allowed.
        return {};
    }

    uint8_t last = payload.back();
    uint8_t mask = (1 << extrabits) - 1;
    if (last & mask) {
        // We have non zero bits as padding.
        return {};
    }

    std::vector<uint8_t> data;
    data.reserve(payload.size() * 5 / 8);
    ConvertBits<5, 8, false>(data, begin(payload), end(payload));

    // Decode type and size from the version.
    uint8_t version = data[0];
    if (version & 0x80) {
        // First bit is reserved.
        return {};
    }

    auto type = CashAddrType((version >> 3) & 0x1f);
    uint32_t hash_size = 20 + 4 * (version & 0x03);
    if (version & 0x04) {
        hash_size *= 2;
    }

    // Check that we decoded the exact number of bytes we expected.
    if (data.size() != hash_size + 1) {
        return {};
    }

    // Pop the version.
    data.erase(data.begin());
    return {type, std::move(data)};
}

CTxDestination DecodeCashAddrDestination(const CashAddrContent &content) {
    uint160 hash20{uint160::Uninitialized};
    uint256 hash32{uint256::Uninitialized};
    Span<uint8_t> destHash; // references data in either hash20 or hash32 above
    if (content.hash.size() == 20) {
        // 20-byte hash, write results into hash20
        destHash = Span<uint8_t>(hash20.data(), hash20.size());
    } else if (content.hash.size() == 32 && (content.type == SCRIPT_TYPE || content.type == TOKEN_SCRIPT_TYPE)) {
        // we accept 32-byte content for p2sh_32, write results into hash32
        destHash = Span<uint8_t>(hash32.data(), hash32.size());
    } else {
        // Only 20 bytes hash are supported for p2sh & p2pkh, or 32-bytes for p2sh_32
        return CNoDestination{};
    }

    std::copy(content.hash.begin(), content.hash.end(), destHash.begin());

    switch (content.type) {
        case PUBKEY_TYPE:
        case TOKEN_PUBKEY_TYPE:
            assert(destHash.data() == hash20.data());
            return CKeyID(hash20);
        case SCRIPT_TYPE:
        case TOKEN_SCRIPT_TYPE:
            if (destHash.data() == hash20.data()) return ScriptID(hash20); // p2sh
            else if (destHash.data() == hash32.data()) return ScriptID(hash32); // p2sh_32
            assert(!"Unexpected state");
            [[fallthrough]]; // not reached
        default:
            return CNoDestination{};
    }
}

// PackCashAddrContent allows for testing PackAddrData in unittests due to
// template definitions.
std::vector<uint8_t> PackCashAddrContent(const CashAddrContent &content) {
    return PackAddrData(content.hash, content.type);
}

} // end namespace bitcoin

#ifdef __clang__
#pragma clang diagnostic pop
#endif
