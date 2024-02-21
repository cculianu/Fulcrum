//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

#include "BlockProcTypes.h"
#include "BTC.h"
#include "Common.h"

#include "bitcoin/transaction.h"
#include "tsl/htrie_map.h"

#include <QString>

#include <cstddef>
#include <cstdint>
#include <cstring> // for std::memcpy
#include <type_traits>

// Our prefixes are lower 4 bits inside char
using PrefixNibble = char;

// TODO provide description of data here
using PrefixMap = tsl::htrie_map<PrefixNibble, std::vector<TxNum>, tsl::ah::str_hash<PrefixNibble>, std::uint8_t>;

// we can save some space on disk by using uint32_t - max size is dependent on block, so if blocks overflow uint32::max txs this could fail
using HATSerializationVectorSizeType = uint32_t;

struct ReusableHATSerializer {
    QByteArray store;

    ReusableHATSerializer() {}

    template <typename T, std::enable_if_t<std::is_arithmetic_v<T>>* = nullptr> // required support for uint64_t and float (WHY float? see https://github.com/Tessil/hat-trie note about serialization)
    void operator()(const T& value) {
        store.append(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    void operator()(const PrefixMap::mapped_type& value) { // specialize for our list of TxNums
        HATSerializationVectorSizeType size = value.size();
        store.append(reinterpret_cast<const char*>(&size), sizeof(size));
        store.append(reinterpret_cast<const char*>(value.data()), size * sizeof(TxNum));
    }

    void operator()(const char* value, std::size_t value_size) {
        store.append(reinterpret_cast<const char*>(value), value_size);
    }
};

struct ReusableHATDeserializer {
    QByteArray store;
    size_t offset = 0u;

    explicit ReusableHATDeserializer(const QByteArray &store_): store(store_) {}

    template <typename T,
              std::enable_if_t<std::is_arithmetic_v<T>>* = nullptr> // required support for uint64_t and float (see note above)
    T operator()() {
        checkReadSizeOk(sizeof(T));
        T value;
        std::memcpy(reinterpret_cast<char*>(&value), store.constData() + offset, sizeof(T));
        offset += sizeof(T);
        return value;
    }

    template <typename T,
              std::enable_if_t<! std::is_arithmetic_v<T>>* = nullptr> // invert the above specialzation for vector (TODO make this more clean)
    T operator()() { // specialization on our value type for deserialization
        static_assert(std::is_same_v<T, PrefixMap::mapped_type>);
        HATSerializationVectorSizeType size = 0;
        size_t bytesToRead = sizeof(size);
        checkReadSizeOk(bytesToRead);
        std::memcpy(reinterpret_cast<char*>(&size), store.constData() + offset, bytesToRead);
        offset += bytesToRead;

        static_assert(std::is_same_v<TxNum, PrefixMap::mapped_type::value_type>);
        bytesToRead = size * sizeof(TxNum); // read "size" TxNums
        checkReadSizeOk(bytesToRead);
        PrefixMap::mapped_type value(size, TxNum{}); // resize our vector so we can copy into it without causing explosion
        std::memcpy(reinterpret_cast<char*>(value.data()), store.constData() + offset, bytesToRead);
        offset += bytesToRead;

        return value;
    }

    void operator()(char* value_out, size_t value_size) {
        checkReadSizeOk(value_size);
        std::memcpy(value_out, store.constData() + offset, value_size);
        offset += value_size;
    }

private:
    void checkReadSizeOk(const size_t bytesToRead) const {
        if (offset + bytesToRead > static_cast<size_t>(store.size()))
            throw InternalError("Attempt to read past end of buffer");
    }
};


/// TODO describe these
/// This stores prefixes -> txids
/// The prefixes are the last bytes of sha256 inputs
struct ReusableBlock {
    constexpr static size_t NIBBLE_WIDTH = 4; // half octet
    constexpr static size_t MAX_BITS = 16; // must be a multiple of NIBBLE_WIDTH
    constexpr static size_t MAX_PREFIX_SIZE = MAX_BITS / NIBBLE_WIDTH;

    PrefixMap pmap; // Prefix map for efficient searching

    bool isValid() const { return true; }

    bool operator==(const ReusableBlock &o) const noexcept { return pmap == o.pmap; }
    bool operator!=(const ReusableBlock &o) const noexcept { return !operator==(o); }

    void clear() { pmap.clear(); }

    // perform serialization of a bitcoin input, the prefix of this will be indexed
    static RuHash serializeInput(const bitcoin::CTxIn& input) {
        return BTC::HashInPlace(input); // double sha256
    }

    // split hash into little nibbles so we can perform prefix queries on 4 bit sections
    // in future this can be expanded if we want even more fine grained queries, this (16bit) currently allows for 1/65536
    static std::string ruHashToPrefix(const QByteArray &a) {
        if (a.size() < 2) throw BadArgs("Specified argument must be >=2 bytes in ReusableBlock::ruHashToPrefix!");
        return {{
            static_cast<char>((a[0] & 0xF0) >> NIBBLE_WIDTH), static_cast<char>(a[0] & 0x0F),
            static_cast<char>((a[1] & 0xF0) >> NIBBLE_WIDTH), static_cast<char>(a[1] & 0x0F),
        }};
    }

    auto prefixSearch(const std::string& prefix) const {
        return pmap.equal_prefix_range(prefix);
    }

    void add(const RuHash& ruHash, const TxNum n) {
        // assert(n != 0); // coinbase - this would be strange.. but for mempool it makes sense.. hm! TODO
        // we could calculate masks from nibble width but it makes code harder to read
        // split the input hash by every 4 bits
        // we can use prefix search on htrie to handle wider scans
        const std::string prefix = ReusableBlock::ruHashToPrefix(ruHash);

        pmap[prefix].push_back(n); // create a new vector or push to existing
    }

    void remove(const RuHash& ruHash) {
        // assert(n != 0); // coinbase - this would be strange.. but for mempool it makes sense.. hm! TODO
        // we could calculate masks from nibble width but it makes code harder to read
        // split the input hash by every 4 bits
        // we can use prefix search on htrie to handle wider scans
        const std::string prefix = ReusableBlock::ruHashToPrefix(ruHash);

        removeForPrefix(prefix);
    }

    void removeForPrefix(const std::string &prefix) { pmap.erase(prefix); }

    auto size() const -> decltype(pmap.size()) { return pmap.size(); }

    // serialization
    QByteArray toBytes() const {
        ReusableHATSerializer serializer;
        pmap.serialize(serializer);
        return serializer.store;
    }

    // deserialization
    static ReusableBlock fromBytes(const QByteArray &ba) {
        ReusableHATDeserializer deserializer(ba);
        ReusableBlock ret;
        ret.pmap = PrefixMap::deserialize(deserializer);
        return ret;
    }
};
