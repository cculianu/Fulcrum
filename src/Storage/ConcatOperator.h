//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <rocksdb/merge_operator.h>
#include <rocksdb/slice.h>

#include <atomic>
#include <string>

namespace StorageDetail {

/// Associative merge operator used for scripthash history concatenation
/// TODO: this needs to be made more efficient by implementing the real MergeOperator interface and combining
/// appends efficiently to reduce allocations.  Right now it's called for each append.
struct ConcatOperator : rocksdb::AssociativeMergeOperator
{
    ~ConcatOperator() override;

    mutable std::atomic_size_t merges = 0u;

    // Gives the client a way to express the read -> modify -> write semantics
    // key:           (IN) The key that's associated with this merge operation.
    // existing_value:(IN) null indicates the key does not exist before this op
    // value:         (IN) the value to update/merge the existing_value with
    // new_value:    (OUT) Client is responsible for filling the merge result
    // here. The string that new_value is pointing to will be empty.
    // logger:        (IN) Client could use this to log errors during merge.
    //
    // Return true on success.
    // All values passed in will be client-specific values. So if this method
    // returns false, it is because client specified bad data or there was
    // internal corruption. The client should assume that this will be treated
    // as an error by the library.
    bool Merge(const rocksdb::Slice& key, const rocksdb::Slice* existing_value,
               const rocksdb::Slice& value, std::string* new_value,
               rocksdb::Logger* logger) const override;

    /* NOTE: This must be the same for the same db each time it is opened! */
    const char* Name() const override { return "ConcatOperator"; }
};

} // namespace StorageDetail
