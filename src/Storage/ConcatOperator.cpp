//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "ConcatOperator.h"

namespace StorageDetail {

ConcatOperator::~ConcatOperator() {} // weak vtable warning prevention

bool ConcatOperator::Merge(const rocksdb::Slice &key [[maybe_unused]], const rocksdb::Slice *existing_value,
                           const rocksdb::Slice &value, std::string *new_value, rocksdb::Logger *) const
{
    ++merges;
    if (!existing_value) {
        new_value->assign(value.data(), value.size());
    } else {
        new_value->clear();
        const size_t evsz{existing_value->size()}, vsz{value.size()};
        new_value->reserve(evsz + vsz);
        new_value->append(existing_value->data(), evsz);
        new_value->append(value.data(), vsz);
    }
    return true;
}


} // namespace StorageDetail
