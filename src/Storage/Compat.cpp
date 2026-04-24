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
#include "Storage/Compat.h"

#include <rocksdb/version.h>
#if ROCKSDB_MAJOR >= 11
/* RocksDB v11.0.0 or greater may not have the "raw pointer" versions of DB::Open() (which we still must support for
 * compatibility with older rocksdb). See: https://github.com/facebook/rocksdb/releases/tag/v11.0.4
 */
#define USE_RAW_PTR_ROCKSDB_OPEN_FUNC 0
#else
#define USE_RAW_PTR_ROCKSDB_OPEN_FUNC 1
#endif

namespace Compat {

rocksdb::Status DBOpen(const rocksdb::Options &options, const std::string &name, std::unique_ptr<rocksdb::DB> *dbptr)
{
#if USE_RAW_PTR_ROCKSDB_OPEN_FUNC
    rocksdb::DB *raw = nullptr;
    rocksdb::Status st = rocksdb::DB::Open(options, name, &raw);
    dbptr->reset(raw); // Give the raw DB ptr to the unique ptr
    return st;
#else
    return rocksdb::DB::Open(options, name, dbptr);
#endif
}

rocksdb::Status DBOpen(const rocksdb::DBOptions &db_options, const std::string &name,
                       const std::vector<rocksdb::ColumnFamilyDescriptor> &column_families,
                       std::vector<rocksdb::ColumnFamilyHandle*> *handles,
                       std::unique_ptr<rocksdb::DB> *dbptr)
{
#if USE_RAW_PTR_ROCKSDB_OPEN_FUNC
    rocksdb::DB *raw = nullptr;
    rocksdb::Status st = rocksdb::DB::Open(db_options, name, column_families, handles, &raw);
    dbptr->reset(raw); // Give the raw DB ptr to the unique ptr
    return st;
#else
    return rocksdb::DB::Open(db_options, name, column_families, handles, dbptr);
#endif
}

} // namespace Compat
