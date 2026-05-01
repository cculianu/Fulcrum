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

#include <cstdio>

#if ROCKSDB_MAJOR >= 11
/* RocksDB v11.0.0 or greater may not have the "raw pointer" versions of DB::Open() (which we still must support for
 * compatibility with older rocksdb). See: https://github.com/facebook/rocksdb/releases/tag/v11.0.4
 */
#define USE_RAW_PTR_ROCKSDB_OPEN_FUNC 0
#else
#define USE_RAW_PTR_ROCKSDB_OPEN_FUNC 1
#endif

/* Tricks to obtain the RocksDB commit hash, which changed as of v6.17.3 using a "properties" API. Older versions used
 * an exported library symbol for this purpose. */
#if ((ROCKSDB_MAJOR << 16)|(ROCKSDB_MINOR << 8)|(ROCKSDB_PATCH)) > ((6 << 16)|(17 << 8)|(3)) // 6.17.3
#define HAS_ROCKSDB_NEW_VERSION_API 1
#else
#define HAS_ROCKSDB_NEW_VERSION_API 0
extern const char* rocksdb_build_git_sha; // internal to rocksdb lib -- if this breaks remove me
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

std::string GetRocksDBVersion()
{
#if !HAS_ROCKSDB_NEW_VERSION_API
    std::string sha(rocksdb_build_git_sha);
    // rocksdb git commit sha: try and pop off the front part, and keep the rest and take the first 7 characters of that
    if (auto pos = sha.find(':'); pos != sha.npos) {
        auto aftercolon = sha.substr(pos + 1, sha.npos);
        if (aftercolon.find(':') == aftercolon.npos) // must match what we expect otherwise don't truncate
            sha = aftercolon.substr(0, 7);
    }
    // We must do things this way due to the fact that std::format is missing from macOS before SDK 13.3
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%d.%d.%d-%s", int(ROCKSDB_MAJOR), int(ROCKSDB_MINOR), int(ROCKSDB_PATCH), sha.c_str());
    return buf;
#else
    const auto dbversion = rocksdb::GetRocksVersionAsString(true);
    const auto sha = []{
        const auto &props = rocksdb::GetRocksBuildProperties();
        if (auto it = props.find("rocksdb_build_git_sha"); it != props.end())
            return it->second.substr(0, 7);
        return std::string{"unk"};
    }();
    return dbversion + "-" + sha;
#endif
}

} // namespace Compat
