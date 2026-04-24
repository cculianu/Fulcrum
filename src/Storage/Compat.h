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

#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/status.h>

#include <string>
#include <memory>
#include <vector>

/// A namespace for encapsulating a "compatibility" layer to smoothe over API differences between various
/// rocksdb versions
namespace Compat {
// rocksdb::DB::Open changed after version v11.0.0 of rocksdb so we smoothe it over with a unified API
rocksdb::Status DBOpen(const rocksdb::Options &options, const std::string &name, std::unique_ptr<rocksdb::DB> *dbptr);
rocksdb::Status DBOpen(const rocksdb::DBOptions &db_options, const std::string &name,
                       const std::vector<rocksdb::ColumnFamilyDescriptor> &column_families,
                       std::vector<rocksdb::ColumnFamilyHandle*> *handles,
                       std::unique_ptr<rocksdb::DB> *dbptr);
} // namespace Compat
