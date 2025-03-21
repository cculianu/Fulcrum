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
#pragma once

#include <cstddef> // for std::byte
#include <cstdint>
#include <type_traits>

namespace bitcoin {

// Added by Calin to make some of the bitcoin code more generic
template <typename T>
concept ByteLike = std::is_same_v<T, char> || std::is_same_v<T, uint8_t> || std::is_same_v<T, std::byte>
                   || std::is_same_v<T, int8_t> || std::is_same_v<T, signed char> || std::is_same_v<T, unsigned char>;

} // namespace bitcoin
