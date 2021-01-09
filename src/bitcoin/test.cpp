//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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
#include "base58.h"

#include "App.h"
#include "Util.h"

#include <QByteArray>

#include <cstring>
#include <string>
#include <vector>

namespace bitcoin {
    bool TestBase58(bool silent, bool throws)
    {
        using Print = Log;
        std::vector<unsigned char> result;
        constexpr auto anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        if (!bitcoin::DecodeBase58Check(anAddress, result)) {
            constexpr auto err = "Base58 decode check fail!";
            if (throws) throw InternalError(err);
            if (!silent) Print() << err;
            return false;
        }
        QByteArray ba;
        ba.insert(0, reinterpret_cast<char *>(&result[0]), int(result.size()));
        const auto hexDecoded = ba.toHex();
        if (!silent) Print() << anAddress << "  ->  " << hexDecoded << "  (decoded)";
        ba = QByteArray::fromHex("00791fc195e712c142df4c4e14fd4ec5b302733832");
        result.resize(size_t(ba.length()));
        std::memcpy(&result[0], ba.constData(), size_t(ba.length()));
        auto str = bitcoin::EncodeBase58Check(result);
        std::vector<unsigned char> result2;
        if (!bitcoin::DecodeBase58Check(str, result2) || result2 != result) {
            constexpr auto err = "Base58 Decode -> Encode results differ! Fail!";
            if (throws) throw InternalError(err);
            if (!silent) Print() << err;
            return false;
        }
        if (!silent) Print() << ba.toHex() << "  ->  " << str << "  (encoded)";
        bool ret = ba.toHex() == hexDecoded && str == std::string(anAddress);
        if (!silent) Print() << (ret ? "Compare ok, success." : "Values differ -- ERROR!!");
        return ret;
    }
}

#ifdef ENABLE_TESTS
namespace {
    const auto t1 = App::registerTest("base58", []{
        const bool res = bitcoin::TestBase58(false, true);
        if (!res) throw Exception("base58 failed");
    });
}
#endif
