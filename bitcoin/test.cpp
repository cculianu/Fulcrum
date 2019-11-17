#include <QByteArray>
#include <string>
#include <string.h>
#include "base58.h"
#include "Util.h"

#include <iostream> // testing

namespace bitcoin {
    bool TestBase58(bool silent, bool throws)
    {
        using Print = Debug;
        std::vector<unsigned char> result;
        const char *anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        if (!bitcoin::DecodeBase58Check(anAddress, result)) {
            static constexpr auto err = "Base58 decode check fail!";
            if (throws) throw InternalError(err);
            if (!silent) Print() << err;
            return false;
        }
        QByteArray ba;
        ba.insert(0, reinterpret_cast<char *>(&result[0]), int(result.size()));
        auto hexDecoded = ba.toHex();
        if (!silent) Print() << anAddress << "  ->  " << hexDecoded << "  (decoded)";
        ba = QByteArray::fromHex("00791fc195e712c142df4c4e14fd4ec5b302733832");
        result.resize(size_t(ba.length()));
        memcpy(&result[0], ba.constData(), size_t(ba.length()));
        auto str = bitcoin::EncodeBase58Check(result);
        std::vector<unsigned char> result2;
        if (!bitcoin::DecodeBase58Check(str, result2) || result2 != result) {
            static constexpr auto err = "Base58 Decode -> Encode results differ! Fail!";
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
