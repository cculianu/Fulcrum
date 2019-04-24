#include "base58.h"
#include <stdio.h>
#include <string>
#include <QByteArray>
#include <string.h>
namespace bitcoin {
    bool TestBase58()
    {
        std::vector<unsigned char> result;
        const char *anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
        if (!bitcoin::DecodeBase58Check(anAddress, result)) {
            printf("Base58 Decode Check Fail!\n");
            return false;
        }
        QByteArray ba;
        ba.insert(0, reinterpret_cast<char *>(&result[0]), int(result.size()));
        auto hexDecoded = ba.toHex();
        printf("%s  ->  %s  (decoded)\n", anAddress, hexDecoded.constData());
        ba = QByteArray::fromHex("00791fc195e712c142df4c4e14fd4ec5b302733832");
        result.resize(size_t(ba.length()));
        memcpy(&result[0], ba.constData(), size_t(ba.length()));
        auto str = bitcoin::EncodeBase58Check(result);
        std::vector<unsigned char> result2;
        if (!bitcoin::DecodeBase58Check(str, result2) || result2 != result) {
            printf("Base58 Decode -> Encode results differ! Fail!\n");
            return false;
        }
        printf("%s  ->  %s  (encoded)\n", ba.toHex().constData(), str.c_str());
        bool ret = ba.toHex() == hexDecoded && str == std::string(anAddress);
        printf("%s\n", ret ? "Compare ok, success." : "Values differ -- ERROR!!");
        return ret;
    }
}
