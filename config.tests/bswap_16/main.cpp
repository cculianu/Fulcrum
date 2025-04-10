#include <byteswap.h>

#include <cstdint>

int main(int argc, char *[])
{
    return bswap_16(static_cast<uint16_t>(argc));
}
