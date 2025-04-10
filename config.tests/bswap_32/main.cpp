#include <byteswap.h>

#include <cstdint>

int main(int argc, char *[])
{
    return static_cast<int>(bswap_32(static_cast<uint32_t>(argc)));
}
