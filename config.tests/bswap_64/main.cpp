#include <byteswap.h>

#include <cstdint>

int main(int argc, char *[])
{
    return static_cast<int>(bswap_64(static_cast<uint64_t>(argc)));
}
