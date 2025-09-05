#include <cstdint>

int main(int argc, char *[])
{
    const uint16_t u16 = static_cast<uint16_t>(argc);
    const uint32_t u32 = static_cast<uint32_t>(argc);
    const uint64_t u64 = static_cast<uint64_t>(argc);
    return __builtin_bswap16(u16) + __builtin_bswap32(u32) + __builtin_bswap64(u64);
}
