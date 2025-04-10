#if __has_include(<endian.h>)
#include <endian.h>
#elif __has_include(<sys/endian.h>)
#include <sys/endian.h>
#endif

#include <cstdint>

int main(int argc, char *[])
{
    const uint16_t u16 = static_cast<uint16_t>(argc);
    const uint32_t u32 = static_cast<uint32_t>(argc);
    const uint64_t u64 = static_cast<uint64_t>(argc);
    return   htole16(u16) + htole32(u32) + htole64(u64)
           + le16toh(u16) + le32toh(u32) + le64toh(u64)
           + htobe16(u16) + htobe32(u32) + htobe64(u64)
           + be16toh(u16) + be32toh(u32) + be64toh(u64);
}
