#include <version>
#if __cpp_lib_endian >= 201907L
#include <bit>
int main(int, char *[]) {
    static_assert(std::endian::native == std::endian::big);
    return 0;
}
#else
#if (defined(__clang__) && defined(__BIG_ENDIAN__)) || (defined(__GNUG__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
int main(int, char *[])
{
    return 0;
}
#else
static_assert (false, "Must be little endian");
#endif
#endif
