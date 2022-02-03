#if (defined(__clang__) && defined(__BIG_ENDIAN__)) || (defined(__GNUG__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
int main(int, char *[])
{
    return 0;
}
#else
static_assert (false, "Must be little endian");
#endif
