#if defined(_WIN32) || (defined(__clang__) && defined(__LITTLE_ENDIAN__)) || (defined(__GNUG__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
int main(int, char *[])
{
    return 0;
}
#else
static_assert (false, "Must be big endian");
#endif
