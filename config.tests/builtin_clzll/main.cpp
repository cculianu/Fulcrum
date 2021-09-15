int main(int argc, char *[])
{
    const unsigned long long x = static_cast<unsigned long long>(argc);
    return __builtin_clzll(x);
}
