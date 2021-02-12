int main(int argc, char *[])
{
    const unsigned long x = static_cast<unsigned long>(argc);
    return __builtin_clzl(x);
}
