#include <cstdlib>
#include <jemalloc/jemalloc.h>

int main()
{
    if (malloc(1) == nullptr)
        return 1;

    if (mallocx(1, MALLOCX_ZERO) == nullptr)
        return 1;

    return 0;
}
