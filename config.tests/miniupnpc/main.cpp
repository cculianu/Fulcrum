#include <iostream>
#include <miniupnpc/miniupnpc.h>

int main()
{
    std::cout << "UPnP Version: miniupnpc " << MINIUPNPC_VERSION
              << ", API version: " << MINIUPNPC_API_VERSION << std::endl;
    return 0;
}
