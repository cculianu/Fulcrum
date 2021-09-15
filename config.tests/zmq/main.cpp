#include <iostream>
#include <zmq.h>

int main()
{
    int maj, min, patch;
    zmq_version(&maj, &min, &patch);
    std::cout << "ZMQ Version: " << maj << "." << min << "." << patch << std::endl;
    return 0;
}
