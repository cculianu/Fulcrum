#include <QCoreApplication>
#include "App.h"
//#include "BTC.h"
//#include "Util.h"
int main(int argc, char *argv[])
{
    App app(argc, argv);

    //BTC::ByteArray b = {1,2,3,4}, b2 = { 5, 6, 7, 8, 9};
    //auto c = b + b2 + "12345";

    //Debug() << "Got: " << c.toHex();
    //return 0;

    return app.exec();
}
