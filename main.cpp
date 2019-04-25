#include <QCoreApplication>
#include "App.h"
#include "BTC.h"

int main(int argc, char *argv[])
{
    return BTC::Address::test();
    App app(argc, argv);

    return app.exec();
}
