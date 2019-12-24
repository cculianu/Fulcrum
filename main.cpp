#include <QCoreApplication>
#include "App.h"

int main(int argc, char *argv[])
{
    App::miscPreAppFixups();
    App app(argc, argv);

    return app.exec();
}
