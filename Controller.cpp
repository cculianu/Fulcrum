#include "Controller.h"

Controller::Controller(QObject *parent)
    : QObject(parent)
{
}

Controller::~Controller()
{
}

Controller::Stats
Controller::stats() const
{
    return Stats();
}
