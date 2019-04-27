#include "Mgr.h"

Mgr::Mgr(QObject *parent)
    : QObject(parent)
{
}

Mgr::~Mgr()
{
}

Mgr::Stats
Mgr::stats() const
{
    return Stats();
}
