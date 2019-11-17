#include "Mgr.h"
#include "Util.h"

#include <QThread>
#include <QTimer>

#include <cassert>
#include <memory>

Mgr::Mgr(QObject *parent)
    : QObject(parent)
{
    assert(qobj()); // Runtime check that derived class followed the rules outlined at the top of Mixins.h
}

Mgr::~Mgr()
{
}
