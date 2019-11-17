#include "Mgr.h"
#include "Util.h"
#include <QTimer>
#include <QThread>
#include <memory>

Mgr::Mgr(QObject *parent)
    : QObject(parent)
{
}

Mgr::~Mgr()
{
}
