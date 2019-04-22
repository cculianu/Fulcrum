#include "EXClient.h"
#include "EXMgr.h"
#include "Util.h"
#include <QtNetwork>
EXClient::EXClient(EXMgr *mgr, const QString &host, int tport, int sport)
    : QObject(nullptr), host(host), tport(tport), sport(sport), mgr(mgr)
{
    Debug() << __FUNCTION__ << " host:" << host << " t:" << tport << " s:" << sport;
    thread.setObjectName(QString("%1 %2").arg("EXClient").arg(host));
}

EXClient::~EXClient()
{
    Debug() << __FUNCTION__ << " host:" << host;
    stop();
}

void EXClient::start()
{
    if (thread.isRunning()) return;
    Debug() << host << " starting thread";
    moveToThread(&thread);
    connect(&thread, &QThread::started, []{
        Debug() << "started";
    });
    connect(&thread, &QThread::finished, []{
        Debug() << "finished.";
    });
    thread.start();
}

void EXClient::stop()
{
    if (socket && socket->state() != QAbstractSocket::UnconnectedState) {
        Debug() << host << " aborting connection";
        socket->abort();
    }
    if (thread.isRunning()) {
        Debug() << host << " thread is running, joining thread";
        thread.quit();
        thread.wait();
    }
    if (socket) { delete socket; socket = nullptr; }
}
