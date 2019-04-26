#include "TcpServer.h"
#include <QCoreApplication>
#include <QtNetwork>

TcpServerError::~TcpServerError() {} // for vtable

TcpServer::TcpServer(const QHostAddress &a, quint16 p)
    : QTcpServer(nullptr), addr(a), port(p)
{
    _thread.setObjectName(prettyName());
}

TcpServer::~TcpServer()
{
    Debug() << __FUNCTION__;
    stop();
}

QString TcpServer::hostPort() const
{
    return QString("%1:%2").arg(addr.toString()).arg(port);
}

QString TcpServer::prettyName() const
{
    return QString("Srv %1").arg(hostPort());
}

void TcpServer::tryStart()
{
    if (!_thread.isRunning()) {
        chan.clear();
        moveToThread(&_thread);
        connect(&_thread, SIGNAL(started()), this, SLOT(on_started()));
        connect(&_thread, SIGNAL(finished()), this, SLOT(on_finished()));
        _thread.start();
        Log() << "Starting listener service for " << hostPort() << " ...";
        if (auto result = chan.get(); result != "ok") {
            result = result.isEmpty() ? "Startup timed out!" : result;
            throw TcpServerError(result);
        }
        Log() << "Service started, listening for connections on " << hostPort();
    } else {
        throw TcpServerError(prettyName() + " already started");
    }
}

void TcpServer::stop()
{
    if (_thread.isRunning()) {
        Debug() << prettyName() << " thread is running, joining thread";
        _thread.quit();
        _thread.wait();
    }
    disconnect(&_thread, SIGNAL(started()), this, SLOT(on_started()));
    disconnect(&_thread, SIGNAL(finished()), this, SLOT(on_finished()));
}

void TcpServer::on_started()
{
    QString result = "ok";
    connect(this, SIGNAL(newConnection()), this, SLOT(on_newConnection()));
    if (!listen(addr, port)) {
        result = errorString();
        result = result.isEmpty() ? "Error binding/listening for connections" : result;
        Debug() << __FUNCTION__ << " listen failed";
    } else {
        Debug() << "started ok";
    }
    chan.put(result);
}

void TcpServer::on_finished()
{
    disconnect(this, SIGNAL(newConnection()), this, SLOT(on_newConnection()));
    close(); /// stop listening
    chan.put("finished");
    Debug() << __FUNCTION__ << " finished.";
    moveToThread(qApp->thread());
}

static inline QString prettySock(QAbstractSocket *sock)
{
    return QString("%1:%2")
            .arg(sock ? sock->peerAddress().toString() : "(null)")
            .arg(sock ? sock->peerPort() : 0);
}

void TcpServer::on_newConnection()
{
    QTcpSocket *sock = nextPendingConnection();
    if (sock) {
        Debug() << "Got connection from: " << prettySock(sock);
        // Testing....
        sock->abort();
        sock->deleteLater();
    } else {
        Warning() << __FUNCTION__ << ": nextPendingConnection returned a nullptr! Called at the wrong time? FIXME!";
    }
}
