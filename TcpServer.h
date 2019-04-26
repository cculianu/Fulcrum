#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <QTcpServer>
#include <QThread>
#include "Common.h"
#include "Util.h"

struct TcpServerError : public Exception
{
    using Exception::Exception; /// bring in c'tor
    ~TcpServerError(); // for vtable
};

/// Custom implementation of QTcpServer, which has its own thread
/// All new connections are in the thread context.
/// TODO: Implement optional SSL.
class TcpServer : public QTcpServer
{
    Q_OBJECT
public:
    TcpServer(const QHostAddress & address, quint16 port);
    virtual ~TcpServer() override;

    QString prettyName() const;
    QString hostPort() const;

    void tryStart(); /// may raise Exception if cannot bind, etc. Blocks waiting for thread to listen and return ok/error status.
    void stop(); /// stop listening, kills all connections

signals:

public slots:

protected:
    QThread _thread;

private slots:
    void on_finished();
    void on_started();
    void on_newConnection();

private:
    QHostAddress addr;
    quint16 port;
    Util::Channel<QString> chan;
};

#endif // TCPSERVER_H
