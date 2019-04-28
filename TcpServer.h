#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "Common.h"
#include "Util.h"
#include "Mixins.h"
#include <QTcpServer>
#include <QThread>
#include <QMap>

class Client;

struct TcpServerError : public Exception
{
    using Exception::Exception; /// bring in c'tor
    ~TcpServerError(); // for vtable
};

/// Custom implementation of QTcpServer, which has its own thread
/// All new connections are in the thread context.
/// TODO: Implement optional SSL.
class TcpServer : public QTcpServer, public IdMixin
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

    Client * newClient(QTcpSocket *);
    inline Client * getClient(qint64 id) {
        if (auto it = clientsById.find(id); it != clientsById.end())
            return it.value();
        return nullptr;
    }
    void killClient(Client *);
    void killClient(qint64 id);
    QMap<qint64, Client *> clientsById;
};


/// These run and live in TcpServer's thread
/// Note that their parent QObject is the sock (for now)!
/// (grandparent is TcpServer) .. do they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public QObject
{
    Q_OBJECT
public:
    explicit Client(qint64 id, TcpServer *srv, QTcpSocket *sock);
    ~Client() override;

    const qint64 id;

protected:
    TcpServer *srv;
    QTcpSocket *sock;
    friend class TcpServer;
};

#endif // TCPSERVER_H
