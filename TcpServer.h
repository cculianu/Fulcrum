#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "Common.h"
#include "Util.h"
#include "Mixins.h"
#include "AbstractConnection.h"
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
class TcpServer : public QTcpServer, protected ThreadObjectMixin, public IdMixin
{
    Q_OBJECT
public:
    TcpServer(const QHostAddress & address, quint16 port);
    ~TcpServer() override;

    QString prettyName() const;
    QString hostPort() const;

    void tryStart(); ///< may raise Exception if cannot bind, etc. Blocks waiting for thread to listen and return ok/error status.
    using ThreadObjectMixin::stop; /// promote this back up to public

signals:

public slots:

private:
    QObject* qobj() override { return this; }
    void on_started() override;
    void on_finished() override;

private slots:
    void on_newConnection();

private:
    QHostAddress addr;
    quint16 port;

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
class Client : public AbstractConnection
{
    Q_OBJECT
public:
    /// NB: sock should be in an already connected state.
    explicit Client(qint64 id, TcpServer *srv, QTcpSocket *sock);
    ~Client() override;

protected slots:
    void on_readyRead() override;

protected:
    void do_ping() override;
    void disconnect(bool graceful = false) override;

    TcpServer *srv;
    friend class TcpServer;
};

#endif // TCPSERVER_H
