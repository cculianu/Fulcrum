#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "Common.h"
#include "Util.h"
#include "Mixins.h"
#include "RPC.h"
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

    const RPC::MethodMap & rpcMethods() const { return _rpcMethods; }

signals:

public slots:
    void onMessage(qint64 clientId, const RPC::Message &m);
    void onErrorMessage(qint64 clientId, const RPC::Message &m);
    void onPeerError(qint64 clientId, const QString &what);

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
    inline Client * getClient(qint64 clientId) {
        if (auto it = clientsById.find(clientId); it != clientsById.end())
            return it.value();
        return nullptr;
    }
    void killClient(Client *);
    void killClient(qint64 id);
    QMap<qint64, Client *> clientsById;

    RPC::MethodMap _rpcMethods;
    void setupMethods();

    bool processSpec(qint64 clientId, const RPC::Message &m, QString & errMsg);
};


/// These run and live in TcpServer's thread
/// Note that their parent QObject is the sock (for now)!
/// (grandparent is TcpServer) .. so they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public RPC::Connection
{
    Q_OBJECT
public:
    /// NB: sock should be in an already connected state.
    explicit Client(const RPC::MethodMap & methods, qint64 id, TcpServer *srv, QTcpSocket *sock);
    ~Client() override;

    struct Info {
        int errCt = 0;
        QString userAgent, protocolVersion;
    };

    Info info;

protected:

    void do_ping() override;
    void do_disconnect(bool graceful = false) override;

    TcpServer *srv;
    friend class TcpServer;
};

#endif // TCPSERVER_H
