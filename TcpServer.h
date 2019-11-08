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
/// (minimally, override on_newConnection to handle new connections)
class AbstractTcpServer : public QTcpServer, protected ThreadObjectMixin, public IdMixin
{
    Q_OBJECT
public:
    AbstractTcpServer(const QHostAddress & listenAddress, quint16 port);
    virtual ~AbstractTcpServer() override;

    void tryStart(); ///< may raise Exception if cannot bind, etc. Blocks waiting for thread to listen and return ok/error status.
    using ThreadObjectMixin::stop; /// promote this back up to public

    virtual QString prettyName() const;
    QString hostPort() const;

    static QString prettySock(QAbstractSocket *sock);

protected:
    /// derived classes must minimally implement this pure virtual to handle connections
    virtual void on_newConnection(QTcpSocket *) = 0;
    virtual void on_acceptError(QAbstractSocket::SocketError);
    // from ThreadObjectMixin
    QObject* qobj() override { return this; }
    void on_started() override;
    void on_finished() override;

    QHostAddress addr;
    quint16 port;
private slots:
    void pvt_on_newConnection();
};


class SimpleHttpServer : public AbstractTcpServer
{
public:
    static constexpr qint64 DEFAULT_MAX_BUFFER = 1000000;
    static constexpr qint64 DEFAULT_TIMELIMIT_MSEC = 10000;

    SimpleHttpServer(const QHostAddress &listenAddr, quint16 listenPort,
                     qint64 maxBuffer = DEFAULT_MAX_BUFFER,
                     qint64 connectionTimeLimit = DEFAULT_TIMELIMIT_MSEC );

    const qint64 MAX_BUFFER = DEFAULT_MAX_BUFFER;
    const qint64 TIME_LIMIT = DEFAULT_TIMELIMIT_MSEC;

    QString prettyName() const override;

    /* other methods not supported for now */
    enum class Method { GET, POST };

    struct Request {
        QString httpVersion = "HTTP/1.1";
        Method method = Method::GET;
        QMap<QString, QString> header; // headers that came in
        QString endPoint; // eg /stats
        QString queryString; // eg everything after the ? bla=1&foo=bar

        struct Response {
            int status = 200;
            QByteArray statusText = "Success";
            QByteArray contentType = "text/plain; charset=utf-8";
            QByteArray headerExtra = "Cache-Control: no-cache\r\n"; // make sure each line ends with \r\n, if you put response headers
            QByteArray data; ///< set this in your lambda
        };
        Response response;
    };

    typedef std::function<void(Request &)> Lambda;

    void addEndpoint(const QString &endPoint, // eg "/stats" "*" is a special catch-all endpoint for everything else not specified in other endpoints.
                     const Lambda &callback);
    void set404Message(const QString &msg) { err404Msg = msg; }

protected:
    void on_newConnection(QTcpSocket *) override;

    QString err404Msg = "Unknown resource";
    QMap<QString, Lambda> endPoints;
};

/// Implements the ElectrumX/ElectronX protocol
/// TODO: Implement optional SSL.
class Server : public AbstractTcpServer
{
    Q_OBJECT
public:
    Server(const QHostAddress & address, quint16 port);
    ~Server() override;

    virtual QString prettyName() const override;
    const RPC::MethodMap & rpcMethods() const { return rpc_methods; }

signals:
    void clientDisconnected(qint64 clientId);

    /// these are emitted from Controller and are connected to private slots we handle in our thread.
    void tellClientScriptHashStatus(qint64 clientId, const RPC::Message::Id & refId, const QByteArray & status, const QByteArray & scriptHash = QByteArray());

public slots:
    void onMessage(qint64 clientId, const RPC::Message &m);
    void onErrorMessage(qint64 clientId, const RPC::Message &m);
    void onPeerError(qint64 clientId, const QString &what);

private:
    void on_started() override;
    void on_newConnection(QTcpSocket *) override;

private slots:

    // connected to signals above, runs in our thread. Note if not scriptHash.isNull(), will send a notification
    // (without including refId), otherwise sends a response with refId included.
    void _tellClientScriptHashStatus(qint64 clientId, const RPC::Message::Id & refId, const QByteArray & status, const QByteArray & scriptHash = QByteArray());

private:
    Client * newClient(QTcpSocket *);
    inline Client * getClient(qint64 clientId) {
        if (auto it = clientsById.find(clientId); it != clientsById.end())
            return it.value();
        return nullptr;
    }
    void killClient(Client *);
    void killClient(qint64 id);
    QMap<qint64, Client *> clientsById;

private:
    // RPC methods below
    void rpc_server_ping(Client *, const RPC::Message &);
    void rpc_server_version(Client *, const RPC::Message &);
    void rpc_blockchain_scripthash_subscribe(Client *, const RPC::Message &);

    using RpcMember_t = void (Server::*)(Client *, const RPC::Message &); ///< ptr to member function

    static const QMap<QString, RpcMember_t> rpc_method_dispatch;
    static const RPC::MethodMap rpc_methods;

    void assertRpcTablesOk(); // will call std::_Exit if above tables are not self-consistent
};


/// Encapsulates an EXClient
/// These run and live in EXServer's thread
/// Note that their parent QObject is the sock (for now)!
/// (grandparent is TcpServer) .. so they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public RPC::Connection
{
    Q_OBJECT
public:
    /// NB: sock should be in an already connected state.
    explicit Client(const RPC::MethodMap & methods, qint64 id, Server *srv, QTcpSocket *sock);
    ~Client() override;

    struct Info {
        int errCt = 0;
        QString userAgent, protocolVersion;
    };

    Info info;

protected:

    void do_ping() override;
    void do_disconnect(bool graceful = false) override;

    Server *srv;
    friend class Server;
};

#endif // TCPSERVER_H
