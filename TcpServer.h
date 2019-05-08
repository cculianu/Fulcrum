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
struct ShuffleSpec;

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

/// TODO: Implement optional SSL.
class TcpServer : public AbstractTcpServer
{
    Q_OBJECT
public:
    TcpServer(const QHostAddress & address, quint16 port);
    ~TcpServer() override;

    virtual QString prettyName() const override;
    const RPC::MethodMap & rpcMethods() const { return _rpcMethods; }

signals:
    void newShuffleSpec(const ShuffleSpec &);
    void clientDisconnected(qint64 clientId);

    /// these are emitted from Controller and are connected to private slots we handle in our thread.
    void tellClientSpecRejected(qint64 clientId, qint64 refId, const QString & reason); // if refId != NO_ID, results in error sent to client with message reason.  Otherwise will be a 'notification' with the error message in the params
    void tellClientSpecAccepted(qint64 clientId, qint64 refId); // results in "accepted" sent to client as result if refId != NO_ID, otherwise will be a notification with 'params : ["accepted"]'
    void tellClientSpecPending(qint64 clientId, qint64 refId); // results in "pending" sent to client as result if refId != NO_ID, otherwise will be a notification with 'params : ["pending"]'

public slots:
    void onMessage(qint64 clientId, const RPC::Message &m);
    void onErrorMessage(qint64 clientId, const RPC::Message &m);
    void onPeerError(qint64 clientId, const QString &what);

private:
    void on_started() override;
    void on_newConnection(QTcpSocket *) override;

private slots:

    // connected to signals above, runs in our thread. Note refId == NO_ID sends JSON RPC notifications, not JSON RPC results/error.
    void _tellClientSpecRejected(qint64 clientId, qint64 refId, const QString & reason);
    void _tellClientSpecAccepted(qint64 clientId, qint64 refId);
    void _tellClientSpecPending(qint64 clientId, qint64 refId);

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
