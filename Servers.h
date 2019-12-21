#ifndef SERVERS_H
#define SERVERS_H

#include "Common.h"
#include "Util.h"
#include "Mixins.h"
#include "RPC.h"
#include <QTcpServer>
#include <QThread>
#include <QMap>
#include <QVector>

#include <memory> // for shared_ptr

struct TcpServerError : public Exception
{
    using Exception::Exception; /// bring in c'tor
    ~TcpServerError(); // for vtable
};

/// Custom implementation of QTcpServer, which has its own thread
/// All new connections are in the thread context.
/// (minimally, override on_newConnection to handle new connections)
class AbstractTcpServer : public QTcpServer, public ThreadObjectMixin, public IdMixin
{
    Q_OBJECT
public:
    AbstractTcpServer(const QHostAddress & listenAddress, quint16 port);
    virtual ~AbstractTcpServer() override;

    void tryStart(ulong timeout_ms = ULONG_MAX); ///< may raise Exception if cannot bind, etc. Blocks waiting for thread to listen and return ok/error status.
    using ThreadObjectMixin::stop; /// promote this back up to public

    virtual QString prettyName() const;
    QString hostPort() const;

    static QString prettySock(QAbstractSocket *sock);

protected:
    /// derived classes must minimally implement this pure virtual to handle connections
    virtual void on_newConnection(QTcpSocket *) = 0;
    virtual void on_acceptError(QAbstractSocket::SocketError);
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


class BitcoinDMgr;
class Client;
class Storage;
/// Implements the ElectrumX/ElectronX protocol
/// TODO: Implement optional SSL.
class Server : public AbstractTcpServer
{
    Q_OBJECT
public:
    Server(const QHostAddress & address, quint16 port, std::shared_ptr<Storage> storage, std::shared_ptr<BitcoinDMgr> bitcoindmgr);
    ~Server() override;

    virtual QString prettyName() const override;
    static const RPC::MethodMap & rpcMethods() { return StaticData::methodMap; }

    // this must be called in the thread context of this thread
    QVariantMap stats() const;

signals:
    void clientDisconnected(quint64 clientId);

    /// these are emitted from Controller and are connected to private slots we handle in our thread.
    void tellClientScriptHashStatus(quint64 clientId, const RPC::Message::Id & refId, const QByteArray & status, const QByteArray & scriptHash = QByteArray());

    /// Connected to SrvMgr parent's "newHeader" signal (which itself is connected to Controller's newHeader).
    /// Used to notify clients that are subscribed to headers that a new header has arrived.
    void newHeader(unsigned height, const QByteArray &header);
public slots:
    void onMessage(quint64 clientId, const RPC::Message &m);
    void onErrorMessage(quint64 clientId, const RPC::Message &m);
    void onPeerError(quint64 clientId, const QString &what);

private:
    void on_started() override;
    void on_newConnection(QTcpSocket *) override;

private slots:

    // connected to signals above, runs in our thread. Note if not scriptHash.isNull(), will send a notification
    // (without including refId), otherwise sends a response with refId included.
    void _tellClientScriptHashStatus(quint64 clientId, const RPC::Message::Id & refId, const QByteArray & status, const QByteArray & scriptHash = QByteArray());

private:
    Client * newClient(QTcpSocket *);
    inline Client * getClient(quint64 clientId) {
        if (auto it = clientsById.find(clientId); it != clientsById.end())
            return it.value();
        return nullptr;
    }
    void killClient(Client *);
    void killClient(quint64 id);
    QMap<quint64, Client *> clientsById;

private:
    struct RPCError : public Exception {
        RPCError(const QString & message, int code = RPC::ErrorCodes::Code_App_BadRequest)
            : Exception(message), code(code) {}
        const int code;
        ~RPCError () override;
    };

    using AsyncWorkFunc = std::function<QVariant()>;
    using BitcoinDSuccessFunc = std::function<QVariant(const RPC::Message &)>;
    using BitcoinDErrorFunc = std::function<void(const RPC::Message &)>; // errfunc should always throw RPCError to indicate the exact error it wants to send.

    /// used by some of the slower rpc methods to do work in a threadpool thread. this returns right away but schedules
    /// the work for later and handles sending the response (returned from work) to the client as well as sending
    /// any errors to the client. the `work` functor may throw RPCError, in which case code and message will be
    /// sent instead.  Note that all other exceptions also end up sent to the client as "internal error: MESSAGE".
    void generic_do_async(Client *client, const RPC::Message::Id &reqId,  const AsyncWorkFunc & work);
    void generic_async_to_bitcoind(Client *client,
                                   const RPC::Message::Id & reqId,  ///< the original client request id
                                   const QString &method,
                                   const QVariantList &params,
                                   const BitcoinDSuccessFunc & successFunc,
                                   const BitcoinDErrorFunc & errorFunc = BitcoinDErrorFunc());
    // RPC methods below
    // server
    void rpc_server_ping(Client *, const RPC::Message &);
    void rpc_server_version(Client *, const RPC::Message &);
    // blockchain misc
    void rpc_blockchain_block_header(Client *, const RPC::Message &);  // fully implemented
    void rpc_blockchain_block_headers(Client *, const RPC::Message &); // todo: cp_height
    void rpc_blockchain_estimatefee(Client *, const RPC::Message &); // todo: this is a stub implementation
    void rpc_blockchain_headers_subscribe(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_relayfee(Client *, const RPC::Message &); // todo: this is a stub implementation
    // scripthash
    void rpc_blockchain_scripthash_get_balance(Client *, const RPC::Message &); // partially implemented -- needs unconfirmed balance
    void rpc_blockchain_scripthash_get_history(Client *, const RPC::Message &); // partially implemented -- needs mempool tx's
    [[noreturn]] void rpc_blockchain_scripthash_get_mempool(Client *, const RPC::Message &); // not yet implemented -- needs mempool subsystem
    void rpc_blockchain_scripthash_listunspent(Client *, const RPC::Message &); // partially implemented -- needs mempool tx's
    [[noreturn]] void rpc_blockchain_scripthash_subscribe(Client *, const RPC::Message &); // not implemented yet
    void rpc_blockchain_scripthash_unsubscribe(Client *, const RPC::Message &); // not implemented yet -- stub impl. always returns true, requires suscribe to work first
    // transaction
    void rpc_blockchain_transaction_broadcast(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get_merkle(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_id_from_pos(Client *, const RPC::Message &); // fully implemented
    // mempool
    void rpc_mempool_get_fee_histogram(Client *, const RPC::Message &); // not implemented yet, returns empty list always

    /// Basically a namespace for our rpc dispatch tables, etc
    struct StaticData {
        using Member_t = void (Server::*)(Client *, const RPC::Message &); ///< ptr to member function

        struct MethodMember : public RPC::Method { Member_t member = nullptr; }; ///< used to associate the method spec with a pointer to member

        // the below two get populated at app init by the above rpc_method_registry table
        /// Dispatch tables of "rpc.method.name" -> pointer to method
        static QMap<QString, Member_t> dispatchTable;
        /// method spec for RPC::Connection class interface to know what to accept/reject
        static RPC::MethodMap methodMap;
        /// This static data is used to build the above two static tables at app init
        static const QVector<MethodMember> registry;

        static void init(); ///< called by Server c'tor. (First time it's called it populates the above tables from the 'registry' table)
        StaticData() = delete; ///< unconstructible class! :D
    };

    /// pointer to shared Storage object -- owned and controlled by the Controller instance
    std::shared_ptr<Storage> storage;
    /// pointer to shared BitcoinDMgr object -- owned and controlled by the Controller instance
    std::shared_ptr<BitcoinDMgr> bitcoindmgr;
};


/// Encapsulates a Electron Cash (Electrum) Client
/// These run and live in 'Server' instance thread
/// Note that their parent QObject is the socket!
/// (grandparent is Server) .. so they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public RPC::LinefeedConnection
{
    Q_OBJECT
public:
    /// NB: sock should be in an already connected state.
    explicit Client(const RPC::MethodMap & methods, quint64 id, Server *srv, QTcpSocket *sock);
    ~Client() override;

    struct Info {
        int errCt = 0; ///< this gets incremented for each peerError. If errCt - nRequests >= 10, then we disconnect the client.
        int nRequestsRcv = 0; ///< the number of request messages that were non-errors that the client sent us
        QString userAgent = "Unknown", protocolVersion = "";
    };

    Info info;

    bool isSubscribedToHeaders = false;

protected:

    void do_ping() override;
    void do_disconnect(bool graceful = false) override;

    Server *srv;
    friend class Server;
};

#endif // SERVERS_H
