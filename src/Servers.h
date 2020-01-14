//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
#pragma once

#include "Common.h"
#include "Mixins.h"
#include "Options.h"
#include "PeerMgr.h"
#include "RPC.h"
#include "Util.h"
#include "Version.h"

#include <QHash>
#include <QSslCertificate>
#include <QSslKey>
#include <QTcpServer>
#include <QThread>
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

    /// not garanteed thread-safe
    virtual QString prettyName() const;
    QString hostPort() const;

    static QString prettySock(QAbstractSocket *sock);

protected:
    /// derived classes must minimally implement this pure virtual to handle connections
    virtual void on_newConnection(QTcpSocket *) = 0;
    virtual void on_acceptError(QAbstractSocket::SocketError);
    void on_started() override;
    void on_finished() override;

    const QHostAddress addr;
    const quint16 port;
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
        QHash<QString, QString> header; // headers that came in
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
    QHash<QString, Lambda> endPoints;
};

class BitcoinDMgr;
class Client;
class Storage;

/// Base class for the Electrum-server-style linefeed-based JSON-RPC service.
///
/// This base class knows how to handle clients and how to dispatch messages. It offers all the facilities an RPC
/// server endpoint in this program would need to serve clients.  All that it lacks to actually do so are a dispatch
/// table of RPC methods.  A concrete class that uses this base is the Server subcless which implements a set of RPC
/// methods (used for serving to Electron Cash SPV clients).
class ServerBase : public AbstractTcpServer, public StatsMixin
{
    Q_OBJECT
protected:
    using Member_t = void (ServerBase::*)(Client *, const RPC::Message &); ///< ptr to member function
    using DispatchTable = QHash<QString, Member_t>; ///< this dispatch table mechanism which relies on ptr to member is a slight performance optimization over std::function with std::bind

    const RPC::MethodMap & methods; ///< must be valid for the lifetime of this instance
    const DispatchTable & dispatchTable; ///< must be valid for the lifetime of this instance

    /// This class can only be inherited from. Cannot be directly constructed.
    /// The `rpcMethods` reference needs to be valid for the lifetime of this instance.
    /// The `dispatchTable` reference needs to be valid for the lifetime of this instance.
    /// It's ok to pass a reference to empty containers for both `rpcMethods` and `dispatchTable` so long as
    /// that data gets filled-in later before the server is started via `tryStart()`.
    /// It is undefined to modify those structures after `tryStart()` has been called, however.
    ServerBase(const RPC::MethodMap & rpcMethods, const DispatchTable & dispatchTable,
               const QHostAddress & address, quint16 port,
               const std::shared_ptr<const Options> & options,
               const std::shared_ptr<Storage> & storage,
               const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ServerBase() = delete; ///< just to drive the "do not construct me" point home further. :)

public:
    ~ServerBase() override;

    inline const RPC::MethodMap & rpcMethods() const { return methods; }

    /// From StatsMixin. This must be called in the thread context of this thread (use statsSafe() for the blocking, thread-safe version!)
    QVariant stats() const override;

signals:
    /// connected to SrvMgr clientConnected slot by SrvMgr class
    void clientConnected(IdMixin::Id clientId, const QHostAddress & remoteAddress);
    /// connected to SrvMgr clientDisconnected slot by SrvMgr class
    void clientDisconnected(IdMixin::Id clientId, const QHostAddress & remoteAddress);

    /// Inform PeerMgr of new add_peer request coming in
    void gotRpcAddPeer(const PeerInfoList &, const QHostAddress &source);

public slots:
    /// Kills the client immediately and ungracefully. Silently ignores request to kill clients for clientIds not found.
    /// This is used internally and is also connected to the clientExceedsConnectionLimit signal by SrvMgr.
    /// Must be called from this object's thread.
    void killClient(IdMixin::Id id);

    /// Kick/Ban support -- kill clients matching a paricular remote address (this isn't called by anything yet but
    /// is in place for later when we add per-IP bans and per-IP kicking). Must be called from this object's thread.
    void killClientsByAddress(const QHostAddress &);

    /// Updates the internal peer list we cache. This is called as a result of PeerMgr::updated() being emitted which
    /// the SrvMgr automatically connects us to.
    void onPeersUpdated(const PeerInfoList &);

protected slots:
    void onMessage(IdMixin::Id clientId, const RPC::Message &m);
    void onErrorMessage(IdMixin::Id clientId, const RPC::Message &m);
    void onPeerError(IdMixin::Id clientId, const QString &what);

    void refreshBitcoinDNetworkInfo(); ///< whenever bitcoind comes back alive, this is invoked to update the BitcoinDInfo struct declared above

protected:
    void on_started() override;
    void on_newConnection(QTcpSocket *) override;

    Client * newClient(QTcpSocket *);
    inline Client * getClient(IdMixin::Id clientId) {
        if (auto it = clientsById.find(clientId); it != clientsById.end())
            return it.value();
        return nullptr;
    }
    void killClient(Client *);
    QHash<IdMixin::Id, Client *> clientsById;

    struct RPCError : public Exception {
        RPCError(const QString & message, int code = RPC::ErrorCodes::Code_App_BadRequest, bool disconnect = false)
            : Exception(message), code(code), disconnect(disconnect) {}
        const int code;
        const bool disconnect;
        ~RPCError () override;
    };
    struct RPCErrorWithDisconnect : public RPCError {
        RPCErrorWithDisconnect(const QString &message) : RPCError(message, RPC::ErrorCodes::Code_App_BadRequest, true) {}
        ~RPCErrorWithDisconnect() override;
    };

    using AsyncWorkFunc = std::function<QVariant()>;
    using BitcoinDSuccessFunc = std::function<QVariant(const RPC::Message &)>;
    using BitcoinDErrorFunc = std::function<void(const RPC::Message &)>; // errfunc should always throw RPCError to indicate the exact error it wants to send.

    /// Used by some of the slower rpc methods to do work in a threadpool thread. This returns right away but schedules
    /// the work for later and handles sending the response (returned from work) to the client as well as sending
    /// any errors to the client. The `work` functor may throw RPCError, in which case code and message will be
    /// sent instead.  Note that all other exceptions also end up sent to the client as "internal error: MESSAGE".
    void generic_do_async(Client *client, const RPC::Message::Id &reqId,  const AsyncWorkFunc & work, int priority = 0);
    void generic_async_to_bitcoind(Client *client,
                                   const RPC::Message::Id & reqId,  ///< the original client request id
                                   const QString &method, ///< bitcoind method to invoke
                                   const QVariantList &params, ///< params for bitcoind method
                                   const BitcoinDSuccessFunc & successFunc,
                                   const BitcoinDErrorFunc & errorFunc = BitcoinDErrorFunc());

    /// pointer to the shared Options object -- app-wide configuration settings. Owned and controlled by the App instance.
    const std::shared_ptr<const Options> options;
    /// pointer to shared Storage object -- owned and controlled by the Controller instance
    const std::shared_ptr<Storage> storage;
    /// pointer to shared BitcoinDMgr object -- owned and controlled by the Controller instance
    const std::shared_ptr<BitcoinDMgr> bitcoindmgr;

    /// This basically all comes from getnetworkinfo to bitcoind.
    struct BitcoinDInfo {
        Version version {0,0,0}; ///> major, minor, revision e.g. {0, 20, 6} for v0.20.6
        QString subversion; ///< subversion string from daemon e.g.: /BitcoinABC bla bla;EB32 ..../
        double relayFee = 0.0; ///< from 'relayfee' in the getnetworkinfo response; minimum fee/kb to relay a tx, usually: 0.00001000
        QString warnings = ""; ///< from 'warnings' in the getnetworkinfo response (usually is empty string, but may not always be)
    };
    BitcoinDInfo bitcoinDInfo;

    PeerInfoList peers;
};

/// Implements the ElectrumX/ElectronX JSON-RPC protocol, version 1.4.2.
/// See also ServerSSL (subclass) which is identical but serves to SSL clients.  (This class serves to TCP clients).
class Server : public ServerBase
{
    Q_OBJECT
public:
    Server(const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
           const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ~Server() override;

    /// This is refactored code that is called both from here (rpc_server_features) and from the PeerMgr
    /// which also needs a features dict when *it* calls add_peer on peer servers.
    /// NOTE: Be sure to only ever call this function from the same thread as the AbstractConnection (first arg) instance!
    static QVariantMap makeFeaturesDictForConnection(AbstractConnection *, const QByteArray &genesisHash, const Options & options);

    virtual QString prettyName() const override;

signals:
    /// Connected to SrvMgr parent's "newHeader" signal (which itself is connected to Controller's newHeader).
    /// Used to notify clients that are subscribed to headers that a new header has arrived.
    void newHeader(unsigned height, const QByteArray &header);

    /// Emitted for the SrvMgr to update its counters of the number of tx's successfully broadcast.  The argument
    /// is a size in bytes.
    void broadcastTxSuccess(unsigned);

private:
    // RPC methods below
    // server
    void rpc_server_add_peer(Client *, const RPC::Message &); // fully implemented
    void rpc_server_banner(Client *, const RPC::Message &); // fully implemented (comes from a text file specified by config banner=)
    void rpc_server_donation_address(Client *, const RPC::Message &); // fully implemented (comes from config donation=)
    void rpc_server_features(Client *, const RPC::Message &); // fully implemented (comes from config)
    void rpc_server_peers_subscribe(Client *, const RPC::Message &); // fully implemented
    void rpc_server_ping(Client *, const RPC::Message &); // fully implemented
    void rpc_server_version(Client *, const RPC::Message &); // fully implemented
    // blockchain misc
    void rpc_blockchain_block_header(Client *, const RPC::Message &);  // fully implemented
    void rpc_blockchain_block_headers(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_estimatefee(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_headers_subscribe(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_relayfee(Client *, const RPC::Message &); // fully implemented
    // scripthash
    void rpc_blockchain_scripthash_get_balance(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_get_history(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_get_mempool(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_listunspent(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_subscribe(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_unsubscribe(Client *, const RPC::Message &); // fully implemented
    // transaction
    void rpc_blockchain_transaction_broadcast(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get_merkle(Client *, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_id_from_pos(Client *, const RPC::Message &); // fully implemented
    // mempool
    void rpc_mempool_get_fee_histogram(Client *, const RPC::Message &); // fully implemented

    /// Basically a namespace for our rpc dispatch tables, etc
    struct StaticData {
        struct MethodMember : public RPC::Method { Member_t member = nullptr; }; ///< used to associate the method spec with a pointer to member

        // the below two get populated at app init by the above rpc_method_registry table
        /// Dispatch tables of "rpc.method.name" -> pointer to method
        static DispatchTable dispatchTable;
        /// method spec for RPC::Connection class interface to know what to accept/reject
        static RPC::MethodMap methodMap;
        /// This static data is used to build the above two static tables at app init
        static const QVector<MethodMember> registry;

        static void init(); ///< called by Server c'tor. (First time it's called it populates the above tables from the 'registry' table)
        StaticData() = delete; ///< unconstructible class! :D
    };

    using HeadersBranchAndRootPair = std::pair<QVariantList, QVariant>;
    /// Helper for rpc block_header* methods -- returns the 'branch' and 'root' keys ready to be put in the results dictionary
    HeadersBranchAndRootPair getHeadersBranchAndRoot(unsigned height, unsigned cp_height);

    /// called from get_mempool and get_history to retrieve the mempool and/or history for a hashx synchronously.
    /// Returns the QVariantMap suitable for placing into the resulting response.
    QVariantList getHistoryCommon(const QByteArray & sh, bool mempoolOnly);
};

/// SSL version of the above Server class that just wraps tcp sockets with a QSslSocket.
/// All sockets emitted by newConnection are QSslSocket instances (a subclass of
/// QTcpSocket), thus the connection is encrypted. Requires SSL support + a cert & a private key.
class ServerSSL : public Server
{
    Q_OBJECT
public:
    ServerSSL(const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
              const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ~ServerSSL() override;

    QString prettyName() const override; ///< overrides super to indicate SSL in server name

signals:
    void ready(); ///< emitted when the underlying QSslSocket emits "encrypted"

protected:
    /// overrides QTcpServer to create a QSslSocket wrapping the passed-in file descriptor.
    void incomingConnection(qintptr) override;
private:
    const QSslCertificate cert;
    const QSslKey key;
};

class SrvMgr;

/// The local admin RPC service for sending control commands to Fulcrum.
class AdminServer : public ServerBase
{
public:
    AdminServer(SrvMgr *srvMgr, const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
                const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ~AdminServer() override;

    QString prettyName() const override;

private:
    SrvMgr * const srvmgr; ///< this is alive for the entire lifetime of this instance.

    void rpc_getinfo(Client *, const RPC::Message &);
    void rpc_shutdown(Client *, const RPC::Message &);

    /// Basically a namespace for our rpc dispatch tables, etc, private to this class
    struct StaticData {
        struct MethodMember : public RPC::Method { Member_t member = nullptr; }; ///< used to associate the method spec with a pointer to member

        // the below two get populated at app init by the above rpc_method_registry table
        /// Dispatch tables of "rpc.method.name" -> pointer to method
        static DispatchTable dispatchTable;
        /// method spec for RPC::Connection class interface to know what to accept/reject
        static RPC::MethodMap methodMap;
        /// This static data is used to build the above two static tables at app init
        static const QVector<MethodMember> registry;

        static void init(); ///< called by Server c'tor. (First time it's called it populates the above tables from the 'registry' table)
        StaticData() = delete; ///< unconstructible class! :D
    };
};

/// Encapsulates an Electron Cash (Electrum) Client
/// These run and live in 'Server' instance thread
/// Note that their parent QObject is the socket!
/// (grandparent is Server) .. so they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public RPC::LinefeedConnection
{
    Q_OBJECT
protected:
    /// Only Server instances can construct us
    friend class ::ServerBase;
    friend class ::Server;
    /// NB: sock should be in an already connected state.
    explicit Client(const RPC::MethodMap & methods, IdMixin::Id id, ServerBase *srv, QTcpSocket *sock, int maxBuffer);
public:
    ~Client() override;

    struct Info {
        int errCt = 0; ///< this gets incremented for each peerError. If errCt - nRequests >= 10, then we disconnect the client.
        int nRequestsRcv = 0; ///< the number of request messages that were non-errors that the client sent us

        // server.version info the client sent us
        QString userAgent = "Unknown"; //< the exact useragent string as the client sent us.
        /// may be 0,0,0 if we were unable to parse the above string. Used to detect old EC versions and send them an error string on broadcast to warn them to upgrade.
        inline Version uaVersion() const { return Version(userAgent); }
        Version protocolVersion = {1,4,0}; ///< defaults to 1,4,0 if client says nothing.
        bool alreadySentVersion = false;
    };

    Info info;

    bool isSubscribedToHeaders = false;
    std::atomic_int nShSubs{0};  ///< the number of unique scripthash subscriptions for this client.

    static std::atomic_size_t numClients, numClientsMax, numClientsCtr; // number of connected clients: current, max lifetime, accumulated counter

protected:

    void do_ping() override;
    void do_disconnect(bool graceful = false) override;

    ServerBase *srv;
};
