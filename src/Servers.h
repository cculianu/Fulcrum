//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "RollingBloomFilter.h"
#include "RPC.h"
#include "Util.h"
#include "Version.h"

#include <QHash>
#include <QSslConfiguration>
#include <QTcpServer>
#include <QThread>
#include <QVector>

#include <memory> // for shared_ptr
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <type_traits>

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

    /// not guaranteed thread-safe
    virtual QString prettyName() const;
    QString hostPort() const;

    static QString prettySock(QAbstractSocket *sock);

    /// Set the objectName and thread objectName to defaults based on the current configuration of the server.  This
    /// is called automatically in the constructor but may need to be set again in subclasses.  Calls prettyName().
    void resetName();

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
class QSslSocket;
class Storage;
class SubsMgr;
class ThreadPool;

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
    using Member_t = void (ServerBase::*)(Client *, RPC::BatchId, const RPC::Message &); ///< ptr to member function
    using DispatchTable = QHash<QString, Member_t>; ///< this dispatch table mechanism which relies on ptr to member is a slight performance optimization over std::function with std::bind

    SrvMgr * const srvmgr; ///< basically a weak reference -- this is guaranteed to be alive for the entire lifetime of this instance, however.
    const RPC::MethodMap & methods; ///< must be valid for the lifetime of this instance
    const DispatchTable & dispatchTable; ///< must be valid for the lifetime of this instance

    /// This class can only be inherited from. Cannot be directly constructed.
    /// The `rpcMethods` reference needs to be valid for the lifetime of this instance.
    /// The `dispatchTable` reference needs to be valid for the lifetime of this instance.
    /// It's ok to pass a reference to empty containers for both `rpcMethods` and `dispatchTable` so long as
    /// that data gets filled-in later before the server is started via `tryStart()`.
    /// It is undefined to modify those structures after `tryStart()` has been called, however.
    ServerBase(SrvMgr *srvMgr,  // the object that owns us
               const RPC::MethodMap & rpcMethods, const DispatchTable & dispatchTable,
               const QHostAddress & address, quint16 port,
               const std::shared_ptr<const Options> & options,
               const std::shared_ptr<Storage> & storage,
               const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ServerBase() = delete; ///< just to drive the "do not construct me" point home further. :)

public:
    ~ServerBase() override;

    /// @returns a reference to the long-lived rpc method map
    const RPC::MethodMap & rpcMethods() const { return methods; }

    /// From StatsMixin. This must be called in the thread context of this thread (use statsSafe() for the blocking, thread-safe version!)
    QVariant stats() const override;

    /// Default false.
    bool usesWebSockets() const { return usesWS; }
    /// This should be called/set once before we begin listening for connections.  Called by SrvMgr depending on options from config.
    virtual void setUsesWebSockets(bool b) { usesWS = b; resetName(); }

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

    /// Connected to SrvMgr::requestMaxBufferChange; Iterates through all clients, applying the newMaxBuffer.
    /// If the new setting is out of bounds, has no effect. See: Options::maxBufferMin & Options::maxBufferMax.
    void applyMaxBufferToAllClients(int newMax);

protected slots:
    void onMessage(IdMixin::Id clientId, RPC::BatchId batchId, const RPC::Message &m);
    void onErrorMessage(IdMixin::Id clientId, const RPC::Message &m);
    void onPeerError(IdMixin::Id clientId, const QString &what);

protected:
    /// Overrides QTcpServer -- identical to default impl. from QTcpServer except it also attaches a child
    /// Client::PerIPDataHolder_Temp object named "__PerIPDataHolder_Temp" to the QTcpSocket that it creates, and
    /// auto-fails the connection if the app-wide per-IP connection limit is exceeded.
    void incomingConnection(qintptr socketDescriptor) override;

    // Helpers used in `incomingConnection` in both this base class and the ServerSSL derived class.
    //

    /// Derived classes that re-implement incomingConnection should call this to attach the Client::PerIPDataHolder_Temp
    /// object. (Or, alternatively, call createSocketFromDescriptorAndCheckLimits).
    ///
    /// Returns false if the connection would exceed limits.
    ///
    /// Note: On false return, socket->abort() and then socket->deleteLater() are called by this function.
    bool attachPerIPDataAndCheckLimits(QTcpSocket *);
    /// Used internally by both this incomingConnection implementation and ServerSSL's implementation.
    /// SockType must be QTcpSocket or QSslSocket.
    template <typename SockType,
              typename = std::enable_if_t< std::is_same_v<QTcpSocket, SockType> || std::is_same_v<QSslSocket, SockType> > >
    SockType *createSocketFromDescriptorAndCheckLimits(qintptr socketDescriptor);
    /// Initiates the WebSocket handshake.  If false is returned, the passed-in socket has already been queued for
    /// deletion. If true is returned, some time later after handshake success, addPendingConnection() will get called
    /// and newConnection() will be emitted.  On handshake failure errors will be logged and the socket object will get
    /// deleted.  Note that a WebSocket::Wrapper will be used to wrap the socket and that will end up being added
    /// to addPendingConnection().
    bool startWebSocketHandshake(QTcpSocket *);
    ///
    // /end `incomingConnection` Helpers

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
    void generic_do_async(Client *client, RPC::BatchId, const RPC::Message::Id &reqId,  const AsyncWorkFunc & work, int priority = 0);
    void generic_async_to_bitcoind(Client *client,
                                   RPC::BatchId batchId, ///< if running in batch context, will be !batchId.isNull()
                                   const RPC::Message::Id & reqId,  ///< the original client request id
                                   const QString &method, ///< bitcoind method to invoke
                                   const QVariantList &params, ///< params for bitcoind method
                                   const BitcoinDSuccessFunc & successFunc,
                                   const BitcoinDErrorFunc & errorFunc = BitcoinDErrorFunc());

    /// Subclasses may set this pointer if they wish the generic_do_async function above to use a private/custom
    /// threadpool. Otherwise the app-global ::AppThreadPool()  will be used for generic_do_async().
    ThreadPool *asyncThreadPool = nullptr;

    /// pointer to the shared Options object -- app-wide configuration settings. Owned and controlled by the App instance.
    const std::shared_ptr<const Options> options;
    /// pointer to shared Storage object -- owned and controlled by the Controller instance
    const std::shared_ptr<Storage> storage;
    /// pointer to shared BitcoinDMgr object -- owned and controlled by the Controller instance
    const std::shared_ptr<BitcoinDMgr> bitcoindmgr;

    PeerInfoList peers;

    /// Default false. If true, derived classes should instead create WebSocket::Wrapper instances of the underlying
    /// QTcpSocket or QSslSocket.  See getter/setter: usesWebSockets and setUsesWebSockets.  Decided by the
    /// "ws" & "wss" config file options and/or the --ws/--wss (-w/-W) CLI args.
    bool usesWS = false;

    /// This is set on construction by querying Storage. Subclasses may use this information at runtime to present
    /// RPC behavior differences between BTC vs BCH vs LTC (e.g. in the address_* RPCs).
    BTC::Coin coin = BTC::Coin::Unknown;
    /// If true we are on the BTC or LTC chains.
    bool isNonBCH() const { return coin != BTC::Coin::BCH; }
    bool isLTC() const { return coin == BTC::Coin::LTC; }
};

/// Implements the ElectrumX/ElectronX JSON-RPC protocol, version 1.4.4.
/// See also ServerSSL (subclass) which is identical but serves to SSL clients.  (This class serves to TCP clients).
class Server : public ServerBase
{
    Q_OBJECT
public:
    Server(SrvMgr *, const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
           const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ~Server() override;

    /// This is refactored code that is called both from here (rpc_server_features) and from the PeerMgr
    /// which also needs a features dict when *it* calls add_peer on peer servers.
    /// NOTE: Be sure to only ever call this function from the same thread as the AbstractConnection (first arg) instance!
    static QVariantMap makeFeaturesDictForConnection(AbstractConnection *, const QByteArray &genesisHash,
                                                     const Options & options, bool hasDSProofRPC, bool hasCashTokens);

    virtual QString prettyName() const override;

    /// override from base -- we add custom stats for things like the bloom filter stats, etc
    QVariant stats() const override;

signals:
    /// Connected to SrvMgr parent's "newHeader" signal (which itself is connected to Controller's newHeader).
    /// Used to notify clients that are subscribed to headers that a new header has arrived.
    void newHeader(unsigned height, const QByteArray &header);

    /// Emitted for the SrvMgr to update its counters of the number of tx's successfully broadcast.  The argument
    /// is a size in bytes.
    void broadcastTxSuccess(unsigned);

    /// Emitted when the SubsMgr throws LimitReached inside rpc_scripthash_subscribe. Conneced to SrvMgr which
    /// will iterate through all perIPData instances and kick the ip address with the most subs.
    void globalSubsLimitReached();

private:
    // RPC methods below
    // server
    void rpc_server_add_peer(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_server_banner(Client *, RPC::BatchId, const RPC::Message &); // fully implemented (comes from a text file specified by config banner=)
    void rpc_server_donation_address(Client *, RPC::BatchId, const RPC::Message &); // fully implemented (comes from config donation=)
    void rpc_server_features(Client *, RPC::BatchId, const RPC::Message &); // fully implemented (comes from config)
    void rpc_server_peers_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_server_ping(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_server_version(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // address (resurrected in protocol 1.4.3)
    void rpc_blockchain_address_get_balance(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_get_history(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_get_mempool(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_get_scripthash(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_listunspent(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_address_unsubscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // blockchain misc
    void rpc_blockchain_block_header(Client *, RPC::BatchId, const RPC::Message &);  // fully implemented
    void rpc_blockchain_block_headers(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_estimatefee(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_headers_get_tip(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_headers_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_headers_unsubscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_relayfee(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // scripthash
    void rpc_blockchain_scripthash_get_balance(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_get_history(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_get_mempool(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_listunspent(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_scripthash_unsubscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // transaction
    void rpc_blockchain_transaction_broadcast(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get_height(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_get_merkle(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_id_from_pos(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_unsubscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // transaction.dsproof
    void rpc_blockchain_transaction_dsproof_get(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_dsproof_list(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_dsproof_subscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    void rpc_blockchain_transaction_dsproof_unsubscribe(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    /* / */
    // utxo
    void rpc_blockchain_utxo_get_info(Client *, RPC::BatchId, const RPC::Message &); // fully implemented
    // mempool
    void rpc_mempool_get_fee_histogram(Client *, RPC::BatchId, const RPC::Message &); // fully implemented

    // Impl. for blockchain.scripthash.* & blockchain.address.* methods (both sets call into these).
    // Note: Validation should have already been done by caller.
    void impl_get_balance(Client *, RPC::BatchId, const RPC::Message &, const HashX &scriptHash, Storage::TokenFilterOption tokenFilter);
    void impl_get_history(Client *, RPC::BatchId, const RPC::Message &, const HashX &scriptHash);
    void impl_get_mempool(Client *, RPC::BatchId, const RPC::Message &, const HashX &scriptHash);
    void impl_listunspent(Client *, RPC::BatchId, const RPC::Message &, const HashX &scriptHash, Storage::TokenFilterOption tokenFilter);
    void impl_generic_subscribe(SubsMgr *, Client *, RPC::BatchId, const RPC::Message &, const HashX &key,
                                const std::optional<QString> & aliasUsedForNotifications = {});
    void impl_generic_unsubscribe(SubsMgr *, Client *, RPC::BatchId, const RPC::Message &, const HashX &key);
    /// Commonly used by above methods.  Takes the first address argument in the m.paramsList() and converts it to
    /// a scripthash, returning the raw bytes.  Will throw RPCError on invalid argument.
    /// It is assumed the caller already ensured m.paramsList() has at least 1 item in it (which the RPC machinery
    /// does normally if the params spec is correctly written).  Validation is done on the argument, however, and
    /// it will throw RPCError in all parse/failure cases and only ever returns a valid scripthash on success.
    HashX parseFirstAddrParamToShCommon(const RPC::Message &m, QString *addrStrOut = nullptr) const;
    /// Commonly used by above methods.  Takes the first hex argument in the m.paramsList() and hes decodes it to
    /// a hash, returning the raw bytes.  Will throw RPCError on invalid argument. The error will be
    /// "Invalid scripthash" unless errMsg is specified, in which case it will be errMsg.
    /// It is assumed the caller already ensured m.paramsList() has at least 1 item in it (which the RPC machinery
    /// does normally if the params spec is correctly written).  Validation is done on the argument, however, and
    /// it will throw RPCError in all parse/failure cases and only ever returns a valid hash on success.
    HashX parseFirstHashParamCommon(const RPC::Message &m, const char *const errMsg = nullptr) const;

    /// Helper used by blockchain.*.listunspent *.get_balance to parse optional 2nd arg
    Storage::TokenFilterOption parseTokenFilterOptionCommon(Client *c, const RPC::Message &m, size_t argPos) const;

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
    QVariantList getHistoryCommon(const HashX & sh, bool mempoolOnly);

    double lastSubsWarningPrintTime = 0.; ///< used internally to rate-limit "max subs exceeded" message spam to log

protected:
    /// Rolling bloom filters used by blockchain.transaction.broadcast to suppress repetitive messages to the log.
    /// There is 1 of these shared amongst all intances of this class, however access to it is thread-safe.
    struct LogFilter {
        class Broadcast {
            mutable std::mutex lock;
            // NOTE: the below must only be accessed with .lock held
            RollingBloomFilter
                success { 1024, 0.000001}, ///<  ~11042 bytes - this filter resets with each new block found
                fail    {16384, 0.000001}; ///< ~176672 bytes - this filter does not reset with each new block found
        public:
            void operator()(bool isSuccess, const QByteArray &logLine, const QByteArray &key);
            QVariantMap stats() const;
            void onNewBlock();
        } broadcast;
    };
    static std::weak_ptr<LogFilter> weakLogFilter;
    std::shared_ptr<LogFilter> logFilter;

public:
    /// Helper function called by blockchain.scripthash.listunspent RPC and by the Controller class for /debug/
    /// @returns A QVariantMap that matches the output of `blockchain.scripthash.listunspent`
    [[nodiscard]] static QVariantMap unspentItemToVariantMap(const Storage::UnspentItem &);
};

/// SSL version of the above Server class that just wraps tcp sockets with a QSslSocket.
/// All sockets emitted by newConnection are QSslSocket instances (a subclass of
/// QTcpSocket), thus the connection is encrypted. Requires SSL support + a cert & a private key.
class ServerSSL : public Server
{
    Q_OBJECT
public:
    ServerSSL(SrvMgr *, const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
              const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr);
    ~ServerSSL() override;

    QString prettyName() const override; ///< overrides super to indicate SSL in server name

    /// override from Server -- we add custom stats for our TLS certificate
    QVariant stats() const override;

    /// Overides ServerBase -- re-sets the SSL config (sometimes WSS uses a different config from regular SSL ports).
    /// Do not call this after the server has already been started.
    void setUsesWebSockets(bool b) override;

public slots:
    /// Normally called from c'tor, but may be called as a result of a connection to SSLCertMonitor's certInfoChanged()
    /// signal.
    void setupSslConfiguration();

protected:
    /// overrides ServerBase to create a QSslSocket wrapping the passed-in file descriptor, and then initiate the TLS
    /// server-side handshake.
    void incomingConnection(qintptr) override;
private:
    QSslConfiguration sslConfiguration;
};

class SrvMgr;

/// The local admin RPC service for sending control commands to Fulcrum.
class AdminServer : public ServerBase
{
public:
    AdminServer(SrvMgr *srvMgr, const QHostAddress & address, quint16 port, const std::shared_ptr<const Options> & options,
                const std::shared_ptr<Storage> & storage, const std::shared_ptr<BitcoinDMgr> & bitcoindmgr,
                const std::weak_ptr<PeerMgr> & peerMgr = {});
    ~AdminServer() override;

    QString prettyName() const override;

protected:
    /// From StatsMixin. This must be called in the thread context of this thread (use statsSafe() for the blocking, thread-safe version!)
    QVariant stats() const override;

private:
    std::unique_ptr<ThreadPool> threadPool; ///< we use our own threadpool for the admin server so as to not interfere with the normal one used for SPV clients.

    const std::weak_ptr<PeerMgr> peerMgr; ///< this isn't always valid if peering is disabled.  SrvMgr owns this, and as the app shuts down it may go away.

    static constexpr int kBlockingCallTimeoutMS = 10000;

    enum BanOp { Kick, Ban, Unban };
    void kickBanBoilerPlate(const RPC::Message &, BanOp);
    void rpc_addpeer(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_ban(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_banpeer(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_bitcoind_throttle(Client *, RPC::BatchId, const RPC::Message &); // getter / setter in 1 method
    void rpc_clients(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_getinfo(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_kick(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_listbanned(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_loglevel(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_maxbuffer(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_peers(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_rmpeer(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_simdjson(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_shutdown(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_unban(Client *, RPC::BatchId, const RPC::Message &);
    void rpc_unbanpeer(Client *, RPC::BatchId, const RPC::Message &);

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

        static void init(); ///< called by AdminServer c'tor. (First time it's called it populates the above tables from the 'registry' table)
        StaticData() = delete; ///< unconstructible class! :D
    };
};

/// Encapsulates an Electron Cash (Electrum) Client
/// These run and live in 'Server' instance thread
/// Note that their parent QObject is the socket!
/// (grandparent is Server) .. so they will be destroyed
/// when the server goes away or the socket is deleted.
class Client : public RPC::ElectrumConnection
{
    Q_OBJECT
protected:
    /// Only Server instances can construct us
    friend class ::ServerBase;
    friend class ::Server;
    /// NB: sock should be in an already connected state. `options` should be guaranteed to outlive this instance.
    explicit Client(const RPC::MethodMap * methods, IdMixin::Id id, QTcpSocket *sock, const Options &options);
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
        unsigned nTxSent = 0, nTxBroadcastErrors = 0, nTxBytesSent = 0;
    };

    Info info;

    /// Data that is per-IP address. This data structure is potentially shared with multiple Client * instances living
    /// in multiple ServerBase instances, in multiple threads.  The table that stores these is in SrvMgr. See SrvMgr.h.
    struct PerIPData {
        mutable std::shared_mutex mut;  ///< guards _whiteListedSubnet

        enum WhiteListState { UNINITIALIZED, WhiteListed, NotWhiteListed };
        std::atomic_int whiteListState{UNINITIALIZED}; ///< used to determine if we should apply limits.
        Options::Subnet _whiteListedSubnet; ///< guarded by mut. Use getter for thread-safe reads. This is only ever valid iff whiteListState == WhiteListed. otherwise .isValid() == false

        inline bool isWhitelisted() const { return whiteListState.load() == WhiteListed; }
        /// Thread-safe getter for _whiteListedSubnet above
        inline Options::Subnet whiteListedSubnet() const { std::shared_lock g(mut); return _whiteListedSubnet; }

        std::atomic_int nClients{0}; ///< the number of alive clients referencing this perIPData item
        std::atomic_int64_t nShSubs{0}; ///< the number of unique scripthash subscriptions for all clients coming from this IP address.
        std::atomic_int64_t bdReqCtr{0}; ///< the number bitcoind requests active right now for all clients coming from this IP address.
        std::atomic_uint64_t bdReqCtr_cum{0}; ///< the number bitcoind requests, cumulatively, for all clients coming from this IP address.
        std::atomic_int64_t lastConnectionLimitReachedWarning{0}; ///< timstamp (in msec) of the last "connection limit exceeded" warning printed to the log for this IP address.
        /// The cumulative `batch.items.size()` for all batch requests currently active for this IP.
        /// As RPC::BatchProcessors are created this is increased, and as they are deleted this is decreased.
        std::atomic_uint64_t nExtantBatchRequests{0};
        /// The total estimated memory footprint of all extant batch requests for this IP
        std::atomic_int64_t extantBatchRequestCosts{0};
    };

    std::shared_ptr<PerIPData> perIPData;

    QMetaObject::Connection headerSubConnection; ///< if valid, this client is subscribed to headers (`Server::newHeader` signal)
    std::atomic_int nShSubs{0};  ///< the number of unique scripthash subscriptions for this client.

    //bitcoind_throttle counter, per client
    qint64 bdReqCtr = 0;

    double lastWarnedAboutSubsLimit = 0.; ///< used to throttle log messages when client hits subs limit

    static std::atomic_size_t numClients, numClientsMax, numClientsCtr; // number of connected clients: current, max lifetime, accumulated counter

    /// Returns true iff the client is token aware (protocol version >= 1.4.6). Note that this only makese sense on BCH.
    bool hasMinimumTokenAwareVersion() const;

signals:
    /// Used by ServerBase via a direct connection.  The class d'tor emits this.  This is better for us than
    /// QObject::destroyed because that runs after this type no longer is a "Client", wheras this is emitted
    /// immediately from this instance's d'tor.
    void clientDestructing(Client *self);
protected:
    void do_ping() override;
    void do_disconnect(bool graceful = false) override;

    /// This gets attached to a QTcpSocket instance in ServerBase::incomingConnection immediately to create/find
    /// Per-IP data as soon as a connection comes in (for the purposes of checking the client's IP against app-wide
    /// per-ip connection limits).  Later on after any initial handshakes on the QTcpSocket finish, this object is
    /// destroyed after the perIPData ref is transferred to the Client * instance (see this class's static take()
    /// method, which is called by ServerBase::newClient).
    class PerIPDataHolder_Temp : public QObject
    {
    public:
        std::shared_ptr<PerIPData> perIPData;
        static constexpr auto kName = "__PerIPDataHolder_Temp";
        PerIPDataHolder_Temp(std::shared_ptr<PerIPData> && ref, QTcpSocket *socket);
        ~PerIPDataHolder_Temp() override;
        /// Call this once the connection is fully accepted to "take" the PerIPData reference from the QTcpSocket's
        /// child holder object (attached in ServerBase::incomingConnection). The holder object will implicitly
        /// delete itself using deleteLater() after this is called.
        ///
        /// May return an invalid shared_ptr if no child holder object could be found.
        /// Note: In the interests of defensive programming, check the return value to make sure a valid PerIPData was
        /// found.
        static std::shared_ptr<PerIPData> take(QTcpSocket *s);
    };

    /// Does some per-IP book-keeping. If everything checks out, returns true. Otherwise returns false.
    [[nodiscard]] bool canAcceptBatch(RPC::BatchProcessor *) override;
private:
    const Options & options;
};
