//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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

#include "AbstractConnection.h"
#include "Compat.h"
#include "Json/Json.h"
#include "RPCMsgId.h"
#include "Util.h"

#include <QtGlobal> // for qsizetype (and other typedefs)
#include <QHash>
#include <QMap>
#include <QSet>
#include <QString>
#include <QVariant>
#include <QVector>

#include <memory>
#include <optional>
#include <utility> // for std::pair, std::move

namespace WebSocket { class Wrapper; } ///< fwd decl

namespace RPC {

    /// Thrown on json that is a json object but doesn't match JSON-RPC 2.0 spec.
    struct InvalidError : Json::Error {
        using Json::Error::Error;
    };

    enum ErrorCodes {
        /// "Parse error" ; Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.
        Code_ParseError = -32700,
        /// "Invalid Request" ; The JSON sent is not a valid Request object.
        Code_InvalidRequest = -32600,
        /// "Method not found" ; The method does not exist / is not available.
        Code_MethodNotFound = -32601,
        /// "Invalid params" ; Invalid method parameter(s).
        Code_InvalidParams = -32602,
        /// "Internal error" ; Internal JSON-RPC error.
        Code_InternalError = -32603,
        /// "Server error" 100 error codes that are reserved for implementation-defined server-errors.
        Code_ReservedError = -32000,
        /// Anything above this number is ok for us to use for application-specific errors.
        Code_Custom = -31999,
        /// Application-level bad request, eg request a header out of range, etc
        Code_App_BadRequest = 1,
        /// Daemon problem
        Code_App_DaemonError = 2,
        /// Excessive flood
        Code_App_ExcessiveFlood = 3,
        /// Limit exceeded
        Code_App_LimitExceeded = 4,
    };

    using KeySet = QSet<QString>;

    /// this is used to lay out the protocol methods a class supports in code
    /// Trivially constructible and copyable
    struct Method
    {
        QString method; // eg 'server.ping' or 'blockchain.headers.subscribe', etc
        /// If allowsRequests is false, requests for this method will return an error.
        /// If allowsNotifications is false, notifications for this method will be silently ignored.
        bool allowsRequests = true, allowsNotifications = false;
        using PosParamRange = std::pair<unsigned, unsigned>;
        static constexpr unsigned NO_POS_PARAM_LIMIT = UINT_MAX; ///< use this for PosParamsRange.second to specify no limit.
        /// If this optional !has_value, then positional arguments (list for "params") are rejected.
        /// Otherwise, specify an unsigned int range where .first is the minimum and .second is the maximum number
        /// of positional parameters accepted.  If .second is NO_POS_PARAM_LIMIT, then any number of parameters from
        /// .first onward is accepted.
        std::optional<PosParamRange> opt_nPosParams = PosParamRange{0, NO_POS_PARAM_LIMIT};
        /// If this optional !has_value, then named arguments (dict for "params") are rejected.
        /// If this optional has_value, we also accept kwargs (named args) appearing in the specified set
        /// (case sensitive). (Note that a method can theoretically accept both position and kwargs if so configured).
        std::optional<KeySet> opt_kwParams = {}; // '= {}' is how you specify undefined (!has_value)
        /// If true, and if opt_kwParams.has_value, then we are ok with extra 'params' coming in that are not in
        /// *opt_kwParams (but we still reject if keys in *opt_kwParams are missing from incoming 'params', thus
        /// *opt_kwParams becomes a set of minimally required params, and we ignore everything extra if this is true).
        bool allowUnknownNamedParams = false;
    };

    extern const QString jsonRpcVersion; ///< always "2.0"

    /// An RPC message.  A request, response, method call or error all use this generic struct.
    /// Note this struct is cheap to copy because it uses Qt's copy-on-write containers which are fast on copy
    /// because they update a shared data pointer and refct.  So we don't bother wrapping this
    /// in a shared_ptr or other stuff when passing it across threads, emitting it in signals, etc.
    /// TODO: see if performance benefit can be gained by wrapping in shared_ptr anyway..
    struct Message
    {
        using Id = RPCMsgId;

        // -- DATA --

        Id id; ///< guaranteed to be either string, qint64, or null
        QString method; /**< methodName extracted from data['method'] if it was present. If this is empty then no
                             'method' key was present in JSON. May also contain the "matched" method on a response
                             object where we matched the id to a method we knew about in Connection::idMethodMap. */
        QVariantMap data; ///< parsed json. 'method', 'jsonrpc', 'id', 'error', 'result', and/or 'params' get put here
        bool v1 = false; ///< iff true, we parse/validate/generate based on JSON-RPC 1.0 rules, otherwise we enforce 2.0.
        // -- METHODS --

        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromUtf8(const QByteArray &, Id *id_out = nullptr, bool v1 = false, bool strict = false);
        /// may throw Exception. This factory method should be the way one of the 6 ways one constructs this object
        static Message fromJsonData(const QVariantMap &jsonData, Id *id_parsed_even_if_failed = nullptr,
                                    bool v1 = false, bool strict = false);
        // 4 more factories below..
        /// will not throw exceptions
        static Message makeError(int code, const QString & message, const Id & id = Id(), bool v1 = false);
        /// will not throw exceptions
        static Message makeRequest(const Id & id, const QString &methodName, const QVariantList & paramsList = QVariantList(), bool v1 = false);
        static Message makeRequest(const Id & id, const QString &methodName, const QVariantMap & paramsList = QVariantMap(), bool v1 = false);
        /// similar to makeRequest. A notification is just like a request but always lacking an 'id' member. This is used for asynch notifs.
        static Message makeNotification(const QString &methodName, const QVariantList & paramsList = QVariantList(), bool v1 = false);
        static Message makeNotification(const QString &methodName, const QVariantMap & paramsList = QVariantMap(), bool v1 = false);
        /// will not throw exceptions
        static Message makeResponse(const Id & reqId, const QVariant & result, bool v1 = false);

        /// Note in pathological cases bad_alloc may be thrown here, so we just return an empty QString in that case and hope for the best.
        QByteArray toJsonUtf8() const { QByteArray ret; try {ret = Json::toUtf8(data, true);} catch (...) {} return ret; }

        // -- PERFORMANCE OPTIMIZATION --
        // It turns out QString::QString(const char *) is called a lot in typical usase of this class, so we pre-create
        // the strings we will need as static data, app-wide.
        static const QString s_code;    ///< "code"
        static const QString s_data;    ///< "data"
        static const QString s_error;   ///< "error"
        static const QString s_id;      ///< "id"
        static const QString s_jsonrpc; ///< "jsonrpc"
        static const QString s_message; ///< "message"
        static const QString s_method;  ///< "method"
        static const QString s_params;  ///< "params"
        static const QString s_result;  ///< "result"
        // ./

        bool isError() const {
            if (!v1)
                return data.contains(s_error); // v2, error= key missing unless is an actual error result.
            else
                return !data.value(s_error).isNull(); // v1, error=null may always be there. is error if it's not null
        }
        int  errorCode() const { return data.value(s_error).toMap().value(s_code).toInt(); }
        QString  errorMessage() const { return data.value(s_error).toMap().value(s_message).toString(); }
        QVariant errorData() const { return data.value(s_error).toMap().value(s_data); }

        bool isRequest() const { return !isError() && hasMethod() && (hasId() && (!v1 || !id.isNull())) && !hasResult(); }
        bool isResponse() const { return !isError() && hasResult() && hasId(); }
        bool isNotif() const {
            if (!v1)
                return !isError() && !hasId() && !hasResult() && hasMethod(); // v2 notifs -- NO ID present
            else
                return !isError() && hasId() && id.isNull() && !hasResult() && hasMethod(); // v1 notifs..  ID present, but must be null.
        }

        bool hasId() const { return data.contains(s_id); }

        bool hasParams() const { return data.contains(s_params); }
        bool isParamsList() const { return Compat::IsMetaType(data.value(s_params), QMetaType::QVariantList); }
        bool isParamsMap() const { return Compat::IsMetaType(data.value(s_params), QMetaType::QVariantMap); }
        QVariant params() const { return data.value(s_params); }
        QVariantList paramsList() const { return params().toList(); }
        QVariantMap paramsMap() const { return params().toMap(); }


        bool hasResult() const { return data.contains(s_result); }
        QVariant result() const { return data.value(s_result); }

        bool hasMethod() const { return data.contains(s_method); }

        QString jsonRpcVersion() const { return data.value(s_jsonrpc).toString(); }
    };

    using MethodMap = QHash<QString, Method>;

    // forward declarations because these are used in ConnectionBase
    class BatchProcessor;

    /// Encapsulates a BatchId, which is really the same `id` as the BatchProcessor that is handling this batch. This
    /// starts life out as "isNull()" (id == 0) until a BatchProcessor takes the Batch at which point it gets given the
    /// same `id` as the BatchProcessor instance handling it.
    ///
    /// This could very well just have been a type alias for IdMixin::Id, but adding this feature involved a big
    /// refactor and we wanted to simplify the refactor by adding extra type safety via a wrapper class.
    class BatchId
    {
        static constexpr IdMixin::Id Unassigned = 0;
        IdMixin::Id id = Unassigned;
    public:
        /// true if a BatchProcessor exists (or once existed) for this instance
        constexpr IdMixin::Id get() const noexcept { return id; }
        constexpr bool isNull() const noexcept { return id == Unassigned; }

        constexpr bool operator<(const BatchId & o) const noexcept { return id < o.id; }
        constexpr bool operator<=(const BatchId & o) const noexcept { return id <= o.id; }
        constexpr bool operator>(const BatchId & o) const noexcept { return id > o.id; }
        constexpr bool operator>=(const BatchId & o) const noexcept { return id >= o.id; }
        constexpr bool operator==(const BatchId & o) const noexcept { return id == o.id; }
        constexpr bool operator!=(const BatchId & o) const noexcept { return id != o.id; }
    protected:
        friend class BatchProcessor;
        constexpr void set(IdMixin::Id newId) noexcept { id = newId; } ///< only BatchProcessor calls this
    };

    /// For QHash/QSet etc support
    inline Compat::qhuint qHash(const BatchId b, Compat::qhuint seed = 0) { return ::qHash(quint64(b.get()), seed); }

    /// A semi-concrete derived class of AbstractConnection implementing a
    /// JSON-RPC based method<->result protocol.  This class is client/server
    /// agnostic and it just operates in terms of JSON RPC methods and results.
    /// It can be used for either a client or a server.
    ///
    /// Note that this class is somewhat transport agnostic and is intended to
    /// be re-used for either HTTP or line-based (as in Electrum) JSON-RPC via
    /// subclassing.
    ///
    /// Concrete subclasses should implement on_readyRead() and wrapForSend().
    ///
    /// This class just processes JSON. Subclasses implementing on_readyRead()
    /// should call processJson() in this base to process the potential JSON
    /// further. processJson() does validation and may implicitly close the
    /// connection, etc if it doesn't like the data it received.  processJson()
    /// is intended to be called when the subclass thinks the client has sent it a
    /// full "packet" of a JSON RPC message.
    ///
    /// Note we implement a subset of JSON-RPC 2.0 which requires 'id' to
    /// always be ints, strings, or null.  We do not accept floats for id (the
    /// JSON-RPC 2.0 spec strongly recommends against floats anyway, we are just
    /// slighlty more strict than the spec).
    ///
    /// Methods invoked on the peer need an id, and this id is used to track
    /// the reply back and associate it with the method that was invoked on
    /// the peer (see idMethodMap instance var).
    ///
    /// See class Server for an example class that constructs a MethodMap and
    /// passes it down.
    ///
    /// Classes that manage rpc methods should register for the gotMessage()
    /// signal and process incoming messages further.  All incoming messages
    /// are either requests or notifications.
    ///
    /// gotErrorMessage can be used to receive error messages.
    ///
    /// Note that gotMessage() won't always be emitted if the message was
    /// filtered out (eg, a notification received but no "method" defined for
    /// it, or a result received without a known id in idMethodMap, etc).
    ///
    /// Server's 'Client' class derives from this.
    ///
    class ConnectionBase : public AbstractConnection
    {
        Q_OBJECT

        Q_PROPERTY(bool v1 READ isV1 WRITE setV1)
        Q_PROPERTY(bool strict READ isStrict WRITE setStrict)

        friend class BatchProcessor;

    protected:
        /// Subclasses should call processJson to process what they think may be a complete JSON-RPC message.
        ///
        /// Note the move semantics here. We take ownership of the passed-in QByteArray and clear it immediately
        /// once JSON processing is done, but before callbacks are dispatched -- this is to reduce peak memory usage
        /// if processing a huge JSON payload containing a big block (for networks like ScaleNet).
        void processJson(QByteArray &&);

        struct ProcessObjectResult {
            struct Error {
                int code{};
                QString message;
                Error(int c, const QString & m) : code(c), message(m) {}
            };
            // only 0 or 1 of the below 2 optionals will ever be valid at a time.
            std::optional<Error> error;
            std::optional<Message> message;
            Message::Id parsedMsgId;

            ProcessObjectResult(Error && e, const Message::Id &mid) : error{std::move(e)}, parsedMsgId{mid} {}
            ProcessObjectResult(Message && m, const Message::Id &mid) : message{std::move(m)}, parsedMsgId{mid} {}
            ProcessObjectResult(const Message::Id &mid) : parsedMsgId{mid} {}
        };

        /// Process an individual JSON object.
        /// May be called in either batch context or immediate context.
        [[nodiscard]] ProcessObjectResult processObject(QVariantMap &&);

        /* --
         * -- Stuff subclasses must implement to make use of this class as base:
         * --
         */

        /// subclasses must implement this to wrap outgoing data for sending.
        virtual QByteArray wrapForSend(QByteArray &&) = 0;

        /* subclasses must also implement this pure virtual inherited from base:
             void on_readyRead() override; */

        /*
         * /end
         */

    public:
        ConnectionBase(const MethodMap * methods /* null ok */, IdMixin::Id id,
                       QObject *parent = nullptr, qint64 maxBuffer = DEFAULT_MAX_BUFFER);
        ~ConnectionBase() override;

        /// Points to either the passed-in methods pointer (if not-null), or if it was nullptr, to a static empty
        /// map. Note: this map needs to remain alive for the lifetime of this connection (and all connections)
        /// .. so it should point to static or long-lived data!
        const MethodMap & methods;

        struct BadPeer : public Exception {
            using Exception::Exception;  // bring in c'tor
        };

        /// if peer asked for an unknown method
        struct UnknownMethod : public Exception { using Exception::Exception; };

        /// If peer request object was not JSON-RPC 2.0
        struct InvalidRequest : public BadPeer { using BadPeer::BadPeer; };
        /// If peer request object has invalid number of params
        struct InvalidParameters : public BadPeer { using BadPeer::BadPeer; };
        /// If the batch limit has been exceeded
        struct BatchLimitExceeded : public BadPeer { using BadPeer::BadPeer; };

        static constexpr int MAX_UNANSWERED_REQUESTS = 20000; ///< TODO: tune this down?

        /// Subclasses, such as ElectrumConnection, reimplement this
        virtual bool isReadPaused() const { return false; }

        bool isV1() const { return v1; }
        void setV1(bool b) { v1 = b; }

        bool isStrict() const { return strict; }
        void setStrict(bool b) { strict = b; }

        bool isBatchPermitted() const { return batchPermitted; }
        void setBatchPermitted(bool b) { batchPermitted = b; }

    signals:
        /// Call (emit) this to send a request to the peer. Note sending doesn't support batching.
        void sendRequest(const RPC::Message::Id & reqid, const QString &method, const QVariantList & params = {});
        /// Call (emit) this to send a notification to the peer
        void sendNotification(const QString &method, const QVariant & params);
        /// Call (emit) this to send an error message to the peer.
        /// @param `batchId` is the batch this error pertains to, if it is in response to a request from a batch,
        /// otherwise may be .isNull() (response will be sent immediately, and not collated to any batch in that case)
        void sendError(bool disconnectAfterSend, int errorCode, const QString &message, RPC::BatchId batchId,
                       const RPC::Message::Id & reqid = {});
        /// Call (emit) this to send a result reply to the peer (`"result" : result` JSON RPC message).
        /// @param `batchId` is the batch this result pertains to, if it is in response to a request from a batch,
        /// otherwise may be .isNull() (response will be sent immediately, and not collated to any batch in that case)
        void sendResult(RPC::BatchId batchId, const RPC::Message::Id & reqid, const QVariant & result = {});

        /// this is emitted when a new message arrives that was successfully parsed and matches
        /// a known method described in the 'methods' MethodMap. Unknown messages will eventually result
        /// in auto-disconnect.
        void gotMessage(IdMixin::Id thisId, RPC::BatchId batchId, const RPC::Message & m);
        /// Same as a above, but for 'error' replies
        void gotErrorMessage(IdMixin::Id thisId, const RPC::Message &em);
        /// This is emitted when the peer sent malformed data to us and we didn't disconnect
        /// because errorPolicy is not ErrorPolicyDisconnect
        void peerError(IdMixin::Id thisId, const QString &what);

        /// This is only ever really emitted by ElectrumConnection and subclasses. `newState` indicates the new
        /// paused state which has already been put into effect before this signal is emitted. This is only emitted on
        /// state changes so the old state was always !newState.
        void readPausedStateChanged(bool newState);

    protected slots:
        /// Actual implentation that prepares the request. Is connected to sendRequest() above. Runs in this object's
        /// thread context. Eventually calls send() -> do_write() (from superclass).
        void _sendRequest(const RPC::Message::Id & reqid, const QString &method, const QVariantList & params = {});
        // ditto for notifications
        void _sendNotification(const QString &method, const QVariant & params);
        /// Actual implementation of sendError, runs in our thread context.
        void _sendError(bool disconnect, int errorCode, const QString &message, RPC::BatchId batchId, const RPC::Message::Id &reqid = {});
        /// Actual implementation of sendResult, runs in our thread context.
        void _sendResult(RPC::BatchId batchId, const RPC::Message::Id & reqid, const QVariant & result = {});

    protected:
        /// chains to base, connects sendRequest signal to _sendRequest slot
        void on_connected() override;
        /// Chains to base, clears idMethodMap
        void on_disconnected() override;

        /// adds the nRequestsSent, etc stats
        Stats stats() const override;

        /// map of requests that were generated via _sendRequest to method names to build a more meaningful Message
        /// object (which has a .method defined even on 'result=' messages).  It is an error to receive a result=
        /// message from the peer with its id= parameter not having an entry in this map.
        QHash<Message::Id, QString> idMethodMap;

        enum ErrorPolicy {
            /// Send an error RPC message on protocol errors.
            /// If this is set and ErrorPolicyDisconnect is set, the disconnect will be graceful.
            /// Note that within a batch request this flag is ignored and errors are always sent
            /// inside the batch response array (as per JSON-RPC spec).
            ErrorPolicySendErrorMessage = 1,
            /// Disconnect on RPC protocol errors. If this is set along with ErrorPolicySendErrorMessage,
            /// the disconnect will be graceful.
            /// Note that within a batch request this flag will lead to a disconnect only after the batch completes
            /// and returns results to the client.
            ErrorPolicyDisconnect = 2,
        };
        /// derived classes can set this internally (bitwise or of ErrorPolicy*)
        /// to affect on_readyRead()'s behavior on peer protocol error.
        int errorPolicy = ErrorPolicyDisconnect;

        bool v1 = false; // if true, will generate v1 style messages and respond to v1 only
        bool strict = false; // if true, we will be more strict and reject some malformed JSON-RPC messages
        bool batchPermitted = false; // if true, we will accept JSON-RPC Batches

        /// New in 1.0.1: This is latched to true in Client::on_disconnect to signal that the client is being
        /// disconnected and to just throw away any future messages from this client.
        bool ignoreNewIncomingMessages = false;

        QString lastPeerError;
        quint64 nRequestsSent = 0, nNotificationsSent = 0, nResultsSent = 0, nErrorsSent = 0;
        quint64 nErrorReplies = 0, nUnansweredLifetime = 0;

        /// Subclasses may reimplement this to reject or accept a new JSON-RPC batch.
        /// - If this method returns false, the passed-in batch will be immediately deleted, and a JSON-RPC message will
        ///   be sent to the client, indicating that limits have been exceeded.
        /// - If it returns true, then the batch will be added to the extantBatchProcessors table immediately and it
        ///   will begin processing when the current event loop becomes free.  Reimplemented in the `Client` subclass.
        [[nodiscard]] virtual bool canAcceptBatch(BatchProcessor *) { return true; }

        /// This is called internally by either processJson() or by the BatchProcessor when it is killed.
        void on_processJsonFailure(int code, const QString & message, const Message::Id &msgId = {});

    private:
        /// Table used to store the extant batch processors running.
        /// Keyed off of the BatchId (which has same id as the BackProcessor->id())
        QHash<BatchId, BatchProcessor *> extantBatchProcessors;

        // Internally called by processObject()
        [[nodiscard]] ProcessObjectResult processObject_internal(QVariantMap &&);
        // Internally called by _sendResult and _sendError
        // Precondition: Message must be either: isError() or isResponse() (this is not checked here for performance)
        [[nodiscard]] bool batchResponseFilter(RPC::BatchId batchId, const Message & msg);
        // Internally called to enqueue a new batch -- this may throw InvalidRequest if the QVariantList is empty
        void enqueueNewBatch(QVariantList &&);
    };

    inline constexpr bool debugBatchExtra = false; ///< if true, Debug() log will print extra info for the batch processing feature

    /// Structure to hold a "batch request" context
    struct Batch
    {
        BatchId batchId; ///< the object id of the BatchProcessor instance that is handling this batch request.
        QVariantList items; ///< the contents of the original batch request list. Data items may be any JSON type.
        QVariantList::size_type nextItem = 0; ///< index into above array
        /// The number of `items` that we have processed thus far that are notifications or that don't warrant a
        /// response in the batch response.
        QVariantList::size_type skippedCt = 0;
        /// The number of responses in the batch response that were error responses.
        QVariantList::size_type errCt = 0;
        /// The number of messages we sent asynch to observers but for which we have yet to receive a reply
        QVariantList::size_type unansweredRequests{};

        /// Responses enqueued for sending back to the client, may also include error responses aside from results
        QVector<Message> responses;

        bool hasNext() const { return nextItem < items.size(); }
        QVariant getNextAndIncrement();
        bool isComplete() const { return !hasNext() && skippedCt + responses.size() >= items.size(); }

        Batch() = default;
        Batch(QVariantList && items_) : items{std::move(items_)} {}
    };

    /// An individual batch request is managed by this object. Instances of this class are always children of
    /// `ConnectionBase`. They appear in the ConnectionBase parent's `extantBatchProcessors` table.
    ///
    /// Limitation: For now, the BatchProcessor only knows how to handle batch requests coming from the other side,
    /// and cannot (yet) process batch replies.  As such, it will reject batches containing 'error' and 'result'
    /// messages.
    class BatchProcessor : public QObject, public IdMixin, public ProcessAgainMixin, public TimersByNameMixin,
                           public StatsMixin
    {
        Q_OBJECT

        ConnectionBase & conn;
        Batch batch;
        const Tic t0;
        bool done = false;
        bool isProcessingPaused = false;
        bool killed = false;
        qsizetype cumCost = 0; ///< The cost of the JSON batch array itself initially, but it accumulates response costs too.

    public:
        explicit BatchProcessor(ConnectionBase & parent, Batch && batch);
        ~BatchProcessor() override;

        /// Precondition: Message must be either: isError() or isResponse() (this is not checked here for performance)
        void gotResponse(const Message &);
        void process() override;

        const Batch & getBatch() const { return batch; }
        BatchId batchId() const { return batch.batchId; } // NB: the actual batchId.get() value should be always same as this->id!
        bool isFinished() const { return done; }

        qsizetype cost() const { return cumCost; }

        void killForExceedngLimit();

    protected:
        Stats stats() const override;

    signals:
        /// Tells observers that this object's lifecycle has ended. Will always eventually be emitted regardless of
        /// reason for lifecycle termination.
        void finished();
        /// Update observers on this instance's on-going cost. `delta` may be positive or negative. A negative delta
        /// is always emitted from this class's d'tor, to tell observers to deduct all the previously-seen cumulative
        /// costs.  To use this properly to track cumulative costs:
        /// (1) First take the current `cost()` and save it.
        /// (2) Connect to this signal and each time the signal is delivered, add `delta` to your tracked cost.
        /// (3) The final time this signal fires, `delta` will always be negative, e.g.: `-cost()`.
        /// Note: Ensure the connection in (2) above is via a direct connection to be guaranteed delivery on destruction
        /// of this instance.
        void costDelta(qsizetype delta);

    private:
        void addCost(qsizetype cost);
        void pushResponse(Message && m);
        void pushResponse(const Message & m) { pushResponse(Message{m}); }
    };


    /// Concrete class. For Electrum Cash style JSON RPC.
    /// This class can be used either with a bare QTcpSocket/QSslSocket in which case newlines delimit RPC messages.
    /// If used with a WebSocket::Wrapper instance, messages are already framed and newlines are not required.
    class ElectrumConnection : public ConnectionBase {
    public:
        using ConnectionBase::ConnectionBase;
        ~ElectrumConnection() override; ///< for vtable

        // the below two can/should only be called from the same thread as this object's thread
        void setReadPaused(bool);
        bool isReadPaused() const override { return readPaused; }

        /// Reimplemented from AbstractConnection.
        /// Returns true if the socket is wrapped by a WebSocket::Wrapper, false otherwise.
        bool isWebSocket() const override;
        /// Reimplemnted from AbstractConnection.
        /// Returns true if the underlying socket is a QSslSocket (either the socket itself or the nested one wrapped by
        /// a WebSocket::Wrapper), false otherwise.
        bool isSsl() const override;

    protected:
        /// implements pure virtual from super to handle linefeed-based JSON. When a full line arrives, calls ConnectionBase::processJson
        void on_readyRead() override;
        QByteArray wrapForSend(QByteArray &&) override;

    private:
        qint64 memoryWasteThreshold = -1; ///< gets lazy-initialized in memoryWasteDoSProtection below
        bool memoryWasteTimerActive = false;  ///< inticates the DoS protection timer is active, used by memoryWasteDoSProtection
        void memoryWasteDoSProtection(); ///< must be called from on_readyRead only.

        bool readPaused = false;
        bool skippedOnReadyRead = false;
        std::optional<WebSocket::Wrapper *> webSocket; ///< set once the first time on_readyRead() or wrapForSend() is called. If set and valid, affects the framing behavior of this class.
        WebSocket::Wrapper *checkSetGetWebSocket();
    };

    /// JSON RPC over HTTP.  Wraps the outgoing data in headers and can also parse incoming headers.
    /// For use by the bitcoind rpc mechanism.
    class HttpConnection : public ConnectionBase {
        Q_OBJECT
    public:
        using ConnectionBase::ConnectionBase;
        ~HttpConnection() override; ///< for vtable

        /// For: "Authorization: Basic <cookie>"; used to calculate the <cookie>
        void setAuth(const QString & username, const QString & password);
        void clearAuth() { header.authCookie.clear(); }

        /// Sets the HTTP header "Host:" field.  This string will be sent verbatim to the other end when
        /// doing an HTTP/1.1 POST.  This must be set if acting as a client, otherwise no "Host:" header
        /// field will be sent, which some endpoints don't like (namely bchd) since it violates RFC 2616.
        void setHeaderHost(const QString &);
        QString headerHost() const { return header.host; }
        void clearHeaderHost() { header.host.clear(); }

    signals:
        /// emitted when the other side (usually bitcoind) didn't accept our auth cookie.
        void authFailure(RPC::HttpConnection *me);

    protected:
        void on_readyRead() override;
        QByteArray wrapForSend(QByteArray &&) override;

    private:
        /// These end up verbatim in the HTTP/1.1 POST header.
        struct {
            QByteArray authCookie; ///< "Authorization: Basic <cookie>"
            QByteArray host; ///< "Host: <host>"; caller should set this if acting as a client
        } header;
        struct StateMachine;
        using SMDel = std::function<void(StateMachine *)>;
        std::unique_ptr<StateMachine, SMDel> sm; ///< we need to declare this with a deleter otherwise subclasses won't be able to inherit from us because StateMachine is a private, opaque struct; the need for a deleter is due to implementation details of how unique_ptr works with opaque types.
    };

    /// Query whether using the simdjson backend or using default for JSON parsing.
    bool isFastJson();
    /// Set fast Json parsing to on or off. Note that the requested setting may not take effect if we are missing
    /// the underlying libs or are on an unsupported platform.  As such, this returns true on success, false on failure.
    bool setFastJson(bool);

} // end namespace RPC

/// So that Qt signal/slots work with this type.  Metatypes are also registered at startup via qRegisterMetatype
Q_DECLARE_METATYPE(RPC::Message);
Q_DECLARE_METATYPE(RPC::Message::Id);
Q_DECLARE_METATYPE(RPC::BatchId);
