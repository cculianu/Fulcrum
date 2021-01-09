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

#include "Common.h"

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMetaObject>
#include <QObject>
#include <QPointer>
#include <QTcpSocket>

#include <cstddef>
#include <list>
#include <optional>

class QTcpSocket;
class QTimer;

namespace WebSocket
{
    /// All functions throw a type of this exception (but some may throw ::BadArgs or ::InternalError as well)
    struct Error : public Exception { using Exception::Exception; ~Error() override; };
    /// Thrown if the parsed or generated data exceeds INT_MAX
    struct MessageTooBigError : public Error { using Error::Error; ~MessageTooBigError() override; };

    /// Default to 4096-byte fragments.
    inline constexpr std::size_t DefaultFragmentSize = 4096;

    enum FrameType : std::uint8_t {
        // Payload (application data) frame types
        Text = 0x1, // supports fragmentation
        Binary = 0x2, // supports fragmentation

        // Control frame types
        Ctl_Close = 0x8, // may contain up to 125 bytes of optional payload data for the reasonCode (2 bytes) + message
        Ctl_Ping = 0x9,  // may contain up to 125 bytes of optional payload data
        Ctl_Pong = 0xA,   // may contain up to 125 bytes of payload data (must be same data echoed back from the Ping data, if any)

        // Internal use only
        _Continuation = 0x0,  // "continuation" of Text/Binary (all fragments after the first use this opcode)
    };

    QString frameTypeName(FrameType);

    /// The below codes are all from RFC 6455
    enum CloseCode : std::uint16_t {
        /// 1000 indicates a normal closure, meaning that the purpose for which the connection was established has been fulfilled.
        Normal = 1000,
        /// 1001 indicates that an endpoint is "going away", such as a server going down or a browser having navigated away from a page.
        GoingAway = 1001,
        /// 1002 indicates that an endpoint is terminating the connection due to a protocol error.
        ProtocolError = 1002,
        /// 1003 indicates that an endpoint is terminating the connection because it has received a type of data it
        /// cannot accept (e.g., an endpoint that understands only text data MAY send this if it receives a binary
        /// message).
        CannotAcceptDataType = 1003,

        Reserved1 = 1004,
        Reserved2 = 1005,
        Reserved3 = 1006,

        /// 1007 indicates that an endpoint is terminating the connection because it has received data within a message
        /// that was not consistent with the type of the message (e.g., non-UTF-8 [RFC3629] data within a text message).
        BadData = 1007,
        /// 1008 indicates that an endpoint is terminating the connection because it has received a message that violates
        /// its policy.  This is a generic status code that can be returned when there is no other more suitable status
        /// code (e.g., 1003 or 1009) or if there is a need to hide specific details about the policy.
        PolicyViolated = 1008,
        /// 1009 indicates that an endpoint is terminating the connection because it has received a message that is too
        /// big for it to process.
        MessageTooBig = 1009,
        /// 1010 indicates that an endpoint (client) is terminating the connection because it has expected the server
        /// to negotiate one or more extension, but the server didn't return them in the response message of the
        /// WebSocket handshake.  The list of extensions that are needed SHOULD appear in the /reason/ part of the
        /// Close frame.  Note that this status code is not used by the server, because it can fail the WebSocket
        /// handshake instead.
        ExtensionMissing = 1010,
        /// 1011 indicates that a server is terminating the connection because it encountered an unexpected condition
        /// that prevented it from fulfilling the request.
        ServerCannotFulfillRequest = 1011,

        Reserved4 = 1015,
        /* From the RFC:
            7.4.2.  Reserved Status Code Ranges

               0-999

                  Status codes in the range 0-999 are not used.

               1000-2999

                  Status codes in the range 1000-2999 are reserved for definition by
                  this protocol, its future revisions, and extensions specified in a
                  permanent and readily available public specification.

               3000-3999

                  Status codes in the range 3000-3999 are reserved for use by
                  libraries, frameworks, and applications.  These status codes are
                  registered directly with IANA.  The interpretation of these codes
                  is undefined by this protocol.

               4000-4999

                  Status codes in the range 4000-4999 are reserved for private use
                  and thus can't be registered.  Such codes can be used by prior
                  agreements between WebSocket applications.  The interpretation of
                  these codes is undefined by this protocol.
        */
    };

    /// Functions for generating wire protocol data frames
    namespace Ser {
        /// Given a complete payload of data, inserts the proper framing into the data stream, and returns the same data
        /// with the framing inserted (and properly fragmented). fragmentSize controls the size of fragments.
        ///
        /// Note that only FrameType::Text and FrameType::Binary frames may be fragmented.  The Ctl_* frames may not (their
        /// payload may only consist of a single fragment of up to 125 bytes in length).
        ///
        /// If isMasked == true, then the masking key is selected by calling QRandomGenerator::global()->generate(). The
        /// masking key is XOR'd with the data payload and is also embedded into the frame header.  The WebSockets RFC says
        /// that all client-originating messages must be masked, including control frames.
        ///
        /// The fragmentSize argument is ignored for Ctl_* frame types.
        ///
        /// May throw BadArgs if:
        /// - fragmentSize is 0 and `type` is Text or Binary
        /// - fragmentSize is > a 63-bit integer and `type` is Text or Binary
        /// - data.size() > 125 and `type` is one of the Ctl_* types.
        ///
        /// May also throw MessageTooBigError if:
        /// - the resuling data would exceed the maximum size of a QByteArray (currently INT_MAX)
        QByteArray wrapPayload(const QByteArray &data, FrameType type, bool isMasked, std::size_t fragmentSize = DefaultFragmentSize);

        /// Convenience function that wraps 'data' using the 'Text' data frame opcode. Note that 'data' must be Utf8 encoded
        /// text or else the other side may terminate the connection.
        inline QByteArray wrapText(const QByteArray &data, bool isMasked, std::size_t fragmentSize = DefaultFragmentSize) {
            return wrapPayload(data, FrameType::Text, isMasked, fragmentSize);
        }
        /// Convenience function that wraps 'data' using the 'Data' data frame opcode.
        inline QByteArray wrapBinary(const QByteArray &data, bool isMasked, std::size_t fragmentSize = DefaultFragmentSize) {
            return wrapPayload(data, FrameType::Binary, isMasked, fragmentSize);
        }

        /// Convenience function that creates a PING control frame. Optionally up to 125 bytes worth of data may be
        /// sent to the other end, which will be echoed back in its PONG reply.
        inline QByteArray makePingFrame(bool isMasked, const QByteArray & data = {}) {
            return wrapPayload(data.size() > 125 ? data.left(125) : data, FrameType::Ctl_Ping, isMasked);
        }

        /// Convenience function that creates a PONG reply control frame. Note that the reply must contain the same data
        /// received from the corresponding PING that this frame is in reply to.
        inline QByteArray makePongFrame(const QByteArray & data, bool isMasked) {
            return wrapPayload(data.size() > 125 ? data.left(125) : data, FrameType::Ctl_Pong, isMasked);
        }

        /// Returns a "Close" control frame with empty data payload (which is prefectly ok to send as per the RFC)
        inline QByteArray makeCloseFrame(bool isMasked) {
            return wrapPayload({}, FrameType::Ctl_Close, isMasked);
        }

        /// Returns a "Close" control frame with non-empty data payload.  The payload will consist of 2-byte code + reason (reason may be empty)
        QByteArray makeCloseFrame(bool isMasked, CloseCode code, const QByteArray &reason = {});
    } // end namespace Ser

    namespace Deser {
        struct Frame {
            FrameType type = FrameType::Text;
            bool masked{}; ///< true iff the data was masked as it came in from the wire. Servers must enforce that clients send masked data.
            QByteArray payload{}; ///< the actual "payload data" from the payload.  Note in the case of Text/Binary this is always fully assembled from all fragments.

            /* control frames always have high bit in low order nibble set. */
            inline constexpr bool isControl() const noexcept { return type & 0x08; }
        };

        /// Thrown if the incoming wire data is out-of-spec and/or invalid.
        struct ProtocolError : public Error { using Error::Error; ~ProtocolError() override; };

        enum MaskEnforcement {
            DontCare = 0,
            RequireMasked = 1,
            RequireUnmasked = 2,
        };

        /// Modifies `buf` in-place, extracting out the control frames it encounters as well as fully assembled Text/Binary
        /// messages (after all fragments have been found).  Leaves any data in `buf` that it could not process untouched (e.g.
        /// incomplete data due to missing ending FIN frames).  This function is designed to work with asynch TCP socket
        /// code as a parsing/deserialization function of an ongoing read buffer.
        ///
        /// Does full validation of input and throws on validation error.  May throw ProtocolError or MessageTooBigError.
        /// If MaskEnforcement is enabled, then it will also throw ProtocolError if the mask predicate is violated for
        /// any frames encountered.
        ///
        /// Note: Potentially ::InternalError can be thrown if there are bugs in this code -- calling code may wish
        /// to catch that exception as well and abort the app in that case.
        std::list<Frame> parseBuffer(QByteArray &buf, MaskEnforcement maskEnforcement = DontCare);

        /// Convenience helper for parsing out the CloseCode and the reason from a Close frame.
        struct CloseFrameInfo {
            std::optional<quint16> code; // see enum CloseCode for possible codes specified in RFC. This may !has_value() if no code was specified.
            QByteArray reason; // remaining bytes after parsing out code from paylaod, if any

            CloseFrameInfo() = default;
            /// Construct this from a Frame, parsing out the code (if any) and the remaining bytes put into 'reason'
            inline CloseFrameInfo(const Frame &f) { *this = f; }
            CloseFrameInfo &operator=(const Frame &);
        };
    }

    /// Handshake manager objects for automatically performing a websocket handshake and transitioning the other endpoint
    /// into WebSocket mode.
    namespace Handshake {

        /// Asynchronous managers
        namespace Async {

            /// Base class -- common code used by both ClientSide and ServerSide below.
            class ClientServerBase : public QObject {
                Q_OBJECT
            public:
                explicit ClientServerBase(QTcpSocket * /* may not be nullptr */);
                ~ClientServerBase() override;

                static constexpr int kDefaultTimeout = 10000, ///< 10s handshake timeout default
                                     kDefaultMaxHeaders = 8192;

                /// Get the underlying socket.
                inline QTcpSocket *socket() const { return const_cast<QTcpSocket *>(sock); }
                /// We will fail if the incoming headers exceed this size
                inline int maxHeaderBytes() const { return maxHeaders; }
                /// Set failure threshold.  Set to <= 0 to allow unlimited headers.
                inline void setMaxHeaderBytes(int max) { maxHeaders = max; }
                /// If true, we will call this->deleteLater() on ourselves after finished() is emitted. Default true.
                inline bool autoDelete() const { return autodelete; }
                inline void setAutoDelete(bool b) { autodelete = b; }
                /// If true, we will call socket->disconnectFromHost() after failure() is emitted.
                inline bool audoDisconnect() const { return autodisconnect; }
                inline void setAutoDisconnect(bool b) { autodisconnect = b; }
            signals:
                // One of the below will be emitted if the socket isn't deleted before completion.
                /// Emitted when the handshake has completed successfully. After this is emitted the other endpoint
                /// is expecting the WebSocket protocol.
                void success();
                /// Emitted if the handshake timed out or some other error occurred.
                /// Note that if this is emitted, and autoDisconnect() is true, the socket will also be disconnected
                /// using disconnectFromHost().
                void failure(const QString &reason);
                /// Emitted immediately after success() or failure()
                void finished();
            protected:
                using ConnList = QList<QMetaObject::Connection>;
                ConnList conns;
                QTcpSocket *sock;
                QTimer *timer = nullptr;
                int maxHeaders = kDefaultMaxHeaders;
                bool autodelete = true, autodisconnect = true;

                int nread = 0;
                QHash<QString, QString> headers;
                bool checkHeaders(QString *what = nullptr) const;

                /// called from derived classes' start(), returns false if should abort start(), emits failure(reason)
                /// on false return.  On true return, sets up some private signal/slot connections for emitting failure
                /// on various socket errors and timeout.
                bool startCommon(int timeout);

                virtual void on_ReadyRead() = 0;
            };

            /// Negotiates a handshake for a given QTcpSocket, from the client side.
            ///
            /// Use this with a freshly connected socket before transmitting any data to get the other end to speak
            /// the WebSocket protocol.  WSS is supported: the socket may be a QSslSocket in which case it should be
            /// used with this class after the QSslSocket has emitted the `encrypted()` signal (that is, right after the
            /// TLS handshake has completed).
            class ClientSide : public ClientServerBase {
            public:
                using ClientServerBase::ClientServerBase; /// re-use c'tor
                ~ClientSide() override;

                /// This begins the asynchronous handshake process. Either success() or failure() will be emitted, with
                /// finished() emitted right after in either case.
                ///
                /// This function may be used with either a QTcpSocket or a QSslSocket. For QSslSockets, call it right
                /// after the 'encrypted()' signal is emitted and for regular sockets, call this after the 'connected()'
                /// signal is emitted. In other words, this should be called precisely once right after the connection
                /// is made and before any data is sent to the socket.
                ///
                /// If the handshake is successful the following properties will be written to the QTcpSocket QObject:
                ///
                /// - "websocket-protocol" -> bool, true
                /// - "websocket-headers"  -> The headers received from the server during the handshake. This is a
                ///                           QVariantMap of header/value pairs, as QStrings without the ':' separator.
                ///                           All keys are lowercased, and values are copied verbatim (after Utf8
                ///                           decode).
                ///
                void start(const QString & resourceName /* e.g. "/" */,
                           const QString &host /* e.g. "remoteserver.com" */,
                           const QString &origin = {} /* Akin to http referer. This is optional, Typically omitted for non-browser clients */,
                           int timeout = kDefaultTimeout /* milliseconds */);

            protected:
                void on_ReadyRead() override;
            private:
                QString expectedDigest;
            };

            /// Negotiates a handshake for a given QTcpSocket, from the server side.
            ///
            /// Use this with a freshly connected socket before transmitting any data to negotiate with the other end
            /// to speak the WebSocket protocol.  WSS is supported: the socket may be a QSslSocket in which case it
            /// should be used with this class after the QSslSocket has emitted the `encrypted()` signal (that is, right
            /// after the TLS handshake has completed).
            class ServerSide : public ClientServerBase {
            public:
                using ClientServerBase::ClientServerBase; /// re-use c'tor
                ~ServerSide() override;

                static constexpr auto kDefaultServerAgent = (APPNAME "/" VERSION);

                /// This begins the asynchronous handshake process. Either success() or failure() will be emitted, with
                /// finished() emitted right after in either case.
                ///
                /// This function may be used with either a QTcpSocket or a QSslSocket. For QSslSockets, call it right
                /// after the 'encrypted()' signal is emitted (after you call startServerEncryption()), and for regular
                /// sockets call this after the new socket is returned from `QTcpServer::nextPendingConnection()`.
                ///
                /// In other words, this should be called precisely once right after the connection is established fully
                /// and before any data is sent to the socket.
                ///
                /// If the handshake is successful the following properties will be written to the QTcpSocket QObject:
                ///
                /// - "websocket-protocol" -> bool, true
                /// - "websocket-request-resource" -> QString. The thing they sent us after the HTTP GET, e.g. "/" or "/chat", etc
                /// - "websocket-headers"  -> The headers received from the client during the handshake. This is a
                ///                           QVariantMap of header/value pairs, as QStrings without the ':' separator.
                ///                           All keys are lowercased, and values are copied verbatim (after Utf8
                ///                           decode).
                ///
                void start(const QString & serverAgent = kDefaultServerAgent /* If emtpy, the Server: of the response header will be omitted. */,
                           int timeout = kDefaultTimeout /* milliseconds */);

            protected:
                void on_ReadyRead() override;
            private:
                QString serverAgent, reqResource;
            };

        } // end namespace Async
    } // end namespace Handshake

    /// QTcpSocket work-alike.  Wraps a real underying socket (which it becomes the parent of). Requires an event
    /// loop for correct operation (since it uses some asynchronous magic behind the scenes).
    ///
    /// This class is intented to be used asynchronously. The readyRead() or messagesReady() signal can be used for
    /// notification when data messages become available.  Use readNextMessage() or readAllMessages() to retrieve the
    /// buffered messages.  Use setReadBufferSize() to limit the amount of buffering done for these messages.
    ///
    /// Writing to the WebSocket can be accomplished via the write() method (as with a regular QTcpSocket), in which
    /// case the entire QByteArray buffer is sent down the wire as a single message (possibly fragmented) of
    /// either Text or Binary type (default Text).  Use setMessageMode() to set the default mode for write(), or
    /// use the custom methods sendText() and sendBinary() to explicitly send specific message types on a case-by-case
    /// basis.
    ///
    /// PING/PONG support is provided via an optional automatic mechanism (on by default).  There is also an automatic
    /// PING keepalive sent to the other endpoint (20 second interval, ~60 second timeout by default, configurable).
    ///
    /// CLOSE is handled automatically as well.  disconnectFromHost() will use the WebSocket close handshake mechanism
    /// with a 3 second timeout (before force-closing the socket).  If the other endpoint sends us a CLOSE frame, the
    /// handshake is handled asynchronously by this class and eventually disconnected() will be emitted, with the
    /// underlying connection being closed.
    ///
    /// This class must be used with a freshly-connected QTcpSocket or QSslSocket (in the QSslSocket case, use this
    /// class after the socket has entered encrypted() mode).  In both cases no application data should be sent down
    /// the underlying socket before the websocket connection handshake is done.
    ///
    /// To start the handshake, use startClientHandshake() or startServerHandshake() (depending on whether you are the
    /// client or server endpoint).
    class Wrapper : public QTcpSocket
    {
        Q_OBJECT
    public:
        enum Mode : std::uint8_t {
            Unknown = 0,
            ClientMode,
            ServerMode,
        };

        enum MessageMode : std::uint8_t {
            Text = FrameType::Text,
            Binary = FrameType::Binary
        };

        using Message = Deser::Frame;
        using MessageList = std::list<Message>;

        /// This instance will become the parent of socket.  The socket should already be in the Connected state.
        /// Socket may not be nullptr.  If socket is a QSslSocket, it should already be in the 'encrypted' state.
        /// Note: Passing a Wrapper * instance as the first argument to this constructor is not supported and the
        /// WebSocket handshake will fail.
        explicit Wrapper(QTcpSocket *socket, QObject *parent = nullptr);
        ~Wrapper() override;

        inline QTcpSocket *wrappedSocket() const { return socket; }

        /// Use this after construction to start the WebSocket handshake as a client. `handshakeSuccess` or
        /// `handshakeFailed` will be emitted when the handshake finishes (iff true is returned).
        /// No-op if called twice or if socket is not in the connected state, in which case false is returned.
        bool startClientHandshake(const QString & resourceName, const QString & host, const QString & origin = {},
                                  int timeout = Handshake::Async::ClientSide::kDefaultTimeout);

        /// Use this after construction to start the WebSocket handshake as a server. `handshakeSuccess` or
        /// `handshakeFailed` will be emitted when the handshake finishes (iff true is returned).
        /// No-op if called twice or if socket is not in the connected state, in which case false is returned.
        bool startServerHandshake(const QString & serverAgent = Handshake::Async::ServerSide::kDefaultServerAgent,
                                  int timeout = Handshake::Async::ServerSide::kDefaultTimeout);

        /// Returns true iff the socket is now in a valid websocket state and is still connected (after handshake this is true).
        bool isValid() const;
        /// Read-only property. This is set depending on whether startClientHandshake or startServerHandshake was previously called
        Mode mode() const { return _mode; }
        /// The default message mode to use when generating frames for the QIODevice::write() function
        MessageMode messageMode() const { return _messageMode; }
        void setMessageMode(MessageMode m) { _messageMode = m; }
        /// If true, we will auto-reply to pings asynchronously in this object's thread's event loop
        bool autoPingReply() const { return autopingreply; }
        void setAutoPingReply(bool b) { autopingreply = b; }
        /// Returns the auto-ping interval in msec. Auto-ping is enabled by default and is set to 20000 (20 secs).
        /// When enabled, the other endpoint is automatically pinged at the specified interval.  Returns 0 if disabled.
        int autoPingInterval() const { return autopinginterval; }
        /// Set to <= 0 to disable auto-ping.
        void setAutoPingInterval(int msec);
        /// The maximum number of messages that may be queued. If more than this number of messages are in the message queue,
        /// then disconnectFromHost(PolicyViolated) will be sent to the other endpoint, as a DoS defense. Default: 20000.
        unsigned maxMessageQueue() const { return maxframes; }
        void setMaxMessageQueue(unsigned val) { if (val) maxframes = val; }

        /// From QTcpSocket, etc
        void resume() override { socket->resume(); }
        bool setSocketDescriptor(qintptr socketDescriptor, SocketState state = ConnectedState, OpenMode openMode = ReadWrite) override
        { return socket->setSocketDescriptor(socketDescriptor, state, openMode); }
        qintptr socketDescriptor() const override { return socket->socketDescriptor(); }

        using QAbstractSocket::connectToHost;
        /// calls underlying socket
        void connectToHost(const QString &hostName, quint16 port, OpenMode openMode = ReadWrite, NetworkLayerProtocol protocol = AnyIPProtocol) override
        { socket->connectToHost(hostName, port, openMode, protocol); }
        void setSocketOption(QAbstractSocket::SocketOption option, const QVariant &value) override
        { socket->setSocketOption(option, value); }
        QVariant socketOption(QAbstractSocket::SocketOption option) override
        { return socket->socketOption(option); }

        /// Sends CLOSE frame (Code: Normal 1000), waits 3 seconds for CLOSE reply before timing out the close handshake
        /// and aborting the connection unconditionally (this all happens asynch. -- this function returns immediately).
        void disconnectFromHost() override;
        /// Disconnect from remote host with a specified code and reason. Same semantics as disconnectFromHost().
        void disconnectFromHost(CloseCode code, const QByteArray & reason = {});

        // From QIODevice
        qint64 bytesAvailable() const override { return dataFrameByteCount + readDataPartialBuf.size(); }
        qint64 bytesToWrite() const override { return socket->bytesToWrite(); }
        bool canReadLine() const override; ///< do not use this
        void close() override { if (socket && socket->isOpen()) { emit aboutToClose(); } abort();  setOpenMode(NotOpen); }
        bool atEnd() const override { return socket->atEnd(); }
        bool flush() { return socket->flush(); } // ### Qt6: remove me (implementation moved to private flush())
        void abort() { socket->abort(); }

        // From QAbstractSocket:
        void setReadBufferSize(qint64 size) override { QTcpSocket::setReadBufferSize(size); socket->setReadBufferSize(size); }

        /// Returns the number of Binary and/or Text message frames in the receive message queue.
        int messagesAvailable() const { return int(dataMessages.size()); }
        /// Pops and returns the next (complete) Binary or Text message waiting in the receive queue, or an empty
        /// QByteArray if the receive queue was empty. Note that it's possible for the other endpoint to send empty
        /// frames (payload size 0), so to distinguish between that situation and an empty queue, one would need to call
        /// messagesAvailable() before calling this function. If the `binary` pointer is specified, will write true or
        /// false to it depending on whether the retrieved frame was of Binary or Text type.
        QByteArray readNextMessage(bool *binary = nullptr);
        /// Pops all of the queued messages off the receive queue and returns them. (All of the messages returned
        /// are complete -- no partial messages are ever returned here).
        MessageList readAllMessages();

        /// TODO: what do we do about all these?!
        bool waitForConnected(int msecs = 30000) override { return socket->waitForConnected(msecs); }
        //bool waitForHandshake(int msecs = 30000);
        bool waitForReadyRead(int msecs = 30000) override { return socket->waitForReadyRead(msecs); }
        bool waitForBytesWritten(int msecs = 30000) override { return socket->waitForBytesWritten(msecs); }
        bool waitForDisconnected(int msecs = 30000) override { return socket->waitForDisconnected(msecs); }

    signals:
        /// Emitted after startClientHandshake() or startServerHandshake() is called after successful websocket
        /// handshake completion. After this signal is emitted, the socket is in websocket mode and data may be
        /// sent/received.
        void handshakeSuccess();
        /// Emitted after startClientHandshake() or startServerHandshake() is called after a failed websocket handshake.
        void handshakeFailed(const QString &errorMessage);
        /// Guaranteed to eventually be emitted after startClientHandshake() or startServerHandshake() is called (if
        /// they returned true), indicating the handshake process has finished.  This is always emitted after
        /// handshakeSuccess() and/or handshakeFailed().
        void handshakeFinished();

        /// Similar in spirit to QSslSocket's "encryptedBytesWritten".  Emitted when the underlying socket sends
        /// data down the wire.  The value here will always be larger than the `bytesWritten` signal this class
        /// also emits, since it will account for Web Socket framing + payload data. (In contrast `bytesWritten` reports
        /// payload sizes, not counting framing overhead).
        void rawBytesWritten(qint64 totalBytes);

        void closeFrameReceived(quint16 code, const QByteArray &data);
        void pingFrameReceived(const QByteArray &data);
        void pongFrameReceived(const QByteArray &data);

        /// This is emitted when Text or Binary messages have arrived and are ready for processing.
        /// Use readNextMessage() or readAllMessages() to read the completed data frames.
        void messagesReady();

    public slots:
        qint64 sendPing(const QByteArray &data = {});
        qint64 sendPong(const QByteArray &data = {});

        qint64 sendText(const QByteArray &data);
        qint64 sendBinary(const QByteArray &data);

    protected:
        qint64 readData(char *data, qint64 maxlen) override; ///< this breaks the framing if called.
        qint64 readLineData(char *data, qint64 maxlen) override; ///< this breaks the framing if called.
        qint64 writeData(const char *data, qint64 len) override; ///< wraps the data in a frame and writes it to socket. uses the frameType specified in messageMode

        qint64 sendClose();
        qint64 sendClose(quint16 code, const QByteArray &reason = {});

    private:
        QPointer<QTcpSocket> socket;
        qint64 lastPongRecvd = 0;
        MessageList dataMessages;
        QByteArray readDataPartialBuf; ///< leftover data if readData() was called instead of the readNextMessage() API
        QByteArray buf; ///< working buffer for deserializing frames.
        qint64 dataFrameByteCount = 0;
        unsigned maxframes = 20'000;
        Mode _mode = Unknown;
        MessageMode _messageMode = Text;
        bool disconnectFlag = false;
        bool autopingreply = true;
        bool sentclose = false, gotclose = false;
        int autopinginterval = 20'000;

        void on_readyRead();
        inline bool isMasked() const { return _mode == ClientMode; }
        QTimer *getPingTimer();
        static constexpr auto kPingTimer = "_Auto_Ping_";
        void miscCleanup();
        void startAutoPing();
    };


#if defined(QT_DEBUG)
    /// call this from main directly with no QApplication object or anything else created (this creates its own qApp)
    int test(int argc, char *argv[]);
#endif
} // end namespace WebSocket

