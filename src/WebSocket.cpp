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
#include "Util.h"
#include "WebSocket.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QLocale>
#include <QMetaObject>
#include <QRandomGenerator>
#include <QSet>
#include <QSslSocket>
#include <QTcpSocket>
#include <QtEndian>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <limits>
#include <memory>

namespace WebSocket
{
    Error::~Error() {} // for vtable
    MessageTooBigError::~MessageTooBigError() {} // for vtable

    using Byte = quint8;

    QString frameTypeName(FrameType ft)
    {
        switch(ft) {
        case FrameType::Text:          return QStringLiteral("Text");
        case FrameType::Binary:        return QStringLiteral("Binary");
        case FrameType::Ctl_Ping:      return QStringLiteral("Ping");
        case FrameType::Ctl_Pong:      return QStringLiteral("Pong");
        case FrameType::Ctl_Close:     return QStringLiteral("Close");
        case FrameType::_Continuation: return QStringLiteral("Continuation");
        }
        return QStringLiteral("Unknown (0x%1)").arg(quint8(ft), 2, 16, QChar('0'));
    }

    namespace Ser {
        QByteArray wrapPayload(const QByteArray &data, FrameType type, bool isMasked, std::size_t fragmentSize)
        {
            const bool isCtl = type & 0x08;
            if (isCtl)
                fragmentSize = 125; // force 125 for below code to work
            // see: https://tools.ietf.org/html/rfc6455#section-5.2
            if (fragmentSize == 0)
                throw BadArgs("fragmentSize may not be 0");
            if (fragmentSize > std::uint64_t(std::numeric_limits<std::int64_t>::max()))
                throw BadArgs("fragmentSize cannot exceed a 63-bit size");
            if (isCtl && data.size() > 125)
                throw BadArgs("control frames may not exceed 125 bytes of payload data");
            const auto dsize = std::size_t(data.size());
            constexpr int maxUShort = std::numeric_limits<std::uint16_t>::max();
            fragmentSize = std::max(std::min(dsize, fragmentSize), std::size_t(1));
            const auto nFragments = std::max(std::size_t(1), (dsize / fragmentSize) + (fragmentSize > 1UL && dsize % fragmentSize ? 1UL : 0UL));
            const auto perFragmentOverhead =
                    2UL // base opcode byte + minimum payload length byte
                    + (isMasked ? 4UL : 0) // if we have a mask, then the mask is encoded in the frame, per-frame as 4 bytes
                    + (fragmentSize > 125UL // sizes > 125 bytes are either 2-byte or 8-byte
                       ? (fragmentSize <= std::size_t(maxUShort) // does it fit in 2 bytes? (65535)
                          ? 2UL  // yes, it's <= 65535 and >= 126
                          : 8UL) // no, it does not, use a 64-bit (actually 63-bit size)
                       : 0UL); // <= 125 byte frame, no extra length bytes needed
            const auto retSize = dsize + perFragmentOverhead * nFragments;
            if (retSize > std::numeric_limits<int>::max())
                throw MessageTooBigError(QString("resulting buffer size of %1 is too large").arg(retSize));
            QByteArray ret(int(retSize), Qt::Uninitialized); // the last fragment here may contain too much data (at most 8 extra bytes)
            int nBytesRemain = int(dsize);
            Byte *dest = reinterpret_cast<Byte *>(ret.data());
            const Byte *src = reinterpret_cast<const Byte *>(data.constData());
            Byte opcode = Byte(type); // we intentionally made the enum type match the opcodes defined in the RFC
            const Byte maskBit = isMasked ? 0x80 : 0x0;
            assert(nFragments == 1 || type == Text || type == Binary);
            for (std::size_t i = 0; i < nFragments; ++i) {
                const quint32 mask = isMasked ? QRandomGenerator::global()->generate() : 0U;
                const Byte *pmask = reinterpret_cast<const Byte *>(isMasked ? &mask : nullptr);
                // write opcode byte
                *dest++ = Byte( opcode
                                // FIN-bit is the MSB bit. It is set if this is the last (or only) frame
                                | (i == nFragments-1 ? 0x80 : 0x0) );

                const int bytes2write = std::min(nBytesRemain, int(fragmentSize));
                // write length byte(s)
                if (bytes2write <= 125)
                    *dest++ = Byte(bytes2write) | maskBit;
                else if (bytes2write <= maxUShort) {
                    // >= 126, <= 65535
                    *dest++ = Byte(126) | maskBit; // indicate extended payload (2 bytes)
                    qToBigEndian(quint16(bytes2write), dest);
                    dest += 2;
                } else {
                    // >= 65536
                    *dest++ = Byte(127) | maskBit; // indicate extended payload (8 bytes)
                    qToBigEndian(quint64(bytes2write), dest);
                    dest += 8;
                }
                if (pmask == nullptr) {
                    assert(!maskBit);
                    // no mask, just write the frame data directly
                    std::memcpy(dest, src, std::size_t(bytes2write));
                    // update positions
                    dest += bytes2write;
                    src += bytes2write;
                } else {
                    assert(maskBit);
                    // mask is set -- write the octets xor'd with the mask
                    // first: write the 4 mask bytes themselves to the header so that the other end can decode
                    std::memcpy(dest, pmask, 4);
                    dest += 4;
                    // next: write the payload xor'd with the mask bytes
                    for (int j = 0; j < bytes2write; ++j)
                        *dest++ = *src++ ^ pmask[j % 4];
                }

                // update bytes remaining
                nBytesRemain -= bytes2write;

                // fragments after the first use opcode=0x0 (continuation frame)
                opcode = FrameType::_Continuation;
            }
            const char * const endpos = reinterpret_cast<char *>(dest);
//#ifdef QT_DEBUG
//            qDebug("Used %d/%d bytes", int(endpos-ret.constData()), ret.size());
//#endif
            assert(endpos >= ret.constData() && endpos <= ret.constData() + ret.size());
            // truncate the QByteArray down to the actual number of bytes used
            ret.truncate(int(endpos - ret.constData()));

            return ret;
        }

        QByteArray makeCloseFrame(bool isMasked, CloseCode code, const QByteArray &reason)
        {
            QByteArray buf(2, Qt::Uninitialized);
            qToBigEndian(quint16(code), buf.data());
            if (!reason.isEmpty())
                buf += reason.left(123);
            return wrapPayload(buf, FrameType::Ctl_Close, isMasked);
        }
    } // end namspace Ser


    namespace Deser {
        ProtocolError::~ProtocolError() {} // for vtable

        namespace {
            inline constexpr auto kMessageTooBig1 = "invalid payload length (>INT_MAX!)";

            inline void applyMask(Byte *buf, unsigned bufLen, const Byte *mask) {
                for (unsigned i = 0; i < bufLen; ++i)
                    buf[i] = buf[i] ^ mask[i % 4];
            }

            struct PartialFrame : public Frame {
                bool fin{};  // .fin is always true if .isControl() is true, but not the other way around
                // these point to the source buffer
                const Byte *begin = nullptr, *payloadBegin = nullptr, *end = nullptr;
                const Byte *mask = nullptr; // pointer to mask in src buffer -- non-null only iff this->masked == true
                bool accepted = false;
                // helpers -- these refer to the source buffer
                inline std::size_t srcWireLen() const { return end > begin ? std::size_t(end-begin) : 0U; }
                inline std::size_t srcPayloadLen() const { return end > payloadBegin ? std::size_t(end-payloadBegin) : 0U; }
                inline void loadDataFromSrc(QByteArray *dest) {
                    assert(dest);
                    if (payloadBegin) {
                        dest->reserve(std::max(dest->capacity(), dest->size() + int(srcPayloadLen())));
                        dest->append(reinterpret_cast<const char *>(payloadBegin), int(srcPayloadLen()));
                        if (mask && masked)
                            applyMask(reinterpret_cast<Byte *>(dest->data() + dest->length() - int(srcPayloadLen())),
                                      unsigned(srcPayloadLen()), mask);
                    }
                }
            };

            // Note the returned frames do NOT have the src data copied in! They all have .payload.isEmpty().
            // Calling code should use loadDataFromSrc() later to load the frames if/when they are accepted
            std::optional<PartialFrame> parseFrame(const Byte * const pos, const std::size_t len, MaskEnforcement maskEnforcement) {
                std::optional<PartialFrame> ret;
                if (len >= 2) {
                    std::size_t header = 2;
                    auto opByte = pos[0], lenByte = pos[1];
                    const bool isFin = opByte & 0x80; // highest bit indicates FIN
                    opByte = opByte & 0x0F; // take lower 4 bits (nibble)
                    const bool isMasked = lenByte & 0x80; // hightest bit indicates masked
                    lenByte = lenByte & 0x7F; // take lower 7 bits
                    // enforce mask, if maskEnforcement requires it
                    if (maskEnforcement == RequireMasked && !isMasked)
                        throw ProtocolError("encountered an unmasked frame, however masked frames are required");
                    else if (maskEnforcement == RequireUnmasked && isMasked)
                        throw ProtocolError("encountered a masked frame, however unmasked frames are required");
                    if (isMasked)
                        header += 4;
                    switch(opByte) {
                    case FrameType::Ctl_Ping:
                    case FrameType::Ctl_Pong:
                    case FrameType::Ctl_Close:
                        if (!isFin)
                            throw ProtocolError("fragmented control frame");
                        if (lenByte > 125)
                            throw ProtocolError("control frame has illegal size");
                        [[fallthrough]];
                    case FrameType::Text:
                    case FrameType::Binary:
                    case FrameType::_Continuation: // fragment continuation frame
                    {
                        constexpr auto kNonMinimalEncoding = "non-minimal length encoding encountered";
                        std::size_t parsedLen = lenByte;
                        if (lenByte == 126) {
                            header += 2;
                            if (len >= header) {
                                parsedLen = qFromBigEndian<quint16>(pos + 2);
                                if (parsedLen < lenByte)
                                    throw ProtocolError(kNonMinimalEncoding);
                            } else
                                break; // break out of switch, indicates not enough data is available
                        } else if (lenByte == 127) {
                            header += 8;
                            if (len >= header) {
                                parsedLen = qFromBigEndian<quint64>(pos + 2);
                                if (parsedLen < lenByte)
                                    throw ProtocolError(kNonMinimalEncoding);
                                if (parsedLen > quint64(std::numeric_limits<qint64>::max()))
                                    // this indicates the actual other end is sending garbage
                                    throw ProtocolError("invalid payload length (length cannot exceeded a 63-bit integer)");
                                if (parsedLen > quint64(std::numeric_limits<int>::max()))
                                    // this indicates our implementation's limitation
                                    throw MessageTooBigError(kMessageTooBig1);
                            } else
                                break; // break out of switch, indicates not enough data is available
                        }
                        const std::size_t total = header + parsedLen;
                        if (len >= total) {
                            const Byte *mask = isMasked ? pos + header - 4 : nullptr;
                            ret.emplace(
                                PartialFrame{
                                    Frame{
                                        FrameType(opByte),
                                        isMasked,
                                        {}, // .payload; never copy out payload data. Calling code will do this as needed.
                                    },
                                    isFin,
                                    pos,           // .begin
                                    pos + header,  // .payloadBegin
                                    pos + total,   // .end
                                    mask           // .mask
                                }
                            );
                        }
                    }
                        break;
                    default:
                        // unknown opcode byte
                        throw ProtocolError(QString("unknown frame opcode: 0x%1").arg(opByte, 2, 16, QChar('0')));
                    }
                }
                return ret;
            }
        }

        std::list<Frame> parseBuffer(QByteArray &buf, MaskEnforcement maskEnforcement)
        {
            std::list<Frame> ret;
            using PFList = std::list<PartialFrame>;
            PFList allFrames;
            std::list<PFList::iterator> ctlFrames, allDataFrames, acceptedDataFrames; // iterators pointing into "allFrames"
            const Byte * d = reinterpret_cast<const Byte *>(buf.constData());
            std::size_t len = std::size_t(buf.size()), pos = 0;
            // cf_a df1_a df1_b cf_b df1_c df0_d df0_d df1_d cf_c df0_e df0_e -> cf_a cf_b cf_c df_a df_b df_c df_d [with df0_e left over]
            while (auto optFrame = parseFrame(d + pos, len - pos, maskEnforcement)) {
                {
                    PartialFrame & pf = optFrame.value();
                    pos += pf.srcWireLen();
                    allFrames.emplace_back( std::move(pf) );
                }
                auto back_it = allFrames.end();
                --back_it;
                if (back_it->isControl()) {
                    ctlFrames.push_back( back_it );
                    back_it->accepted = true; // mark accepted -- this is used below to know which data to keep in the buffer and which to discard because it was already copied
                } else {
                    // queue the data frames for further analysis below
                    allDataFrames.push_back( back_it );
                }
            }

            // Remember what the unparsed/leftover stuff at the end was because we need to keep that around as leftovers
            const Byte * const keepAtEndBegin = d + pos;
            const int keepAtEndLen = int(len) - int(pos);
            int keepReserveSize = keepAtEndLen;

            // Now we have all the frames.

            // Next, search through the dataFrames and figure out ranges that we accept,
            // as well as predicate violations. We throw if:
            // - we encounter 0x0 continue frames without a preceding start data frame
            // - we encounter FIN frames that have non-zero opcode
            // - we encounter fragment START frames that have a zero opcode
            for (auto it = allDataFrames.begin(), end = allDataFrames.end(); it != end; ++it) {
                PFList::iterator pfi = *it;
                if (pfi->fin) {
                    if (pfi->type == FrameType::_Continuation)
                        throw ProtocolError("encountered a 'continue' frame with the FIN bit set, but without a corresponding start frame");
                    // non-fragmented FIN data frame, accept.
                    acceptedDataFrames.push_back(pfi);
                } else {
                    // search for a range of frames that end in a "FIN" frame
                    std::list<PFList::iterator> maybes;
                    auto it2 = it;
                    int cumSize = 0;
                    for (; it2 != end; ++it2) {
                        maybes.push_back(*it2);
                        cumSize += int(maybes.back()->srcWireLen());

                        if (const auto type = (*it2)->type; it == it2) {
                            // make sure that first frame in fragment set has opcode != 0, as per the RFC
                            if (type == FrameType::_Continuation)
                                throw ProtocolError("encountered a fragment start frame with opcode set to 0");
                        } else {
                            // make sure that all subsequent fragments after the first have opcode == 0, as per the RFC
                            if (type != FrameType::_Continuation)
                                throw ProtocolError(QString("encountered a continue frame with non-zero opcode: 0x%1")
                                                    .arg(int(type), 2, 16, QChar('0')));
                        }
                        // we found a FIN frame, indicate this by breaking out of loop
                        if ((*it2)->fin)
                            break;
                    }
                    if (it2 != end) { // did we encounter a FIN frame?
                        // yes, accept all of the maybes
                        acceptedDataFrames.splice(acceptedDataFrames.end(), std::move(maybes) );
                        it = it2; // update our outer loop iterator to point past this range
                    } else {
                        // no, break out of outer loop since we know nothing good is after 'it'.
                        keepReserveSize += cumSize; // remember this cumulative size of stuff we didn't process for later: keepBuf.reserve()
                        break;
                    }
                }
            }

            // now, copy out the PartialFrames -> ret Frame

            // first, the control frames go in front
            for (const auto & pfi : ctlFrames) {
                ret.push_back( *pfi );
                pfi->loadDataFromSrc(&ret.back().payload); // copy the data now directly to the destination Frame
            }

            // next the acceptable data frames, with fragments collapsed down into one destination Frame
            std::optional<Frame> tmpFrame;
            for (auto & pfi : acceptedDataFrames) {
                pfi->accepted = true; // mark ALL accepted now
                if (pfi->type == FrameType::Text || pfi->type == FrameType::Binary) {
                    tmpFrame = *pfi;
                    tmpFrame->payload.clear(); // this should already be empty, but to be defensive we must ensure data is empty initially
                    // data will be copied below
                } else if (pfi->type == FrameType::_Continuation && tmpFrame) {
                    // data will be copied below
                } else
                    // they sent us a continuation frame with a FIN set.. but with no corresponding start frame.
                    // note that this should not normally get triggered as we guard for it above already, but this
                    // was left in for defensive programming.
                    throw ProtocolError(QString("%1: Unexpected state in processing frame -- type=%2 tmpFrame=%3")
                                        .arg(__FUNCTION__ ).arg(pfi->type).arg(tmpFrame ? "valid" : "invalid"));

                // guard against ridiculously big messages that exceed QByteArray size limits
                if (std::size_t(tmpFrame->payload.length()) + pfi->srcPayloadLen() > std::size_t(std::numeric_limits<int>::max()))
                    throw MessageTooBigError(kMessageTooBig1);

                // append data to tmpFrame
                pfi->loadDataFromSrc(&tmpFrame->payload);

                if (pfi->fin) {
                    ret.emplace_back(std::move(*tmpFrame));
                    tmpFrame.reset();
                }
            }
            if (tmpFrame)
                // code above should guard against this -- this should never happen
                throw InternalError(QString("%1: Unexpected state -- tmpFrame was not pushed back .. FIXME!").arg(__FUNCTION__));

            // finally, copy back pieces of data we didn't process so that the `buf` arg now only contains unprocessed data.
            {
                QByteArray keepBuf;
                keepBuf.reserve(keepReserveSize);
                //qDebug("Reserved: %d", keepReserveSize);
                for (const auto & f : allFrames) {
                    if (f.accepted) // this data chunk was accepted, don't keep.
                        continue;
                    // data not accepted here, keep the unprocessed frames for next time
                    keepBuf.append(reinterpret_cast<const char *>(f.begin), int(f.srcWireLen()));
                }
                if (keepAtEndLen > 0)
                    keepBuf.append(reinterpret_cast<const char *>(keepAtEndBegin), keepAtEndLen);
                else if (keepAtEndLen < 0)
                    // Defensive programming. This should never happen.
                    throw InternalError("keepAtEndLen < 0! FIXME!");

                //qDebug("Actual: %d", keepBuf.size());
                buf = keepBuf; // re-assign the buffer now
            }

            return ret;
        }

        CloseFrameInfo & CloseFrameInfo::operator=(const Frame &f)
        {
            if (f.payload.size() >= 2) {
                code = qFromBigEndian<quint16>(f.payload.constData());
                reason = f.payload.mid(2);
            } else {
                code.reset();
                reason.clear();
            }
            return *this;
        }
    } // end namespace Deser

    namespace Handshake {

        namespace {
            /// UUID used for handshake from RFC 6455
            const auto UUID = QByteArrayLiteral("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

            /// some property keys -- these get written to the QTcpSocket
            constexpr auto kHandshakeStartedFlag = "websocket-handshake-started-flag",
                           kWebsocketFlag = "websocket-protocol",
                           kWebsocketHeaders = "websocket-headers",
                           kWebsocketReqResource = "websocket-request-resource";
            /// Some error templates used in ClientSide::start() and ServerSide::start()
            constexpr auto kMaxHeadersExceeded = "maxHeaders exceeded",
                           kBadHttpLine = "Bad HTTP: %1";
            const auto HttpMagic = QByteArrayLiteral("HTTP/");

            // this function is a copy of QHttpNetworkReplyPrivate::parseStatus
            bool parseStatusLine(const QByteArray &status, int *majorVersion, int *minorVersion,
                                 int *statusCode, QString *reasonPhrase)
            {
                // from RFC 2616:
                //        Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
                //        HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
                // that makes: 'HTTP/n.n xxx Message'
                // byte count:  0123456789012
                constexpr int minLength = 11;
                constexpr int dotPos = 6;
                constexpr int spacePos = 8;
                if (status.length() < minLength
                    || !status.startsWith(HttpMagic)
                    || status.at(dotPos) != '.'
                    || status.at(spacePos) != ' ') {
                    // I don't know how to parse this status line
                    return false;
                }
                // optimize for the valid case: defer checking until the end
                *majorVersion = status.at(dotPos - 1) - '0';
                *minorVersion = status.at(dotPos + 1) - '0';
                int i = spacePos;
                int j = status.indexOf(' ', i + 1); // j == -1 || at(j) == ' ' so j+1 == 0 && j+1 <= length()
                const QByteArray code = status.mid(i + 1, j - i - 1);
                bool ok;
                *statusCode = code.toInt(&ok);
                *reasonPhrase = QString::fromLatin1(status.constData() + j + 1);
                return ok && uint(*majorVersion) <= 9 && uint(* minorVersion) <= 9;
            }
            bool parseReqLine(const QByteArray & line, int *majorVersion, int *minorVersion, QString *reqMethod, QString *reqResource)
            {
                // Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
                // Method - all caps, one of: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT
                // Requiest-URI: 1 or more characters, URL encoded (no spaces)
                // HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
                constexpr int minLength = 12, dotPos = 6;
                static const QSet<QByteArray> acceptedMethods = {
                    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"
                };
                if (line.length() < minLength)
                    return false;

                auto toks = line.split(' ');
                if (toks.size() != 3)
                    return false;

                auto tmp = toks[0].trimmed();
                if (!acceptedMethods.contains(tmp))
                    return false;
                *reqMethod = tmp;

                tmp = toks[1].trimmed();
                if (tmp.isEmpty())
                    return false;
                *reqResource = QUrl::fromPercentEncoding(tmp);

                tmp = toks[2].trimmed();
                if (!tmp.startsWith(HttpMagic))
                    return false;
                if (uint(*majorVersion = tmp.at(dotPos - 1) - '0') > 9)
                    return false;
                if (uint(*minorVersion = tmp.at(dotPos + 1) - '0') > 9)
                    return false;
                return true;
            }
        }

        namespace Async {
            ClientServerBase::ClientServerBase(QTcpSocket *s)
                : QObject(s), sock(s)
            {
                setObjectName(QStringLiteral("WebSocket::Handshake::Async::ClientServerBase"));
                if (!sock) {
                    qWarning("ClientSide object constructed with a nullptr QTcpSocket");
                }
                connect(this, &ClientSide::success, this, &ClientSide::finished);
                connect(this, &ClientSide::failure, this, [this]{
                    if (autodisconnect && sock) {
                        //qDebug("Auto-disconnecting");
                        sock->disconnectFromHost();
                    }
                    emit finished();
                });
                connect(this, &ClientSide::finished, this, [this]{
                    if (autodelete) deleteLater();
                    //qDebug("finished");
                });
            }
            ClientServerBase::~ClientServerBase() {} ///< for vtable

            bool ClientServerBase::startCommon(int timeout)
            {
                if (!sock) {
                    emit failure("QTcpSocket is nullptr");
                    return false;
                }
                if (sock->state() != QAbstractSocket::SocketState::ConnectedState) {
                    emit failure("Socket is not connected");
                    return false;
                }
                if (!sock->property(kWebsocketFlag).isNull()) {
                    emit failure("Socket already negotiated protocol successfully");
                    return false;
                }
                if (!sock->property(kHandshakeStartedFlag).isNull()) {
                    emit failure("Already started once");
                    return false;
                }
                if (QSslSocket *ssl = dynamic_cast<QSslSocket *>(sock); ssl && !ssl->isEncrypted()) {
                    emit failure("SSL socket is not in encrypted mode");
                    return false;
                }
                if (!conns.isEmpty() || timer) {
                    // This should never happen. Added in the interests of defensive programming.
                    emit failure("INTERNAL ERROR: ConnList is not empty or timer is not nullptr (this should never happen)");
                    return false;
                }
                sock->setProperty(kHandshakeStartedFlag, true);

                // cleanup func
                conns += connect(this, &ClientSide::finished, this, [this]{
                    if (timer) {
                        timer->stop();
                        delete timer;
                        timer = nullptr;
                    }
                    for (auto & conn : conns)
                        QObject::disconnect(conn);
                    conns.clear();
                });
                // detect disconnect
                conns += connect(sock, &QAbstractSocket::disconnected, this, [this]{
                    emit failure("Connection lost");
                });

                if (timeout > 0) {
                    if (timer) delete timer;
                    timer = new QTimer(this);
                    conns += connect(timer, &QTimer::timeout, this, [this]{
                        emit failure("Timed out");
                    });
                    timer->setSingleShot(true);
                    timer->start(timeout);
                }

                nread = 0;
                headers.clear();

                conns += connect(sock, &QAbstractSocket::readyRead, this, [this]{ on_ReadyRead(); });

                return true;
            } // end function ClientServerBase::startCommon

            // --- ClientSide
            ClientSide::~ClientSide() { /*qDebug("%s", __FUNCTION__);*/ }

            void ClientSide::start(const QString &resourceName, const QString &host, const QString &origin, int timeout)
            {
                if (!startCommon(timeout))
                    return;
                // sock already had some bytes.. this shouldn't happen. Indicate failure.
                if (sock->bytesAvailable()) {
                    emit failure("Other end sent us data unexpectedly");
                    return;
                }

                // generate key
                QByteArray secKey(16, Qt::Uninitialized);
                QRandomGenerator::global()->fillRange(reinterpret_cast<quint32 *>(secKey.data()),
                                                      unsigned(secKey.size()) / sizeof(quint32));
                secKey = secKey.toBase64(); // encode the key now since we need it in this form for the SHA1
                expectedDigest = QString::fromLatin1(QCryptographicHash::hash(secKey + UUID, QCryptographicHash::Algorithm::Sha1).toBase64());


                // -- send header
                const QByteArray header =
                    QStringLiteral(
                        "GET %1 HTTP/1.1\r\n"
                        "Host: %2\r\n"
                        "%3" // may be empty or may be "Origin: originargtext\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %4\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        "\r\n"
                    ).arg(resourceName.trimmed())
                     .arg(host.trimmed())
                     .arg(origin.trimmed().isEmpty() ? QString() : QStringLiteral("Origin: %1\r\n").arg(origin.trimmed()))
                     .arg(QString::fromLatin1(secKey)).toLatin1();
                Trace("Sending header:\n%s", header.constData());
                sock->write(header);
            } // end function ClientSide::start

            void ClientSide::on_ReadyRead()
            {
                bool headersFinished = false;
                bool expectingStatusLine = nread == 0;
                try {
                    constexpr auto Fail = [](const QString &what) { throw Exception(what); };
                    while (sock->canReadLine()) {
                        if (maxHeaders > 0 && sock->bytesAvailable() > maxHeaders)
                            Fail(kMaxHeadersExceeded); // will implicitly disconnect signals from sock
                        auto line = sock->readLine();
                        nread += line.size();
                        if (maxHeaders > 0 && nread > maxHeaders)
                            Fail(kMaxHeadersExceeded);
                        line = line.trimmed();
                        if (line.isEmpty()) {
                            // end of headers
                            headersFinished = true;
                            break;
                        }
                        Trace("Got line: %s", line.constData());
                        if (expectingStatusLine) {
                            // parse status line
                            QString reasonPhrase;
                            int major, minor, code;
                            if (!parseStatusLine(line, &major, &minor, &code, &reasonPhrase)
                                    || major < 1 || minor < 1 || code != 101)
                                Fail(QString(kBadHttpLine).arg(QString(line)));
                            Trace("Got HTTP status 101 ok");
                            expectingStatusLine = false;
                        } else {
                            // expecting Header: value
                            const auto parts = line.split(':');
                            if (parts.size() < 2)
                                Fail("Bad header line");
                            const QString key = QString::fromLatin1(parts.front().trimmed().toLower()),
                                          value = QString::fromLatin1(parts.mid(1).join(':').trimmed());
                            headers[key] = value;
                            //qDebug("[Added header: %s=%s]", key.toUtf8().constData(), value.toUtf8().constData());
                        }
                    } // while
                    if (headersFinished) {
                        const bool ok =
                            !headers.isEmpty()
                                && headers.value(QStringLiteral("upgrade")).toLower() == QStringLiteral("websocket")
                                && headers.value(QStringLiteral("connection")).toLower() == QStringLiteral("upgrade");
                        if (QString gotKey;
                                ok && (gotKey=headers.value(QStringLiteral("sec-websocket-accept"))) != expectedDigest)
                            Fail(QString("Bad key: expected '%1', got '%2'").arg(QString(expectedDigest)).arg(gotKey));
                        if (ok) {
                            Debug("Successful websocket handshake to host %s:%hu", sock->peerName().toLatin1().constData(), sock->peerPort());
                            {
                                // save some properties to the socket
                                sock->setProperty(kWebsocketFlag, true);
                                QVariantMap m;
                                for (auto it = headers.cbegin(); it != headers.cend(); ++it)
                                    m[it.key()] = it.value();
                                sock->setProperty(kWebsocketHeaders, m); // save headers to sock
                            }
                            emit success();
                            return;
                        } else
                            Fail("Missing required headers");
                    }
                } catch (const std::exception &e) {
                    Debug("Failed handshake: %s", e.what());
                    emit failure(e.what());
                    // at this point this slot will never be called again because we auto-disconnect signals
                }
            } // end function ClientSide::on_ReadyRead

            // --- ServerSide
            ServerSide::~ServerSide(){} // for vtable

            void ServerSide::start(const QString & serverAgent, int timeout)
            {
                if (!startCommon(timeout))
                    return;

                reqResource.clear();
                this->serverAgent = serverAgent;

                // sock already had some bytes.. call on_ReadyRead() immediately
                if (sock->bytesAvailable())
                    on_ReadyRead();
            } // end function ServerSide::start

            void ServerSide::on_ReadyRead()
            {
                bool headersFinished = false;
                bool expectingReqLine = nread == 0;
                try {
                    const auto Fail = [this](const QString &what, quint16 code = 400,
                                             const QString & reason_ = QString(), /* Defaults to "Bad Request" */
                                             const QString & verboseReason = QString()) {
                        const QString reason = reason_.isEmpty() ? QStringLiteral("Bad Request") : reason_;
                        const QByteArray content = verboseReason.isEmpty() ? reason.toLatin1() : verboseReason.toLatin1();
                        const QByteArray resp = QStringLiteral(
                            "HTTP/1.1 %1 %2\r\n"
                            "Content-Length: %3\r\n"
                            "Content-Type: text/plain\r\n"
                            "Connection: close\r\n\r\n"
                            "%4"
                        ).arg(code).arg(reason).arg(content.size()).arg(QString::fromLatin1(content)).toLatin1();
                        sock->write(resp);
                        throw Exception(what);
                    };
                    while (sock->canReadLine()) {
                        if (maxHeaders > 0 && sock->bytesAvailable() > maxHeaders)
                            Fail(kMaxHeadersExceeded); // will implicitly disconnect signals from sock
                        auto line = sock->readLine();
                        nread += line.size();
                        if (maxHeaders > 0 && nread > maxHeaders)
                            Fail(kMaxHeadersExceeded);
                        line = line.trimmed();
                        if (line.isEmpty()) {
                            // end of headers
                            headersFinished = true;
                            break;
                        }
                        Trace("Got line: %s", line.constData());
                        if (expectingReqLine) {
                            // parse status line
                            QString method;
                            int major, minor;
                            if (!parseReqLine(line, &major, &minor, &method, &reqResource)
                                    || major < 1 || minor < 1 || method != "GET")
                                Fail(QString(kBadHttpLine).arg(QString(line)));
                            Trace("HTTP GET for: %s", reqResource.toUtf8().constData());
                            expectingReqLine = false;
                        } else {
                            // expecting Header: value
                            const auto parts = line.split(':');
                            if (parts.size() < 2)
                                Fail("Bad header line");
                            const QString key = QString::fromLatin1(parts.front().trimmed().toLower()),
                                          value = QString::fromLatin1(parts.mid(1).join(':').trimmed());
                            headers[key] = value;
                            //Trace("[Added header: %s=%s]", key.toUtf8().constData(), value.toUtf8().constData());
                        }
                    } // while
                    if (headersFinished) {
                        if (headers.isEmpty()
                                || headers.value(QStringLiteral("upgrade")).toLower() != QStringLiteral("websocket")
                                || headers.value(QStringLiteral("connection")).toLower() != QStringLiteral("upgrade"))
                            Fail("Bad header fields", 426, "Upgrade Required");

                        QByteArray key;
                        if (key = headers.value(QStringLiteral("sec-websocket-key")).toLatin1();
                                key.isEmpty() || QByteArray::fromBase64(key).toBase64() != key) {
                            Fail(QString("Bad key: '%1'").arg(QString::fromLatin1(key)),
                                 400, QString(), QStringLiteral("Invalid Sec-WebSocket-Key header: %1").arg(QString::fromLatin1(key)));
                        }
                        // -- send response header
                        {
                            constexpr auto GetHTTPDate = []{
                                return QLocale::c().toString(QDateTime::currentDateTime(), u"ddd, dd MMM yyyy hh:mm:ss 'GMT'");
                            };
                            const QByteArray header =
                                QStringLiteral(
                                    "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: %1\r\n"
                                    "%2" // may be empty or may be "Server: serverAgent\r\n"
                                    "Date: %3\r\n"
                                    "\r\n"
                                ).arg(QString(QCryptographicHash::hash(key + UUID, QCryptographicHash::Algorithm::Sha1).toBase64()))
                                 .arg(serverAgent.trimmed().isEmpty() ? QString() : QStringLiteral("Server: %1\r\n").arg(serverAgent.trimmed()))
                                 .arg(GetHTTPDate())
                                 .toLatin1();
                            Trace("Sending response header:\n%s", header.constData());
                            sock->write(header);
                        }

                        Debug("Successful websocket handshake for client %s:%hu",
                              sock->peerAddress().toString().toUtf8().constData(), sock->peerPort());
                        {
                            // save some properties to the socket
                            sock->setProperty(kWebsocketFlag, true);
                            QVariantMap m;
                            for (auto it = headers.cbegin(); it != headers.cend(); ++it)
                                m[it.key()] = it.value();
                            sock->setProperty(kWebsocketHeaders, m); // save headers to sock
                            sock->setProperty(kWebsocketReqResource, reqResource);
                        }
                        emit success();
                        return;
                    }
                } catch (const std::exception &e) {
                    Debug("%s:%hu failed handshake: %s", sock->peerAddress().toString().toUtf8().constData(), sock->peerPort(),
                          e.what());
                    emit failure(e.what());
                    // at this point this slot will never be called again because we auto-disconnect signals
                }
            } // end function ServerSide::on_ReadyRead

        } // end namespace Async
    } // end namespace Handshake

    // --- Wrapper
    Wrapper::Wrapper(QTcpSocket *socket_, QObject *parent)
        : QTcpSocket(socket_ == parent ? nullptr : parent), socket(socket_)
    {
        assert(socket);
        assert(parent != socket_);
        socket->setParent(this);
        connect(socket, &QTcpSocket::readyRead, this, &Wrapper::on_readyRead);
        connect(socket, &QTcpSocket::bytesWritten, this, &Wrapper::rawBytesWritten);

        connect(socket, &QTcpSocket::hostFound, this, &Wrapper::hostFound);
        connect(socket, &QTcpSocket::connected, this, &Wrapper::connected);
        connect(socket, &QTcpSocket::disconnected, this, &Wrapper::disconnected);
        connect(socket, &QTcpSocket::stateChanged, this, &Wrapper::setSocketState);
        connect(socket, &QTcpSocket::stateChanged, this, &Wrapper::stateChanged);
        connect(socket, qOverload<QAbstractSocket::SocketError>(&QTcpSocket::error), this, &Wrapper::setSocketError);
        connect(socket, qOverload<QAbstractSocket::SocketError>(&QTcpSocket::error),
                this, qOverload<QAbstractSocket::SocketError>(&Wrapper::error));

        setOpenMode(socket->openMode());
        setPeerName(socket->peerName());
        setPeerAddress(socket->peerAddress());
        setPeerPort(socket->peerPort());
        setLocalPort(socket->localPort());
        setLocalAddress(socket->localAddress());
        setSocketState(socket->state());
        setSocketError(socket->error());

        if (socket->state() != ConnectedState) {
            ::Error() << "WebSocket Wrapper may only be used with an already-connected socket";
        }

        // on handshake success, setup the auto-ping interval
        connect(this, &Wrapper::handshakeSuccess, this, &Wrapper::startAutoPing);
        // free some memory on disconnect
        connect(this, &Wrapper::disconnected, this, &Wrapper::miscCleanup);
    }

    void Wrapper::startAutoPing() { setAutoPingInterval(autopinginterval); }

    void Wrapper::miscCleanup() {
        dataMessages.clear();
        readDataPartialBuf.clear();
        buf.clear();
    }

    Wrapper::~Wrapper() {
        // During debug I found spuriously these signals can get delivered when we are no longer a `Wrapper`, but a
        // simple `QAbstractSocket`, so we must explicitly detach them here.
        disconnect(this, &Wrapper::disconnected, this, nullptr);
        if (socket) disconnect(socket, nullptr, this, nullptr);
    }

    bool Wrapper::isValid() const {
        return socket && socket->state() == ConnectedState && socket->property(Handshake::kWebsocketFlag).toBool() && _mode != Unknown;
    }

    QTimer *Wrapper::getPingTimer() { return findChild<QTimer *>(kPingTimer, Qt::FindDirectChildrenOnly); }

    void Wrapper::setAutoPingInterval(int msec)
    {
        auto pingTimer = getPingTimer();
        delete pingTimer; pingTimer = nullptr;
        if (msec > 0 && isValid()) {
            pingTimer = new QTimer(this);
            pingTimer->setObjectName(kPingTimer);
            pingTimer->setInterval(msec);
            connect(pingTimer, &QTimer::timeout, this, [this]{
                auto pingTimer = dynamic_cast<QTimer *>(sender());
                if (!pingTimer)
                    return;
                if (sentclose || gotclose || !isValid()) {
                    pingTimer->deleteLater();
                    return;
                }
                QByteArray data(sizeof(quint32), Qt::Uninitialized);
                *reinterpret_cast<quint32 *>(data.data()) = QRandomGenerator::global()->generate();
                sendPing(data);
                if (Util::getTime() - lastPongRecvd >= pingTimer->interval()*2) {
                    Debug() << "Ping timeout for " << QString::asprintf("%s:%hu", peerAddress().toString().toUtf8().constData(), peerPort());
                    disconnectFromHost(CloseCode::ProtocolError, QByteArrayLiteral("Ping timeout"));
                }
            });
            connect(this, &Wrapper::disconnected, pingTimer, [this]{ delete getPingTimer(); });
            lastPongRecvd = Util::getTime(); // save timestamp now
            pingTimer->start();
        }
        autopinginterval = msec > 0 ? msec : 0;
    }

    /// No-op if called twice or if socket is not in the connected state.
    bool Wrapper::startClientHandshake(const QString & resourceName, const QString & host, const QString & origin, int timeout)
    {
        if (_mode != Unknown || !socket || socket->state() != QAbstractSocket::SocketState::ConnectedState)
            return false;
        _mode = ClientMode;
        auto hs = new Handshake::Async::ClientSide(socket);
        connect(hs, &Handshake::Async::ClientSide::success, this, &Wrapper::handshakeSuccess);
        connect(hs, &Handshake::Async::ClientSide::failure, this, &Wrapper::handshakeFailed);
        connect(hs, &Handshake::Async::ClientSide::finished, this, &Wrapper::handshakeFinished);
        hs->start(resourceName, host, origin, timeout);
        return true;
    }

    /// No-op if called twice or if socket is not in the connected state.
    bool Wrapper::startServerHandshake(const QString & serverAgent, int timeout)
    {
        if (_mode != Unknown || !socket || socket->state() != QAbstractSocket::SocketState::ConnectedState)
            return false;
        _mode = ServerMode;
        auto hs = new Handshake::Async::ServerSide(socket);
        connect(hs, &Handshake::Async::ServerSide::success, this, &Wrapper::handshakeSuccess);
        connect(hs, &Handshake::Async::ServerSide::failure, this, &Wrapper::handshakeFailed);
        connect(hs, &Handshake::Async::ServerSide::finished, this, &Wrapper::handshakeFinished);
        hs->start(serverAgent, timeout);
        return true;
    }

    void Wrapper::disconnectFromHost() { disconnectFromHost(CloseCode::Normal); }

    void Wrapper::disconnectFromHost(CloseCode code, const QByteArray &reason)
    {
        if (disconnectFlag)
            return;
        disconnectFlag = true;

        if (sentclose) {
            // caller is impatient. Just close now.
            socket->disconnectFromHost();
            return;
        }
        // wait up to 3 seconds for close reply
        sendClose(code, reason);
        QTimer::singleShot(3000, this, [this]{
            if (!gotclose && isValid()) {
                Debug() << "close reply timeout, closing socket";
                socket->disconnectFromHost();
            }
        });
    }

    qint64 Wrapper::sendClose()
    {
        return sendClose(CloseCode::Normal);
    }

    qint64 Wrapper::sendClose(quint16 code, const QByteArray &reason)
    {
        sentclose = true;
        Trace() << "sending CLOSE";
        return socket->write(Ser::makeCloseFrame(isMasked(), CloseCode(code), reason));
    }

    qint64 Wrapper::sendPong(const QByteArray &data)
    {
        Trace() << "sending PONG " << data.size() << " bytes";
        return socket->write(Ser::makePongFrame(data, isMasked()));
    }

    qint64 Wrapper::sendPing(const QByteArray &data)
    {
        Trace() << "sending PING " << data.size() << " bytes";
        return socket->write(Ser::makePingFrame(isMasked(), data));
    }

    qint64 Wrapper::sendText(const QByteArray &data)
    {
        Trace() << "sending TEXT " << data.size() << " bytes";
        qint64 res = -1;
        try {
            res = socket->write(Ser::wrapText(data, isMasked()));
        } catch (const std::exception & e) {
            ::Error() << "Wrapper::sendText caught exception: " << e.what();
        }
        if (res > -1) {
            emit bytesWritten(data.size());
            return data.size();
        }
        return -1;
    }
    qint64 Wrapper::sendBinary(const QByteArray &data)
    {
        Trace() << "sending BINARY " << data.size() << " bytes";
        qint64 res = -1;
        try {
            res = socket->write(Ser::wrapBinary(data, isMasked()));
        } catch (const std::exception & e) {
            ::Error() << "Wrapper::sendBinary caught exception: " << e.what();
        }
        if (res > -1) {
            emit bytesWritten(data.size());
            return data.size();
        }
        return -1;
    }

    void Wrapper::on_readyRead()
    {
        if (!isValid())
            return;
        if (socket->readBufferSize() > 0) { // <=0 indicates "infinite" read buffer (which is the default for QAbstractSocket)
            if (const auto size = buf.size() + bytesAvailable(); size > socket->readBufferSize()) {
                const auto peerName = peerAddress().toString() + ":" + QString::number(peerPort());
                Warning() << "WebSocket::wrapper: working buffer size " << size << " exceeds readBufferSize " << socket->readBufferSize() << ", skipping read for peer " << peerName;
                return;
            }
        }
        buf += socket->readAll();
        bool dataQueued = false;
        try {
            auto frames = Deser::parseBuffer(buf, _mode == ServerMode ? Deser::MaskEnforcement::RequireMasked : Deser::MaskEnforcement::RequireUnmasked);
            for (auto & f : frames) {
                if (!f.isControl()) {
                    if (dataMessages.size() >= maxframes) {
                        disconnectFromHost(CloseCode::PolicyViolated, QByteArrayLiteral("Message queue size exceeded"));
                        break;
                    }
                    const auto & back = dataMessages.emplace_back(std::move(f)); // f is invalid now, use `back` instead
                    dataFrameByteCount += back.payload.size();
                    dataQueued = true;
                } else {
                    if (f.type == FrameType::Ctl_Close) {
                        const Deser::CloseFrameInfo info(f);
                        Trace() << "Got CLOSE " << info.code.value_or(0) << info.reason;
                        gotclose = true;
                        emit closeFrameReceived(info.code.value_or(0), info.reason);
                        if (!sentclose) {
                            sendClose();
                        } else {
                            Trace() << "disconnectFromHost received Close reply";
                        }
                        socket->disconnectFromHost();
                    } else if (f.type == FrameType::Ctl_Ping) {
                        Trace() << "Got PING " << f.payload.size() << " bytes";
                        if (autopingreply && !gotclose) {
                            sendPong(f.payload);
                        }
                        emit pingFrameReceived(f.payload);
                    } else if (f.type == FrameType::Ctl_Pong) {
                        Trace() << "Got PONG " << f.payload.size() << " bytes";
                        lastPongRecvd = Util::getTime();
                        emit pongFrameReceived(f.payload);
                    }
                }
            }
            if (dataQueued) {
                emit readyRead();
                emit messagesReady();
            }
        } catch (const std::exception &e) {
            const auto type = dynamic_cast<const WebSocket::Deser::ProtocolError *>(&e) ? "protocol error" : "exception";
            const auto peerName = socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
            Warning() << "WebSocket: " << type << " for " << peerName << ": " << e.what();
            Warning() << "WebSocket: aborting " << peerName;
            close();
            setErrorString(e.what());
        }
    }

    bool Wrapper::canReadLine() const
    {
        Warning() << "WebSocket::Wrapper Warning: canReadLine called -- this is not how this class is meant to be used";
        if (readDataPartialBuf.contains('\n'))
            return true;
        for (const auto & m : dataMessages) {
            if (m.payload.contains('\n'))
                return true;
        }
        return false;
    }

    QByteArray Wrapper::readNextMessage(bool *binary)
    {
        QByteArray ret;
        if (!dataMessages.empty()) {
            auto & msg = dataMessages.front();
            if (binary) *binary = msg.type == FrameType::Binary;
            dataFrameByteCount -= msg.payload.size();
            ret.swap(msg.payload);
            dataMessages.pop_front();
        }
        return ret;
    }

    auto Wrapper::readAllMessages() -> MessageList
    {
        MessageList ret;
        ret.swap(dataMessages);
        for (const auto & m : ret) {
            dataFrameByteCount -= m.payload.size();
        }
        return ret;
    }

    qint64 Wrapper::writeData(const char *data, qint64 len)
    {
        if (len < 0)
            return len;
        if (qint64 max = std::numeric_limits<int>::max()/2; len > max) {
            Warning() << "Wrapper::writeData: len " << len << " exceeds max " << max << ", will do a short write.";
            len = max;
        }
        auto res = socket->write(Ser::wrapPayload(QByteArray(data, int(len)), FrameType(_messageMode), isMasked()));
        if (res > -1) {
            // Note: When socket->write() succeeds, it always returns the full buffer length (infinite write buffer!).
            emit bytesWritten(len);
            return len;
        }
        return -1;
    }

    qint64 Wrapper::readData(char *data, qint64 maxlen) { ///< this breaks the framing if called.
        if (!isValid() || !isOpen() || maxlen < 0)
            return -1;
        Warning() << "WebSocket::Wrapper Warning: readData called -- this is not how this class is meant to be used";
        qint64 nread = 0;
        while (maxlen > 0 && (readDataPartialBuf.size() || !dataMessages.empty())) {
            if (readDataPartialBuf.isEmpty()) {
                readDataPartialBuf = dataMessages.front().payload;
                dataFrameByteCount -= readDataPartialBuf.size();
                dataMessages.pop_front();
            }
            qint64 n = std::min(qint64(readDataPartialBuf.size()), maxlen);
            if (n > 0) {
                std::memcpy(data + nread, readDataPartialBuf.constData(), std::size_t(n));
                readDataPartialBuf = readDataPartialBuf.mid(int(n));
                nread += n;
                maxlen -= n;
            }
        }
        return nread;
    }
    qint64 Wrapper::readLineData(char *data, qint64 maxlen) { ///< this breaks the framing if called.
        if (!isValid() || !isOpen() || maxlen < 0)
            return -1;
        Warning() << "WebSocket::Wrapper Warning: readLineData called -- this is not how this class is meant to be used";
        if (!canReadLine()) // <-- this is slow, but then again, this whole API is not how this class should be used.
            return 0;
        qint64 nread = 0;
        bool found = false;
        while (maxlen > 0 && !found && (readDataPartialBuf.size() || !dataMessages.empty())) {
            if (readDataPartialBuf.isEmpty()) {
                readDataPartialBuf = dataMessages.front().payload;
                dataFrameByteCount -= readDataPartialBuf.size();
                dataMessages.pop_front();
            }
            qint64 pos = readDataPartialBuf.indexOf('\n');
            if (pos < 0)
                pos = readDataPartialBuf.size();
            else  {
                pos += 1;
                found = true;
            }
            qint64 n = std::min(pos, maxlen);
            if (n > 0) {
                std::memcpy(data + nread, readDataPartialBuf.constData(), std::size_t(n));
                readDataPartialBuf = readDataPartialBuf.mid(int(n));
                nread += n;
                maxlen -= n;
            }
        }
        return nread;
    }

    // --- /Wrapper

} // end namespace WebSocket

#if defined(QT_DEBUG)
// testing stuff
#include "Util.h"

#include <QFile>
#include <QHostAddress>
#include <QRegExp>
#include <QTcpServer>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>

#include <QtDebug>

#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <typeinfo>

namespace WebSocket {
    namespace {
        using FramesList = std::list<WebSocket::Deser::Frame>;
        void printFrames(const FramesList & frames)
        {
            std::cout << "Parsed:\n";
            int i = 0;
            if (frames.empty())
                std::cout << "(Nothing parsed)\n";
            for (const auto & f : frames) {
                std::cout << "Frame: " << i++
                          << "  Type: " << WebSocket::frameTypeName(f.type).toUtf8().constData()
                          << "  masked: " << std::boolalpha << f.masked << std::noboolalpha
                          << "\n";
                //std::cout << "Hex:\n";
                //std::cout << f.payload.toHex().constData() << "\n";
                std::cout << "Decoded:\n";
                std::cout << f.payload.constData() << "\n";
            }
        }
    }
    int test(int argc, char *argv[])
    {
        Debug::forceEnable = true;
        Trace::forceEnable = true;
        if (argc < 3) {
            // stand alone test encoding / decoding
            std::cout << "Enter text:\n";
            std::array<char, 65536> linebuf;
            const QRegExp hexRE("^[0-9a-fA-F]+$");
            while ( std::cin.getline(linebuf.data(), linebuf.size()) ) {
                QByteArray b = QByteArray(linebuf.data()).trimmed();
                QByteArray frameData;

                try {
                    if (hexRE.exactMatch(b)) {
                        frameData = QByteArray::fromHex(b);
                    } else {
                        frameData = WebSocket::Ser::wrapText(b, true, 260);
                        std::cout << "Generated hex:\n" << frameData.toHex().constData() << "\n";
                    }
                    const auto frames = WebSocket::Deser::parseBuffer(frameData);
                    printFrames(frames);
                    std::cout << "Leftovers: [" << frameData.toHex().constData() << "]\n";
                } catch (const std::exception & e) {
                    std::cout << "caught exception: " << e.what() << "\n";
                    return 1;
                }
            }
            return 0;
        } else if (argc == 3) {
            // connect to SSL host test
            const QString host = argv[1];
            const quint16 port = quint16(QString(argv[2]).toUInt());
            QCoreApplication app(argc, argv);
            QSslSocket *ssock = new QSslSocket(&app); // will end up owned by the WebSocket::Wrapper
            QThread thr;
            QTimer::singleShot(10, &app, [&]{
                thr.start();
                QObject::connect(&app, &QCoreApplication::aboutToQuit, &app, [&]{
                    thr.quit();
                    thr.wait();
                    qDebug("App quit");
                });
                QObject::connect(&thr, &QThread::finished, &app, []{
                   qDebug("Thread finished");
                }, Qt::DirectConnection);
                std::cout << "Connecting to " << host.toUtf8().constData() << ":" << port << "\n";
                //QObject::connect(ssock, &QAbstractSocket::connected, &app, [&]{
                QObject::connect(ssock, &QSslSocket::encrypted, &app, [&app, ssock, &thr, &host]{
                    WebSocket::Wrapper *sock = new WebSocket::Wrapper(ssock, &app);
                    QObject::connect(sock, &QSslSocket::stateChanged, [](auto state){
                        qDebug("Wrapper state: %d", int(state));
                    });
                    QObject::connect(sock, &WebSocket::Wrapper::handshakeFailed, &app, [&](const QString &reason){
                        qDebug("Handshake failed: %s", reason.toUtf8().constData());
                        app.exit(1);
                    });
                    QObject::connect(sock, &WebSocket::Wrapper::handshakeSuccess, &app, [sock, &thr, &app]{
                        std::cout << "Handshake ok!\n";
                        QObject::connect(sock, &WebSocket::Wrapper::messagesReady, sock, [sock] {
                            const auto frames = sock->readAllMessages();
                            printFrames(frames);
                        });
                        QTimer *timer = new QTimer(nullptr);
                        const auto readLine = [sock, timer, &app]() mutable{
                            std::cout << "Enter text to send:\n";
                            std::array<char, 16384> linebuf;
                            if ( std::cin.getline(linebuf.data(), linebuf.size()) ) {
                                Util::AsyncOnObject(sock, [data = QByteArray(linebuf.data()).trimmed(), sock]() mutable {
                                    if (data == "!")
                                        sock->disconnectFromHost(CloseCode::GoingAway, "Bye");
                                    else if (data == "~")
                                        sock->sendPing("pingtest");
                                    else
                                        sock->sendText(data);
                                });
                            } else {
                                if (timer) {
                                    timer->stop();
                                    timer->deleteLater();
                                    timer = nullptr;
                                }
                                Util::AsyncOnObject(&app, [&app] {app.quit();});
                            }
                        };
                        QObject::connect(timer, &QTimer::timeout, timer, readLine);
                        timer->start(10);
                        timer->moveToThread(&thr);
                    });
                    QObject::connect(sock, &QAbstractSocket::disconnected, &app, [&app, sock]{
                        sock->deleteLater();
                        app.exit(2);
                    });
                    sock->startClientHandshake("/electrum", host, "bitcoin.com");
                });
                QObject::connect(ssock, &QSslSocket::stateChanged, [](auto state){
                    qDebug("Socket state: %d", int(state));
                });
                QObject::connect(ssock, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), [&](auto errs){
                    for (const auto & err : errs) {
                        qDebug("SSL Error: %s", err.errorString().toUtf8().constData());
                    }
                    ssock->ignoreSslErrors();
                });
                //ssock->connectToHost(host, port);
                ssock->connectToHostEncrypted(host, port, host);
            });
            return app.exec();
        } else if (argc == 5) {
#ifdef Q_OS_DARWIN
            // workaround for annoying macos keychain access prompt. see: https://doc.qt.io/qt-5/qsslsocket.html#setLocalCertificate
            setenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1", 1);
#endif
            // echo WSS server mode
            class EchoServer : public QTcpServer {
                QSslCertificate cert;
                QSslKey key;
            public:
                EchoServer(const QSslCertificate & cert, const QSslKey & key, QObject *parent=nullptr)
                    : QTcpServer(parent), cert(cert), key(key) {}
                void incomingConnection(qintptr socketDescriptor) override {
                    // this is taken from ServerSSL in Servers.cpp
                    QSslSocket *socket = new QSslSocket(this);
                    if (socket->setSocketDescriptor(socketDescriptor)) {
                        socket->setLocalCertificate(cert);
                        socket->setPrivateKey(key);
                        socket->setProtocol(QSsl::SslProtocol::AnyProtocol);
                        const auto peerName = QStringLiteral("%1:%2").arg(socket->peerAddress().toString()).arg(socket->peerPort());
                        if (socket->state() != QAbstractSocket::SocketState::ConnectedState || socket->isEncrypted()) {
                            qWarning() << peerName << " socket had unexpected state (must be both connected and unencrypted), deleting socket";
                            delete socket;
                            return;
                        }
                        QTimer *timer = new QTimer(socket);
                        timer->setObjectName(QStringLiteral("ssl handshake timer"));
                        timer->setSingleShot(true);
                        connect(timer, &QTimer::timeout, this, [socket, timer, peerName]{
                            qWarning() << peerName << " SSL handshake timed out after " << QString::number(timer->interval()/1e3, 'f', 1) << " secs, deleting socket";
                            socket->abort();
                            socket->deleteLater();
                        });
                        auto tmpConnections = std::make_shared<QList<QMetaObject::Connection>>();
                        *tmpConnections += connect(socket, &QSslSocket::disconnected, this, [socket, peerName]{
                            qDebug() << peerName << " SSL handshake failed due to disconnect before completion, deleting socket";
                            socket->deleteLater();
                        });
                        *tmpConnections += connect(socket, &QSslSocket::encrypted, this, [this, timer, tmpConnections, socket, peerName] {
                            timer->stop();
                            timer->deleteLater();
                            if (tmpConnections) {
                                // tmpConnections will get auto-deleted after this lambda returns because the QObject connection holding
                                // it alive will be disconnected.
                                for (const auto & conn : *tmpConnections)
                                    disconnect(conn);
                            }
                            qDebug() << "Encrypted ok, wrapping with WebSocket and initiating handshake";
                            WebSocket::Wrapper *wsock = new WebSocket::Wrapper(socket, this);
                            connect(wsock, &QAbstractSocket::disconnected, this, [wsock]{
                                auto peerName = QString::asprintf("%s:%hu", wsock->peerAddress().toString().toUtf8().constData(), wsock->peerPort());
                                qDebug() << peerName << "disconnected, deleting";
                                wsock->deleteLater();
                            });
                            connect(wsock, &Wrapper::handshakeSuccess, this, [wsock, this]{
                                qDebug() << "Handshake ok, calling addPendingConnection";
                                addPendingConnection(wsock);
                                emit newConnection();
                            });
                            wsock->startServerHandshake();
                        });
                        *tmpConnections +=
                        connect(socket, qOverload<const QList<QSslError> &>(&QSslSocket::sslErrors), this, [socket, peerName](const QList<QSslError> & errors) {
                            for (const auto & e : errors)
                                qWarning() << peerName << " SSL error: " << e.errorString();
                            qDebug() << peerName << " Aborting connection due to SSL errors";
                            socket->deleteLater();
                        });
                        timer->start(10000); // give the handshake 10 seconds to complete
                        socket->startServerEncryption();
                    } else {
                        qWarning() << "setSocketDescriptor returned false -- unable to initiate SSL for client: " << socket->errorString();
                        delete socket;
                    }
                }
            };
            QFile certf(argv[1]), keyf(argv[2]);
            if (!certf.open(QIODevice::ReadOnly)) {
                qCritical() << "Failed to open certificate file:" << argv[1];
                return 1;
            }
            if (!keyf.open(QIODevice::ReadOnly)) {
                qCritical() << "Failed to open key file:" << argv[2];
                return 2;
            }
            QSslCertificate cert(&certf, QSsl::EncodingFormat::Pem);
            if (cert.isNull()) {
                qCritical() << "Failed to read certificate file:" << argv[1];
                return 3;
            }
            QSslKey key(&keyf, QSsl::KeyAlgorithm::Rsa, QSsl::EncodingFormat::Pem);
            if (key.isNull()) {
                qCritical() << "Failed to read key file:" << argv[2];
                return 4;
            }
            qDebug() << "Read cert and key ok";
            QHostAddress iface;
            iface.setAddress(QString(argv[3]));
            if (iface.isNull()) {
                qCritical() << "Bad interface" << argv[3];
                return 5;
            }
            quint16 port = QString(argv[4]).toUShort();
            if (port < 1024) {
                qCritical() << "Bad port" << argv[4];
                return 6;
            }
            QCoreApplication app(argc, argv);
            EchoServer srv(cert, key, &app);
            QTimer::singleShot(10, &srv, [&]{
                const QString hostPortStr = QString::asprintf("%s:%hu", iface.toString().toLatin1().constData(), port);
                if (!srv.listen(iface, port)) {
                    qCritical() << "Failed to listen on" << hostPortStr;
                    app.exit(1);
                    return;
                }
                qDebug() << "Listening for connections on" << hostPortStr;
            });
            QObject::connect(&srv, &QTcpServer::newConnection, &app, [&]{
                QTcpSocket *tsock = srv.nextPendingConnection();
                if (!tsock) return;
                WebSocket::Wrapper *sock = dynamic_cast<WebSocket::Wrapper *>(tsock);
                if (!sock) {
                    qWarning() << "Socket not a WebSocket::Wrapper! FIXME!";
                    tsock->deleteLater();
                    return;
                }
                const QString peerName = QString::asprintf("%s:%hu", sock->peerAddress().toString().toLatin1().constData(), sock->peerPort());
                qDebug() << "Got connection from" << peerName;
                auto closing = std::make_shared<bool>(false);
                auto extantPings = std::make_shared<QSet<QByteArray>>();
                QObject::connect(sock, &WebSocket::Wrapper::messagesReady, sock, [sock, extantPings]() mutable {
                    const auto frames = sock->readAllMessages();
                    for (const auto & f : frames) {
                        // data, echo back
                        if (f.type == WebSocket::FrameType::Text) {
                            qDebug("Got text frame [%s], echoing back", f.payload.constData());
                            sock->sendText(QByteArray("ECHO ") + f.payload);
                        } else {
                            qDebug("Got data frame [%d bytes], echoing back", f.payload.size());
                            sock->sendBinary(f.payload);
                        }
                    }
                });
            });
            return app.exec();
        }
        //else ...
        std::cerr << "Unknowna args\n";
        return 1;
    } // end function test
} // end namespace WebSocket

#endif
