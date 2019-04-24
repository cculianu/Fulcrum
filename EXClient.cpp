#include "EXClient.h"
#include "EXMgr.h"
#include "Util.h"
#include <QtNetwork>

namespace  {
    const qint64 MAX_BUFFER = 20000000LL;
}

class BadServerReply : public Exception {
public:
    BadServerReply(const QString &what) : Exception(what) {}
    ~BadServerReply();
};

BadServerReply::~BadServerReply() {}

EXClient::EXClient(EXMgr *mgr, const QString &host, quint16 tport, quint16 sport)
    : QObject(nullptr), host(host), tport(tport), sport(sport), mgr(mgr)
{
    Debug() << __FUNCTION__ << " host:" << host << " t:" << tport << " s:" << sport;
    thread.setObjectName(QString("%1 %2").arg("EXClient").arg(host));
}

EXClient::~EXClient()
{
    Debug() << __FUNCTION__ << " host:" << host;
    stop();
}

/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString EXClient::hostPrettyName() const
{
    QString type = socket ? (dynamic_cast<QSslSocket *>(socket) ? "SSL" : "TCP") : "(NoSocket)";
    QString port = socket && socket->peerPort() ? QString(":%1").arg(socket->peerPort()) : "";
    QString ip = socket && !socket->peerAddress().isNull() ? socket->peerAddress().toString() : "";
    return QString("%1 %2 %3%4").arg(type).arg(host).arg(ip).arg(port);
}

bool EXClient::isGood() const
{
    return thread.isRunning() && status == Connected && info.isValid();
}

bool EXClient::isStale() const
{
    return isGood() && Util::getTime() - lastGood > stale_threshold;
}

void EXClient::start()
{
    if (thread.isRunning()) return;
    Debug() << host << " starting thread";
    moveToThread(&thread);
    connect(&thread, &QThread::started, this, &EXClient::on_started);
    connect(&thread, &QThread::finished, this, &EXClient::on_finished);
    connect(this, &EXClient::sendRequest, this, &EXClient::_sendRequest);
    thread.start();
}

void EXClient::stop()
{
    if (thread.isRunning()) {
        Debug() << host << " thread is running, joining thread";
        thread.quit();
        thread.wait();
    }
    disconnect(this, &EXClient::sendRequest, this, &EXClient::_sendRequest);
    disconnect(&thread, &QThread::started, this, &EXClient::on_started);
    disconnect(&thread, &QThread::finished, this, &EXClient::on_finished);
}

// runs in thread
void EXClient::on_started()
{
    Debug() << "started";
    reconnect();
}

// runs in thread
void EXClient::on_finished()
{
    killSocket();
    moveToThread(qApp->thread());
    Debug() << "finished.";
}

void EXClient::killSocket()
{
    if (socket && socket->state() != QAbstractSocket::UnconnectedState) {
        Debug() << host << " aborting connection";
        boilerplate_disconnect();
    }
    if (socket) { delete socket; socket = nullptr; }
    status = NotConnected;
}

void EXClient::reconnect()
{
    killSocket();
    lastConnectionAttempt = Util::getTime();
    if (sport && QSslSocket::supportsSsl()) {
        QSslSocket *ssl;
        socket = ssl = new QSslSocket(this);
        auto conf = ssl->sslConfiguration();
        conf.setPeerVerifyMode(QSslSocket::VerifyNone);
        ssl->setSslConfiguration(conf);
        connect(ssl, &QSslSocket::encrypted, this, [this]{
            Debug() << hostPrettyName() << " connected encrypted";
            on_connected();
        });
        connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
        socket->setSocketOption(QAbstractSocket::KeepAliveOption, true);  // from Qt docs: required on Windows
        ssl->connectToHostEncrypted(host, static_cast<quint16>(sport));
    } else if (tport) {
        socket = new QTcpSocket(this);
        connect(socket, &QAbstractSocket::connected, this, [this]{
            Debug() << hostPrettyName() << " connected";
            on_connected();
        });
        connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
        socket->setSocketOption(QAbstractSocket::KeepAliveOption, true);  // from Qt docs: required on Windows
        socket->connectToHost(host, static_cast<quint16>(tport));
    } else {
        Error() << "Cannot connect to " << host << "; no TCP port defined and SSL is disabled on this install";
    }
}

void EXClient::on_socketState(QAbstractSocket::SocketState s)
{
    Debug() << hostPrettyName() << " socket state: " << s;
    switch (s) {
    case QAbstractSocket::ConnectedState:
        status = Connected;
        break;
    case QAbstractSocket::HostLookupState:
    case QAbstractSocket::ConnectingState:
        status = Connecting;
        break;
    case QAbstractSocket::UnconnectedState:
    case QAbstractSocket::ClosingState:
    default:
        status = NotConnected;
        break;
    }
}

bool EXClient::_sendRequest(qint64 id, const QString &method, const QVariantList &params)
{
    if (status != Connected || !socket) {
        Error() << __FUNCTION__ << " method: " << method << "; Not connected!";
        return false;
    }
    while (idMethodMap.size() > 20000) {  // prevent memory leaks in case of misbehaving server
        idMethodMap.erase(idMethodMap.begin());
    }
    idMethodMap[id] = method;

    return do_write(makeRequestData(id, method, params));
}

void EXClient::boilerplate_disconnect()
{
    status = status == Bad ? Bad : NotConnected;  // try and keep Bad status around so EXMgr can decide when to reconnect based on it
    if (socket) socket->abort();  // this will set status too because state change, but we set it first above to be paranoid
}

bool EXClient::do_write(const QByteArray & data)
{
    auto data2write = writeBackLog + data;
    qint64 written = socket->write(data2write);
    if (written < 0) {
        Error() << __FUNCTION__ << " error on write " << socket->error() << " (" << socket->errorString() << ") ";
        boilerplate_disconnect();
        return false;
    } else if (written < data2write.length()) {
        writeBackLog = data2write.mid(int(written));
    }
    nSent += written;
    if (writeBackLog.length() > MAX_BUFFER) {
        Error() << __FUNCTION__ << " MAX_BUFFER reached on write (" << MAX_BUFFER << ")";
        boilerplate_disconnect();
        return false;
    }
    return true;
}

void EXClient::kill_pingTimer()
{
    if (pingTimer) { delete pingTimer; pingTimer = nullptr; }
}

void EXClient::start_pingTimer()
{
    kill_pingTimer();
    pingTimer = new QTimer(this);
    pingTimer->setSingleShot(false);
    connect(pingTimer, SIGNAL(timeout()), this, SLOT(on_pingTimer()));
    pingTimer->start(pingtime_ms/* 1 minute */ / 2);
}

void EXClient::on_pingTimer()
{
    if (Util::getTime() - lastGood > pingtime_ms)
        // only ping if we've been idle for longer than 1 minute
        emit sendRequest(mgr->newReqId(), "server.ping");
}

void EXClient::on_connected()
{
    // runs in thread
    Debug() << __FUNCTION__;
    connect(socket, SIGNAL(readyRead()), this, SLOT(on_readyRead()));
    if (dynamic_cast<QSslSocket *>(socket)) {
        // for some reason Qt can't find this old-style signal for QSslSocket so we do the below.
        // Additionally, bytesWritten is never emitted for QSslSocket, violating OOP! Thanks Qt. :P
        connect(socket, SIGNAL(encryptedBytesWritten(qint64)), this, SLOT(on_bytesWritten()));
    } else {
        connect(socket, SIGNAL(bytesWritten()), this, SLOT(on_bytesWritten()));
    }
    connect(socket, &QAbstractSocket::disconnected, this, [this]{
        Debug() << hostPrettyName() << " socket disconnected";
        kill_pingTimer();
        emit lostConnection(this);
        idMethodMap.clear();
        // todo: put stuff to queue up a reconnect sometime later?
    });
    emit newConnection(this);
    start_pingTimer();
}

/* static */
EXResponse EXResponse::fromJson(const QString &json)
{
    const auto m = Util::Json::parseString(json).toMap();
    const auto jsonrpc = m.value("jsonrpc", "").toString();
    if (jsonrpc != "2.0")
        throw BadServerReply(QString("Unexpected or missing jsonrpc version: \"%1\"").arg(jsonrpc));
    const qint64 id = m.value("id", -1).toLongLong();
    QString method = m.value("method", "").toString();
    if (id < 0 && method.isEmpty())
        throw BadServerReply("Bad server reply, missing required id field in JSON");
    QVariantMap err = m.value("error", QVariantMap()).toMap();
    if (!err.isEmpty()) {
        // error reply
        const int code = err.value("code", 123456789).toInt();
        const QString message = err.value("message").toString();
        if (code == 123456789 || message.isEmpty())
            throw BadServerReply("Bad server reply, error field in JSON is not of the expected format");
        return EXResponse{
            jsonrpc, id, method, QVariant(), code, message
        };
    }
    QVariant result = m.value("result", QVariant());
    if (result.isNull()) {
        result = m.value("params", QVariant());
    }

    return EXResponse{
        jsonrpc,
        id,
        method,
        result
    };
}

QString
EXResponse::toString() const
{
    return QString("jsonrpc: %1 ; id: %2 ; method: %3 ; result: %4 ; error code: %5 ; error message: %6")
            .arg(jsonRpcVersion).arg(id).arg(method).arg(result.isNull() ? "(null)" : Util::Json::toString(result, true))
            .arg(errorCode).arg(errorMessage);
}

void EXResponse::validate()
{
    if (!errorMessage.isEmpty())
        return;
    if (method == "server.version" && !result.isNull()) {
        QVariantList l = result.toList();
        if (l.count() < 2 || l[0].toString().isNull() || l[1].toString().isNull())
            throw BadServerReply(QString("%1 expected string list of size 2").arg(method));
        return; // ok
    } else if (method == "blockchain.headers.subscribe" && !result.isNull()) {
        QVariantMap m = result.toMap();
        QVariantList l = result.toList();
        if (m.isEmpty() && !l.isEmpty()) {
            // spontaneous "subscribe" callbacks pass a list containing a dict rather than a straight up dict,
            // so mogrify ourselves to always contain the dict
            m = l.last().toMap();
            result = m; // save back result as a map rather than a list
        }
        if (m.isEmpty() || m.count() < 2 || m.value("height", -1).toInt() < 0 || m.value("hex", "").toString().isEmpty()) {
            throw BadServerReply(QString("%1 expected map with 'height' and 'hex'").arg(method));
        }
        return; // ok
    } else if (method == "server.ping") {
        // always accept
        return;
    }
    throw BadServerReply(QString("Unexpected method \"%1\", and/or incomplete/missing results").arg(method));
}

void EXClient::on_readyRead()
{
    Debug() << __FUNCTION__;
    try {
        while (socket->canReadLine()) {
            auto data = socket->readLine();
            nReceived += data.length();
            auto line = data.trimmed();
            Debug() << "Got: " << line;
            auto resp = EXResponse::fromJson(line);
            auto meth = resp.id > 0 ? idMethodMap.take(resp.id) : resp.method;
            if (meth.isEmpty()) {
                throw BadServerReply(QString("Unexpected/unknown message id (%1) in server reply").arg(resp.id));
            }
            resp.method = meth;
            resp.validate(); // may throw, may modify resp
            Debug() << "Parsed response: " << resp.toString();
            lastGood = Util::getTime();
            emit gotResponse(this, resp);
        }
        if (socket->bytesAvailable() > MAX_BUFFER) {
            // bad server.. sending us garbage data not containing newlines. Kill connection.
            throw BadServerReply(QString("Server has sent us more than %1 bytes without a newline! Bad server?").arg(MAX_BUFFER));
        }
    } catch (const Exception &e) {
        Error() << "Error reading/parsing response: " << e.what();
        boilerplate_disconnect();
        status = Bad;
    }
}

void EXClient::on_bytesWritten()
{
    Debug() << __FUNCTION__;
    if (!writeBackLog.isEmpty() && status == Connected && socket) {
        Debug() << "writeBackLog size: " << writeBackLog.length();
        do_write();
    }
}

void EXClient::on_error(QAbstractSocket::SocketError err)
{
    Warning() << hostPrettyName() << ": error " << err << " (" << (socket ? socket->errorString() : "(null)") << ")";
    boilerplate_disconnect();
    // todo: put stuff to queue up a reconnect sometime later?
}

/* static */
QByteArray EXClient::makeRequestData(qint64 id, const QString &method, const QVariantList &params)
{
    QVariantMap m;
    m["id"] = id;
    m["method"] = method;
    m["params"] = params;
    try {
        static const QChar nl(012);
        return QString("%1%2").arg(Util::Json::toString(m, true)).arg(nl).toUtf8();
    } catch (const Util::Json::Error &e) {
        Error() << __FUNCTION__ << ": " << e.what();
    }
    return QByteArray();
}
