#include "EXClient.h"
#include "EXMgr.h"
#include "Util.h"
#include <QtNetwork>

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

QString EXClient::hostPrettyName() const
{
    QString type = socket ? (dynamic_cast<QSslSocket *>(socket) ? "SSL" : "TCP") : "(NoSocket)";
    QString port = socket ? QString(":%1").arg(socket->peerPort()) : "";
    QString ip = socket ? socket->peerAddress().toString() : "";
    return QString("%1 %2 %3%4").arg(type).arg(host).arg(ip).arg(port);
}

void EXClient::start()
{
    if (thread.isRunning()) return;
    Debug() << host << " starting thread";
    moveToThread(&thread);
    connect(&thread, &QThread::started, this, &EXClient::on_started);
    connect(&thread, &QThread::finished, this, &EXClient::on_finished);
    thread.start();
}

void EXClient::stop()
{
    if (thread.isRunning()) {
        Debug() << host << " thread is running, joining thread";
        thread.quit();
        thread.wait();
    }
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
        socket->abort();
    }
    if (socket) { delete socket; socket = nullptr; }
    status = NotConnected;
}

void EXClient::reconnect()
{
    killSocket();
    if (tport) {
        socket = new QTcpSocket(this);
        connect(socket, &QAbstractSocket::connected, this, [this]{
            Debug() << hostPrettyName() << " connected " << socket->peerAddress().toString();
            on_connected();
        });
        connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
        socket->connectToHost(host, static_cast<quint16>(tport));
    } else if (sport) {
        QSslSocket *ssl;
        socket = ssl = new QSslSocket(this);
        connect(ssl, &QSslSocket::encrypted, this, [this]{
            Debug() << hostPrettyName() << " encrypted " << socket->peerAddress().toString();
            on_connected();
        });
        connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(on_error(QAbstractSocket::SocketError)));
        connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(on_socketState(QAbstractSocket::SocketState)));
        ssl->connectToHostEncrypted(host, static_cast<quint16>(sport));
    } else {
        Error() << "No ssl port or tcp port defined for " << host << "!";
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

int EXClient::sendRequest(const QString &method, const QVariantList &params)
{
    auto id = ++reqid;
    idMethodMap[id] = method;
    socket->write(makeRequestData(id, method, params));
    return id;
}

void EXClient::on_connected()
{
    Debug() << __FUNCTION__;
    connect(socket, &QAbstractSocket::disconnected, this, [this]{
        Debug() << hostPrettyName() << " socket disconnected";
        // todo: put stuff to queue up a reconnect sometime later?
    });
    connect(socket, SIGNAL(readyRead()), this, SLOT(on_readyRead()));
    sendRequest("server.version");
}

/* static */
EXResponse EXResponse::fromJson(const QString &json)
{
    const auto m = Util::Json::parseString(json).toMap();
    const auto jsonrpc = m.value("jsonrpc", "").toString();
    if (jsonrpc != "2.0")
        throw BadServerReply(QString("Unexpected or missing jsonrpc version: \"%1\"").arg(jsonrpc));
    const int id = m.value("id", -1).toInt();
    if (id < 0)
        throw BadServerReply("Bad server reply, missing required id field in JSON");
    QVariantMap err = m.value("error", QVariantMap()).toMap();
    if (!err.isEmpty()) {
        // error reply
        const int code = err.value("code", 123456789).toInt();
        const QString message = err.value("message").toString();
        if (code == 123456789 || message.isEmpty())
            throw BadServerReply("Bad server reply, error field in JSON is not of the expected format");
        return EXResponse{
            jsonrpc, id, "unknown", QVariant(), code, message
        };
    }
    if (m.value("result", QVariant()).isNull()) {
        throw BadServerReply("Bad server reply, missing result field in JSON");
    }
    return EXResponse{
        jsonrpc,
        id,
        "unknown",
        m["result"]
    };
}

QString
EXResponse::toString() const
{
    return QString("jsonrpc: %1 ; id: %2 ; method: %3 ; result: %4 ; error code: %5 ; error message: %6")
            .arg(jsonRpcVersion).arg(id).arg(method).arg(result.isNull() ? "(null)" : Util::Json::toString(result, true))
            .arg(errorCode).arg(errorMessage);
}

void EXResponse::chkValid() const
{
    if (!errorMessage.isEmpty())
        return;
    if (method == "server.version") {
        QVariantList l = result.toList();
        if (l.count() < 2 || l[0].toString().isNull() || l[1].toString().isNull())
            throw BadServerReply(QString("%1 expected string list of size 2").arg(method));
        return;
    }
    throw BadServerReply(QString("Unknown or unexpected method \"%1\"").arg(method));
}

void EXClient::on_readyRead()
{
    Debug() << __FUNCTION__;
    try {
        while (socket->canReadLine()) {
            auto line = socket->readLine().trimmed();
            Debug() << "Got: " << line;
            auto resp = EXResponse::fromJson(line);
            auto meth = idMethodMap.take(resp.id);
            if (meth.isEmpty()) {
                throw BadServerReply(QString("Unexpected/unknown message id (%1) in server reply").arg(resp.id));
            }
            resp.method = meth;
            resp.chkValid(); // may throw
            Debug() << "Parsed response: " << resp.toString();
            lastGood = Util::getTime();
            emit gotResponse(resp);
        }
    } catch (const Exception &e) {
        Error() << "Error reading/parsing response: " << e.what();
        socket->abort();
        status = Bad;
    }
}

void EXClient::on_error(QAbstractSocket::SocketError err)
{

    Warning() << hostPrettyName() << ": error " << err << " (" << (socket ? socket->errorString() : "(null)") << ")";
    if (socket) socket->abort();
    status = NotConnected;
    // todo: put stuff to queue up a reconnect sometime later?
}

/* static */
QByteArray EXClient::makeRequestData(int id, const QString &method, const QVariantList &params)
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
