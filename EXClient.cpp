#include "EXClient.h"
#include "EXMgr.h"
#include "Util.h"
#include <QtNetwork>


class BadServerReply : public Exception {
public:
    using Exception::Exception; /// bring in c'tor
    ~BadServerReply();
};

BadServerReply::~BadServerReply() {} // for vtable

EXClient::EXClient(EXMgr *mgr, qint64 id, const QString &host, quint16 tport, quint16 sport)
    : AbstractClient(id, nullptr), host(host), tport(tport), sport(sport), mgr(mgr)
{
    Debug() << __FUNCTION__ << " host:" << host << " t:" << tport << " s:" << sport;
    _thread.setObjectName(QString("%1 %2").arg("EXClient").arg(host));
    setObjectName(host);
    connect(this, &AbstractClient::lostConnection, this, [this](AbstractClient *){
         emit lostConnection(this); /// re-emits as EXClient * signal (different method in C++)
    });
}

EXClient::~EXClient()
{
    Debug() << __FUNCTION__ << " " << objectName();
    stop(); ///< need to be sure to call this here rather than rely on ThreadObjectMixin, as by the time it runs, we lost our vtable
}

/// this should only be called from our thread, because it accesses socket which should only be touched from thread
QString EXClient::prettyName(bool dontTouchSocket) const
{
    if (_thread.isRunning() && QThread::currentThread() != &_thread) {
        Warning() << __PRETTY_FUNCTION__ << " called from another thread! FIXME!";
        dontTouchSocket = true;
    }
    return AbstractClient::prettyName(dontTouchSocket);
}

bool EXClient::isGood() const
{
    return AbstractClient::isGood() && _thread.isRunning() && info.isValid();
}

void EXClient::start()
{
    ThreadObjectMixin::start();
    connect(this, &EXClient::sendRequest, this, &EXClient::_sendRequest);
}

void EXClient::stop()
{
    /// Disconnect this externally originating signal before stopping to
    /// ensure no new signals get sent to us after we switch back to the
    /// main thread.
    disconnect(this, &EXClient::sendRequest, this, &EXClient::_sendRequest);
    ThreadObjectMixin::stop();
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
    ThreadObjectMixin::on_finished(); // calls moveToThread
    Debug() << "finished.";
}

void EXClient::killSocket()
{
    if (socket && socket->state() != QAbstractSocket::UnconnectedState) {
        Debug() << host << " aborting connection";
        boilerplate_disconnect();
    }
    delete socket; socket = nullptr;  // delete of nullptr ok
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
            Debug() << prettyName() << " connected encrypted";
            on_connected();
        });
        socketConnectSignals();
        ssl->connectToHostEncrypted(host, static_cast<quint16>(sport));
    } else if (tport) {
        socket = new QTcpSocket(this);
        connect(socket, &QAbstractSocket::connected, this, [this]{
            Debug() << prettyName() << " connected";
            on_connected();
        });
        socketConnectSignals();
        socket->connectToHost(host, static_cast<quint16>(tport));
    } else {
        Error() << "Cannot connect to " << host << "; no TCP port defined and SSL is disabled on this install";
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


void EXClient::do_ping()
{
    emit sendRequest(mgr->newId(), "server.ping");
}

void EXClient::on_connected()
{
    // runs in thread
    AbstractClient::on_connected();
    connect(this, &EXClient::lostConnection, this, [this](){
        idMethodMap.clear();
    });
    emit newConnection(this);
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
