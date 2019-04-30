#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
#include "RPC.h"
#include <vector>

EXMgr::EXMgr(const QString & serversFile, QObject *parent)
    : Mgr(parent), serversFile(serversFile)
{
}

EXMgr::~EXMgr()
{
    Debug() << __FUNCTION__ ;
    cleanup();
}

void EXMgr::startup()
{
    if (clients.isEmpty()) {
        initRPCMethods();
        loadServers();
    } else {
        Error() << __PRETTY_FUNCTION__ << " called with EXClients already active! FIXME!";
    }
}

void EXMgr::cleanup()
{
    for (auto ex : clients) {
        delete ex; // will wait for threads to finish
    }
    clients.clear();
    clientsById.clear();
    _rpcMethods.clear();
}

void EXMgr::loadServers()
{
    auto v = Util::Json::parseFile(serversFile);
    auto m = v.toMap();
    for (auto it = m.constBegin(); it != m.constEnd(); ++it) {
        auto smap = it.value().toMap();
        bool versionok = !smap.isEmpty() && smap.value("version", "").toString().startsWith("1.4");
        quint16 tport = versionok ? quint16(smap.value("t", 0).toUInt()) : 0U;
        quint16 sport = versionok ? quint16(smap.value("s", 0).toUInt()) : 0U;
        bool ok = versionok && (tport || sport);
        QString host = it.key();
        //Debug() << "Server: " << host << " s:" << sport << " t:" << tport << " " << (ok ? "ok" : "not ok");
        if (ok) {
            auto client = new EXClient(this, newId(), host, tport, sport);
            clients.push_back(client);
            clientsById[client->id] = client;
            connect(client, &EXClient::newConnection, this, &EXMgr::onNewConnection);
            connect(client, &EXClient::lostConnection, this, &EXMgr::onLostConnection);
            connect(client, &EXClient::gotMessage, this, &EXMgr::onMessage);
            client->start();
        } else {
            Warning() << "Bad server entry: " << host;
        }
    }
    if (clients.isEmpty()) {
        throw Exception("No ElectrumX servers! Cannot proceed.");
    }
    checkClientsTimer = new QTimer(this); checkClientsTimer->setSingleShot(false);
    connect(checkClientsTimer, SIGNAL(timeout()), this, SLOT(checkClients()));
    checkClientsTimer->start(EXClient::reconnectTime/2); // 1 minute
    Log() << "ElectrumX Manager started, found " << clients.count() << " servers from compiled-in servers.json";
}

void EXMgr::onNewConnection(EXClient *client)
{
    Debug () << "New connection for " << client->host;
    emit client->sendRequest(newId(), "server.version", QVariantList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
    emit client->sendRequest(newId(), "blockchain.headers.subscribe");
}

void EXMgr::onLostConnection(EXClient *client)
{
    Debug () << "Connection lost for " << client->host << ", status: " << client->status;
    height.seenBy.remove(client->id);
    client->info.clear();
}

void EXMgr::onMessage(EXClient *client, const RPC::Message &m)
{
    if (m.isError()) {
        // handle error replies -- for now just print yellow warning message to console log for debugging
        // TODO: Figure out what to do about errors.
        Warning("(%s) Got error reply: code: %d message: \"%s\"",
                Q2C(client->host), m.errorCode, Q2C(m.errorMessage));
        return;
    }
    Debug() << "(" << client->host << ") Got message in mgr, method: " << m.method;
    if (m.method == "server.version") {
        QVariantList l = m.data.toList();
        if (l.size() == 2) {
            client->info.serverVersion.first = l[0].toString();
            client->info.serverVersion.second = l[1].toString();
            Debug() << "Got server version: " << client->info.serverVersion.first << " / " << client->info.serverVersion.second;
        } else {
            Error() << "Bad server version reply! Schema should have handled this. FIXME! Json: " << m.toJsonString();
        }
    } else if (m.method == "blockchain.headers.subscribe") {
        // list of dicts.. or a simple value.. handle either.  TODO: make this a more general mechanism.
        const QVariantList list ( m.data.toList() );
        const QVariantMap map ( list.isEmpty() ? m.data.toMap() : list.back().toMap() );
        int ht = map.value("height", 0).toInt();
        QString hdr = map.value("hex", "").toString();
        if (ht > 0 && !hdr.isEmpty()) {
            if (ht > height.height) {
                height.height = ht;
                height.ts = Util::getTime();
                height.header = hdr;
                height.seenBy.clear();
            }
            if (ht == height.height)
                height.seenBy.insert(client->id);
            client->info.height = ht;
            client->info.header = hdr;
        } else {
            Error() << "Bad server headers reply! Schema should have handled this. FIXME! Json: " << m.toJsonString();
        }
        Debug() << "Got header subscribe: " << client->info.height << " / " << client->info.header << " (count for height = " << height.seenBy.count() << ")";
    } else if (m.method == "server.ping") {
        // ignore; timestamps updated in EXClient and RPC::Connection
        //Debug() << "server.ping reply... yay";
    } else {
        Error() << "Unknown method \"" << m.method << "\" from " << client->host;
    }
}

void EXMgr::checkClients() ///< called from the checkClientsTimer every 1 mins
{
    static const qint64 bad_timeout = 15*60*1000, // 15 mins
                        low_server_timeout = checkClientsTimer->interval()/2; // 30 seconds
    Debug() << "EXMgr: Checking clients...";
    const bool lowServers = height.seenBy.count() == 0;
    const qint64 stale_timeout = lowServers ? low_server_timeout : EXClient::reconnectTime; // 1 or 2 mins
    QStringList laggers;
    for (EXClient *client : clients) {
        const auto now = Util::getTime();
        if (const bool lagging = client->info.height < height.height && client->info.isValid();
                client->isGood() && !client->isStale())
        {
            if (lagging) laggers += QString("%1 (%2)").arg(client->host).arg(client->info.height);
            continue;
        }
        qint64 elapsed = qMin(now-client->lastConnectionAttempt, now-client->lastGood);
        if (client->isBad() && elapsed  > bad_timeout) {
            Log() << "'Bad' EX host " << client->host << ", reconnecting...";
            client->restart();
        } else if (client->isStale() && elapsed > stale_timeout) {
            Log() << "'Stale' EX host " << client->host << ", reconnecting...";
            client->restart();
        } else if (!client->isGood() && elapsed > stale_timeout) {
            Log() << "EX host " << client->host << ", retrying...";
            client->restart();
        }
    }
    if (int ct = laggers.count(); ct) {
        QString s = ct == 1 ? " is" : "s are";
        Log("%d server%s lagging behind the latest block height of %d: %s", ct, Q2C(s), height.height, Q2C(laggers.join(", ")));
    }
}

EXClient * EXMgr::pick()
{
    // defensive programming: enforce caller is in main thread
    if (QThread::currentThread() != qApp->thread()) {
        // crash the program
        throw InternalError(QString("%1 was called from a thread other than the main thread")
                            .arg(__PRETTY_FUNCTION__));
    }
    auto unpicked = height.seenBy - recentPicks;
    if (unpicked.isEmpty()) {
        // reset picking
        recentPicks.clear();
        unpicked = height.seenBy - recentPicks;
    }
    std::vector<decltype(unpicked)::key_type> shuffled(unpicked.begin(), unpicked.end());
    Util::shuffle(shuffled.begin(), shuffled.end());
    for (auto id : shuffled) {
        EXClient *client = clientsById[id];
        if (client->status == EXClient::Connected) {
            recentPicks.insert(client->id);
            return client;
        }
    }
    return nullptr;
}

void EXMgr::initRPCMethods()
{
    QString m, d;
    m = "blockchain.headers.subscribe";
    d = "{\"hex\" : \"somestring\", \"height\" : 1}";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [%2] }").arg(m).arg(d), // in schema (asynch from server -> us)
        RPC::schemaResult + QString(" { \"result\" : %1}").arg(d), // result schema (synch. server -> us)
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [\"=0\"] }").arg(m) // out schema  (req. us -> server)
    )));

    m = "server.version";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::Schema(), // in schema (asynch from server -> us) -- DISABLED for server.version
        RPC::schemaResult + QString(" { \"result\" : [\"=2\"] }"), // result schema (synch. server -> us) -- enforce must have 2 string args
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [\"=2\"] }").arg(m) // out schema  (req. us -> server) -- enforce must have 2 string args
    )));

    m = "server.ping";
    _rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::Schema(), // in schema (asynch from server -> us) -- DISABLED for server.ping
        RPC::schemaResult + QString(" { \"result\" : null }"), // result schema -- 'result' arg should be there and be null.
        RPC::schemaMethodNoParams // out schema, ping to server takes no args
    )));
}

void EXMgr::pickTest()
{
    for (int i = 0; i < 100; ++i) {
        auto client = pick();
        if (client) {
            Log() << "Picked " << client->id;
        } else {
            Warning() << "Pick found nothing!";
        }
        QThread::msleep(100);
        if (qApp) qApp->processEvents();
    }
}
