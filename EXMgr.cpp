#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
#include "App.h"
#include <vector>

EXMgr::EXMgr(const QString & serversFile, QObject *parent)
    : Mgr(parent), serversFile(serversFile)
{
    static bool initted_meta = false;
    if (!initted_meta) {
        qRegisterMetaType<EXResponse>();
        initted_meta = true;
    }
}

EXMgr::~EXMgr()
{
    Debug() << __FUNCTION__ ;
    cleanup();
}

inline qint64 EXMgr::newId() const { return app()->newId(); }

void EXMgr::startup()
{
    if (clients.isEmpty()) {
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
            connect(client, &EXClient::gotResponse, this, &EXMgr::onResponse);
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

void EXMgr::onResponse(EXClient *client, EXResponse r)
{
    Debug() << "(" << client->host << ") Got response in mgr to " << r.method;
    if (r.method == "server.version") {
        client->info.serverVersion.first = r.result.toList()[0].toString();
        client->info.serverVersion.second = r.result.toList()[1].toString();
        Debug() << "Got server version: " << client->info.serverVersion.first << " / " << client->info.serverVersion.second;
    } else if (r.method == "blockchain.headers.subscribe") {
        int ht = r.result.toMap().value("height", 0).toInt();
        QString hdr = r.result.toMap().value("hex", "").toString();
        if (ht > 0) {
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
        }
        Debug() << "Got header subscribe: " << client->info.height << " / " << client->info.header << " (count for height = " << height.seenBy.count() << ")";
    } else if (r.method == "server.ping") {
        // ignore; timestamps updated in EXClient
    } else {
        Error() << "Unknown method \"" << r.method << "\" from " << client->host;
    }
}

void EXMgr::checkClients() ///< called from the checkClientsTimer every 1 mins
{
    static const qint64 bad_timeout = 15*60*1000, // 15 mins
                        low_server_timeout = checkClientsTimer->interval()/2; // 30 seconds
    Debug() << "EXMgr: Checking clients...";
    int lagCt = 0;
    const bool lowServers = height.seenBy.count() == 0;
    const qint64 stale_timeout = lowServers ? low_server_timeout : EXClient::reconnectTime; // 1 or 2 mins
    for (EXClient *client : clients) {
        const auto now = Util::getTime();
        const bool lagging = client->info.height < height.height && client->info.isValid();
        if (client->isGood() && !client->isStale()) {
            if (lagging) ++lagCt;
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
    if (lagCt) {
        Log() << lagCt << " servers are lagging behind the latest block height";
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
