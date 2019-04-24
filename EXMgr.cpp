#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
EXMgr::EXMgr(const QString & serversFile, QObject *parent)
    : QObject(parent), serversFile(serversFile)
{
    static bool initted_meta = false;
    if (!initted_meta) {
        qRegisterMetaType<EXResponse>();
        initted_meta = true;
    }
    loadServers();
}

EXMgr::~EXMgr()
{
    Debug() << __FUNCTION__ ;
    for (auto ex : clients) {
        delete ex;
    }
    clients.clear();
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
            auto client = new EXClient(this, host, tport, sport);
            clients.push_back(client);
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
    checkClientsTimer->start(EXClient::reconnectTime/2);
    Log() << "ElectrumX Manager started, found " << clients.count() << " servers from compiled-in servers.json";
}

void EXMgr::onNewConnection(EXClient *client)
{
    Debug () << "New connection for " << client->host;
    emit client->sendRequest(newReqId(), "server.version", QVariantList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
    emit client->sendRequest(newReqId(), "blockchain.headers.subscribe");
}

void EXMgr::onLostConnection(EXClient *client)
{
    Debug () << "Connection lost for " << client->host << ", status: " << client->status;
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
        client->info.height = r.result.toMap().value("height", 0).toInt();
        client->info.header = r.result.toMap().value("hex", "").toString();
        Debug() << "Got header subscribe: " << client->info.height << " / " << client->info.header;
    } else if (r.method == "server.ping") {
        // ignore...
    } else {
        Error() << "Unknown method \"" << r.method << "\" from " << client->host;
    }
}

void EXMgr::checkClients() ///< called from the checkClientsTimer every 1.5 mins
{
    static const qint64 bad_timeout = 15*60*1000, // 15 mins
                        stale_timeout = EXClient::reconnectTime; // 3 mins
    Debug() << "EXMgr: Checking clients...";
    for (EXClient *client : clients) {
        const auto now = Util::getTime();
        if (client->isGood() && !client->isStale())
            continue;
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
}
