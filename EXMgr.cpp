#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
EXMgr::EXMgr(QObject *parent) : QObject(parent)
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
    auto v = Util::Json::parseFile(":/file/servers.json");
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
    Log() << "ElectrumX Manager started, found " << clients.count() << " servers from compiled-in servers.json";
}

void EXMgr::onNewConnection()
{
    EXClient *client = sender() ? dynamic_cast<EXClient *>(sender()) : nullptr;
    if (!client) {
        Error() << __FUNCTION__ << ": no sender!";
        return;
    }
    Debug () << "New connection for " << client->host;
    emit client->sendRequest("server.version", QVariantList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
    emit client->sendRequest("blockchain.headers.subscribe");
}

void EXMgr::onLostConnection()
{
    EXClient *client = sender() ? dynamic_cast<EXClient *>(sender()) : nullptr;
    if (!client) {
        Error() << __FUNCTION__ << ": no sender!";
        return;
    }
    Debug () << "Connection lost for " << client->host;
}

void EXMgr::onResponse(EXResponse r)
{
    EXClient *client = sender() ? dynamic_cast<EXClient *>(sender()) : nullptr;
    if (!client) {
        Error() << __FUNCTION__ << ": no sender!";
        return;
    }
    Debug() << "(" << client->host << ") Got response in mgr to " << r.method;
    if (r.method == "server.version") {
        client->info.serverVersion[0] = r.result.toList()[0].toString();
        client->info.serverVersion[1] = r.result.toList()[1].toString();
        Debug() << "Got server version: " << client->info.serverVersion[0] << " / " << client->info.serverVersion[1];
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
