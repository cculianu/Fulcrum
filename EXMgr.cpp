#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
EXMgr::EXMgr(QObject *parent) : QObject(parent)
{
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
        int tport = versionok ? smap.value("t", 0).toInt() : 0;
        int sport = versionok ? smap.value("s", 0).toInt() : 0;
        bool ok = versionok && (tport || sport);
        QString host = it.key();
        //Debug() << "Server: " << host << " s:" << sport << " t:" << tport << " " << (ok ? "ok" : "not ok");
        if (ok) {
            auto client = new EXClient(this, host, tport, sport);
            clients.push_back(client);
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
