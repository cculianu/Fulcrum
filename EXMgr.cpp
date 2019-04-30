#include "EXMgr.h"
#include "EXClient.h"
#include "Util.h"
#include "RPC.h"
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
    rpcMethods.clear();
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
    // testing
    //testComposeRequest(123, "blockchain.headers.subscribe");
    //testComposeRequest(123, "server.version", QVariantList({QString("%1/%2").arg(APPNAME).arg(VERSION), QString("1.4")}));
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
        Log("%d server%s lagging behind the latest block height of %d: %s", ct, s.toUtf8().constData(), height.height, laggers.join(", ").toUtf8().constData());
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

void EXMgr::initRPCMethods()
{
    QString m, d;
    m = "blockchain.headers.subscribe";
    d = "{\"hex\" : \"somestring\", \"height\" : 1}";
    rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [%2] }").arg(m).arg(d), // in schema (asynch from server -> us)
        RPC::schemaResult + QString(" { \"result\" : %1}").arg(d), // result schema (synch. server -> us)
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [\"=0\"] }").arg(m) // out schema  (req. us -> server)
    )));
    rpcMethods[m]->setSelf(rpcMethods[m]);

    m = "server.version";
    rpcMethods.insert(m, QSharedPointer<RPC::Method>(new RPC::Method(
        m,
        RPC::Schema(), // in schema (asynch from server -> us) -- DISABLED for server.version
        RPC::schemaResult + QString(" { \"result\" : [\"=2\"] }"), // result schema (synch. server -> us)
        RPC::schemaMethod + QString(" { \"method\" : \"%1!\", \"params\" : [\"=2\"] }").arg(m) // out schema  (req. us -> server)
    )));
    rpcMethods[m]->setSelf(rpcMethods[m]);
}

void EXMgr::testCheckMethod(const QString &json) const
{
    try {
        const auto m = Util::Json::parseString(json, true).toMap();
        for (auto it = rpcMethods.cbegin(); it != rpcMethods.cend(); ++it) {
            QList<const RPC::Schema *> schemas({&(it.value()->inSchema), &(it.value()->resultSchema)});
            for (auto s : schemas) {
                if (!s->isValid())
                    // disabled schema
                    continue;
                QString err;
                if (auto res = s->match(m, &err); !res.isEmpty()) {
                    Debug() << "---> testCheckMethod on " << it.key() << ": parsed -> " << Util::Json::toString(res, true);
                } else {
                    Debug() << "---> testCheckMethod on " << it.key() << ": failed -> " << err;
                }
            }
        }
    } catch (const Exception &e) {
        Warning() << "testCheckMethod: " << e.what() << " (" << json << ")";
    }
}

QVariantMap EXMgr::testComposeRequest(qint64 id, const QString &method, const QVariantList &params) const
{
    QVariantMap ret;
    if (auto it = rpcMethods.find(method); it != rpcMethods.end()) {
        ret = it.value()->outSchema.toStrippedMap();
        ret["id"] = id;
        ret["params"] = params;
        if (QString err; ! (ret = it.value()->outSchema.match(ret, &err)).isEmpty()) {
            Debug() << method << " ---> compose --> matched, json = " << Util::Json::toString(ret, true);
            return ret;
        } else {
            Debug() << method << " ---> compose error: " << err;
        }
    }
    return ret;
}
