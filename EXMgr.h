#ifndef ECMGR_H
#define ECMGR_H

#include "Mgr.h"
#include "EXClient.h"
#include "RPC.h"
#include "BTC.h"
#include "Controller.h"
#include <QObject>
#include <QList>
#include <QSet>
#include <QMap>
#include <QPair>

class EXMgr : public Mgr
{
    Q_OBJECT
public:
    explicit EXMgr(const QString & serversFile, QObject *parent = nullptr);
    virtual ~EXMgr() override;

    void startup() override;
    void cleanup() override;

    inline qint64 newId() const { return IdMixin::newId(); } /// alias for app()->newId()

    /// Picks a client that is up-to-date in a random fashion. Subsequent
    /// calls to this function will return a new EXClient each time until the
    /// list has been exhausted, at which point the randome selection
    /// starts again.  May return nullptr if no EXClients are up-to-date.
    /// Should be called from the main thread only, otherwise an Exception will
    /// be thrown.
    EXClient *pick();


    const RPC::MethodMap & rpcMethods() const { return _rpcMethods; }

signals:
    /// Call (emit) these signals from outside this class in any thread to enqueue a request to this class
    /// in its thread.  (These "signal()" correspond to "_signal()" private slots in this class)
    void listUnspent(const BTC::Address &);

    /// -

    /// Emitted by this class when listunspent results become available from one of the EX servers.
    void gotListUnspentResults(const AddressUnspentEntry &);
    /// Emitted by class when a new server height is first seen
    void gotNewBlockHeight(int height);

public slots:

protected slots:
    void onNewConnection(EXClient *);
    void onLostConnection(EXClient *);
    void onMessage(EXClient *, const RPC::Message &);
    void onErrorMessage(EXClient *, const RPC::Message &);

private slots:
    void checkClients();

    /// connected to listUnspent above, runs in our thread
    void _listUnspent(const BTC::Address &);

private:
    const QString serversFile;
    void loadServers(); // may throw
    void initRPCMethods(); // may throw

    QList<EXClient *> clients;
    QMap<qint64, EXClient *> clientsById; ///< note to self: always maintain this map to be synched to above list

    QTimer *checkClientsTimer = nullptr;

    QSet<qint64> recentPicks;

    struct Height {
        int height = 0;  ///< the largest height seen
        QString header; ///< the block header of height
        qint64 ts = 0; ///< the ts of height, when first seen
        QSet<qint64> seenBy; ///< the server ids reporting this latest height
    };
    Height height;

    void pickTest();

    RPC::MethodMap _rpcMethods;

    /// listunspent handling...
    struct PendingLUSReq {
        BTC::Address address;
        qint64 clientId = NO_ID; // EXClient *-> id
        qint64 ts = 0; // timestamp sent from Util::getTime()
        bool isValid() const { return clientId > NO_ID && ts > 0 && address.isValid(); }
    };
    /// map of message.id -> PendingLUSReq struct
    QMap<qint64, PendingLUSReq> pendingListUnspentReqs;
    void processListUnspentResults(EXClient *, const RPC::Message &m);
    /// /end listunspent handling.
};

#endif // ECMGR_H
