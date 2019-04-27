#ifndef ECMGR_H
#define ECMGR_H

#include "Mgr.h"
#include "EXClient.h"
#include <QObject>
#include <QList>
#include <QSet>
#include <atomic>
class EXClient;

class EXMgr : public Mgr
{
    Q_OBJECT
public:
    explicit EXMgr(const QString & serversFile, QObject *parent = nullptr);
    virtual ~EXMgr() override;

    void startup() override;
    void cleanup() override;

    qint64 newId() { return ++curid; }

    /// Picks a client that is up-to-date in a random fashion. Subsequent
    /// calls to this function will return a new EXClient each time until the
    /// list has been exhausted, at which point the randome selection
    /// starts again.  May return nullptr if no EXClients are up-to-date.
    /// Should be called from the main thread only, otherwise an Exception will
    /// be thrown.
    EXClient *pick();

signals:

public slots:

protected slots:
    void onNewConnection(EXClient *);
    void onLostConnection(EXClient *);
    void onResponse(EXClient *, EXResponse);

private slots:
    void checkClients();

private:
    const QString serversFile;
    void loadServers();
    std::atomic<qint64> curid = 0;

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

};

#endif // ECMGR_H
