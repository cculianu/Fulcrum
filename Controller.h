#ifndef CCCONTROLLER_H
#define CCCONTROLLER_H

#include "BTC.h"
#include "Mixins.h"
#include "Mgr.h"

#include <QObject>
#include <QMap>
#include <QSet>
#include <QMetaType>

class SrvMgr;
class EXMgr;
class TcpServer;

struct AddressUnspentEntry
{
    BTC::Address address;
    QMap<BTC::UTXO, quint64> utxoAmounts, utxoUnconfAmounts;
    QSet<qint64> clientSet; ///< basically of reference counts of client ids that refer to this entry. as clients die, they get removed from this set
    int heightVerified = 0;
    qint64 tsVerified = 0;

    QString toDebugString() const;
};

Q_DECLARE_METATYPE(AddressUnspentEntry); // see register_MetaTypes.cpp for run-time registration with metatype system.

/*
struct ClientDesc
{
    qint64 clientId = -1;
    QSet<quint64> amountsReq; /// shuffle output amounts requested
    BTC::Address shuffleAddr, changeAddr;
    QMap<BTC::Address, QMap<BTC::UTXO, quint64> > addrUtxoAmts;
};
*/

struct ShuffleSpec
{
    qint64 clientId = NO_ID, ///< id of the Client * object asking for this spec
           refId = NO_ID; ///< id passed in to the method request from remote client
    QSet<quint64> amounts; /// shuffle output amounts requested in satoshis
    BTC::Address shuffleAddr, changeAddr;
    QMap<BTC::Address, QSet<BTC::UTXO> > addrUtxo;

    QString toDebugString() const;
    void clear() { clientId = refId = NO_ID; amounts.clear(); shuffleAddr = changeAddr = BTC::Address(); addrUtxo.clear(); }
    bool isValid() const {
        return clientId > NO_ID && refId > NO_ID && !amounts.isEmpty()
                && !addrUtxo.isEmpty() && shuffleAddr.isValid() && changeAddr.isValid()
                && shuffleAddr != changeAddr;
    }
};

Q_DECLARE_METATYPE(ShuffleSpec);

class Controller : public Mgr, public ThreadObjectMixin
{
    Q_OBJECT
public:
    Controller(SrvMgr *srvMgr, EXMgr *exMgr);
    ~Controller() override;

    void startup() override; // from Mgr
    void cleanup() override; // from Mgr

protected:
    virtual QObject *qobj() override; // from ThreadObjectMixin
    virtual void on_started() override; // from ThreadObjectMixin
    virtual void on_finished() override; // from ThreadObjectMixin

private slots:
    // NB: assumption is TcpServer lives for lifetime of this object. If this invariant changes,  please update this code.
    void onNewTcpServer(TcpServer *);
    void onClientDisconnected(qint64 clientId);
    void onNewShuffleSpec(const ShuffleSpec &);
private:
    SrvMgr *srvMgr = nullptr;
    EXMgr *exMgr = nullptr;
    QMap<BTC::Address, AddressUnspentEntry> addessUnspentCache;
    QMap<qint64, TcpServer *> clientIdToServerMap; ///< advisory map of client ids to servers
};


#endif // CCCONTROLLER_H
