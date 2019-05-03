#ifndef CCCONTROLLER_H
#define CCCONTROLLER_H

#include "BTC.h"
#include "Mixins.h"

#include <QObject>
#include <QMap>
#include <QSet>
#include <QMetaType>


struct AddressUnspentEntry
{
    BTC::Address address;
    QMap<BTC::UTXO, quint64> utxoAmounts;
    QSet<qint64> clientSet; ///< basically of reference counts of client ids that refer to this entry. as clients die, they get removed from this set
    int heightVerified = 0;
    qint64 tsVerified = 0;
};

Q_DECLARE_METATYPE(AddressUnspentEntry);

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
           refId = NO_ID; ///< id passed in to the method request
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

class Controller : public QObject, public ThreadObjectMixin
{
    Q_OBJECT
public:
    Controller();
    ~Controller() override;

protected:
    virtual QObject *qobj() override;

private:
    QMap<BTC::Address, AddressUnspentEntry> addessUnspentCache;
};


#endif // CCCONTROLLER_H
