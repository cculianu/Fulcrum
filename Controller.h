#ifndef CCCONTROLLER_H
#define CCCONTROLLER_H

#include "BTC.h"
#include "Mixins.h"
#include "Mgr.h"

#include <QObject>
#include <QMap>
#include <QSet>
#include <QMetaType>
#include <algorithm>

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

// see register_MetaTypes.cpp for run-time registration with metatype system.
Q_DECLARE_METATYPE(AddressUnspentEntry);


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
                && std::all_of(amounts.begin(), amounts.end(), [](quint64 amt) -> bool { return amt > 0; })
                && !addrUtxo.isEmpty() && shuffleAddr.isValid() && changeAddr.isValid()
                && shuffleAddr != changeAddr && !addrUtxo.contains(shuffleAddr);
    }
};

// see register_MetaTypes.cpp for run-time registration with metatype system.
Q_DECLARE_METATYPE(ShuffleSpec);


struct ClientStateException : public Exception
{ using Exception::Exception; ~ClientStateException() override; };

/// Client state managed by the controller, stored in controller's clientStates map
struct ClientState
{
    qint64 clientId = NO_ID; // redundant. this field also exists in .spec ..
    ShuffleSpec spec;
    // handle to server -- assumption is all TcpServer objects live for lifetime of the Controller
    TcpServer *server = nullptr;
    enum SpecState {
        None = 0, Pending, InProcess, Rejected, Accepted
    };
    SpecState specState = None;

    // possibly more here...

    // throws ClientStateException on error
    inline void gotNewSpec(TcpServer *srv, const ShuffleSpec & sp)
    {
        if (!srv)
            throw ClientStateException(QString("TcpServer is null! (clientId: %1)").arg(sp.clientId));
        if (!sp.isValid())
            throw ClientStateException(QString("Bad or invalid spec: %1").arg(sp.toDebugString()));
        server = srv;
        spec = sp; // copy is cheap (copy-on-write for Qt containers)
        clientId = sp.clientId;
        specState = Pending;
    }
};



class Controller : public Mgr, public ThreadObjectMixin, protected TimersByNameMixin
{
    Q_OBJECT
public:
    Controller(SrvMgr *srvMgr, EXMgr *exMgr);
    ~Controller() override;

    void startup() override; // from Mgr
    void cleanup() override; // from Mgr

protected:
    virtual QObject *qobj() override; // from ThreadObjectMixin & TimersByNameMixin
    virtual void on_started() override; // from ThreadObjectMixin
    virtual void on_finished() override; // from ThreadObjectMixin

private slots:
    // NB: assumption is TcpServer lives for lifetime of this object. If this invariant changes,  please update this code.
    void onNewTcpServer(TcpServer *);
    void onClientDisconnected(qint64 clientId);
    void onNewShuffleSpec(const ShuffleSpec &);
    // connected by us to exMgr's "gotListUnspentResults" signal. Again, assumption is exMgr lives for lifetime of this object
    void onListUnspentResults(const AddressUnspentEntry &);
    // connected by us to exMgr's "gotNewBlockHeight" signal.
    void onNewBlockHeight(int);
private:
    SrvMgr *srvMgr = nullptr;
    EXMgr *exMgr = nullptr;
    QMap<BTC::Address, AddressUnspentEntry> addressUnspentCache;
    QMap<qint64, ClientState> clientStates; ///< map of client ids to ClientState
    QSet<BTC::Address> pendingAddressLookups;

    int removeClientFromAllUnspentCache(qint64 clientId);
    void refClientToAllUnspentCache(const ShuffleSpec &spec);
    void lookupAddresses(const QSet<BTC::Address> &);

    QSet<BTC::Address> analyzeShuffleSpec(const ShuffleSpec &) const; // may throw Exception on rejection of spec
};


#endif // CCCONTROLLER_H
