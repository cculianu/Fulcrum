#include "Controller.h"
#include "SrvMgr.h"
#include "EXMgr.h"

Controller::Controller(SrvMgr *srv, EXMgr *ex)
    : Mgr(nullptr/* top-level because thread*/), srvMgr(srv), exMgr(ex)
{
    setObjectName("Controller");
    _thread.setObjectName(objectName());
}

Controller::~Controller()
{
    cleanup();
}

void Controller::cleanup()
{
    stop(); // no-op if not running
}

void Controller::startup()
{
    start(); // start thread
    if (chan.get<QString>(10000).isEmpty())
        throw Exception("Controller startup timed out after 10 seconds");
}

QObject *Controller::qobj() { return this; }

void Controller::on_started()
{
    ThreadObjectMixin::on_started();
    Log() << objectName() << " started";
    chan.put("ok");
}

void Controller::on_finished()
{
    ThreadObjectMixin::on_finished();
    Debug() << objectName() << " finished.";
}

QString ShuffleSpec::toDebugString() const
{
    QString ret;
    {
        QTextStream ts(&ret);

        ts << "(Shuffle Spec; clientId: " << clientId << "; refId: " << refId << "; <amounts: ";
        for (const auto amt : amounts)
            ts << amt << ", ";
        ts << ">; shuffleAddr: " << shuffleAddr.toString() << "; changeAddr: " << changeAddr.toString();
        ts << "; <utxos: ";
        for (auto it = addrUtxo.begin(); it != addrUtxo.end(); ++it) {
            for (const auto & utxo : it.value()) {
                ts << it.key().toString() << "/" << utxo.toString() << ", ";
            }
        }
        ts << ">)";
    }
    return ret;
}

QString AddressUnspentEntry::toDebugString() const
{
    QString ret;
    {
        QTextStream ts(&ret);
        ts << "(AddressUnspentEntry; address: " << address.toString() << "; heightVerified: " << heightVerified << "; tsVerified: " << tsVerified
           << "; <clients: ";
        for (const auto c : clientSet) {
            ts << c << ", ";
        }
        ts << ">; <UTXO Amounts: ";
        for (auto it = utxoAmounts.begin(); it != utxoAmounts.end(); ++it) {
            ts << it.key().toString() << "=" << it.value() << " sats, ";
        }
        ts << ">; <UTXO Unconf. Amounts: ";
        for (auto it = utxoUnconfAmounts.begin(); it != utxoUnconfAmounts.end(); ++it) {
            ts << it.key().toString() << "=" << it.value() << " sats, ";
        }
        ts << ">)";
    }
    return ret;
}
