#include "Controller.h"

Controller::Controller()
{

}

Controller::~Controller()
{

}

QObject *Controller::qobj() { return this; }


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
        ts.flush();
    }
    return ret;
}
