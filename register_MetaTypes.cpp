
#include "App.h"
#include "RPC.h"
#include "BTC.h"
#include <QMetaType>

void App::register_MetaTypes()
{
    static bool registered = false;

    if (!registered) {
        // finish registering RPC::Message metatype so that signals/slots work. This needs to only happen
        // once in main thread at app init.
        qRegisterMetaType<RPC::Message>();
        qRegisterMetaType<RPC::Message::Id>("RPC::Message::Id"); // for some reason when this is an alias for QVariant it needs this string here
        // ditto for BTC::Address
        qRegisterMetaType<BTC::Address>();

        registered = true;
    }
}
