
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
#if CLANG_11
        qRegisterMetaType<RPC::Message::Id>();
#endif
        // ditto for BTC::Address
        qRegisterMetaType<BTC::Address>();

        registered = true;
    }
}
