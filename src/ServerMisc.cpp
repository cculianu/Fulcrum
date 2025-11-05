#include "Common.h"
#include "ServerMisc.h"

namespace ServerMisc
{
    const QString AppVersion(VERSION);
    const QString AppSubVersion = QString("%1 %2").arg(APPNAME, VERSION);
}
