#include "Common.h"
#include "ServerMisc.h"

namespace ServerMisc
{
    const Version MinProtocolVersion(1,4,0);
    const Version MaxProtocolVersion(1,5,0);
    const Version MinTokenAwareProtocolVersion(1,5,0);
    const QString AppVersion(VERSION);
    const QString AppSubVersion = QString("%1 %2").arg(APPNAME, VERSION);
}
