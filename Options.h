#ifndef OPTIONS_H
#define OPTIONS_H

#include <atomic>
#include <QPair>
#include <QHostAddress>
#include <QString>
#include <QList>

struct Options {
    static constexpr quint16 DEFAULT_PORT = 50001;

    std::atomic_bool verboseDebug =
#ifdef QT_DEBUG
        true; ///< gets set to true on debug builds
#else
        false; ///< gets set to false on release builds
#endif
    std::atomic_bool verboseTrace = false; ///< this gets set if -d -d specified
    std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

    using Interface = QPair<QHostAddress, quint16>;
    QList<Interface> interfaces; ///< interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT
    QList<Interface> statsInterfaces; ///< ditto for 'stats' server, defaults empty (no stats server)
    Interface bitcoind;
    QString rpcuser, rpcpassword;
};

#endif // OPTIONS_H
