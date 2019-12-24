#ifndef OPTIONS_H
#define OPTIONS_H

#include <QHostAddress>
#include <QList>
#include <QPair>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>

#include <atomic>
#include <tuple>

struct Options {
    static constexpr quint16 DEFAULT_PORT_TCP = 50001, DEFAULT_PORT_SSL = 50002;

    std::atomic_bool verboseDebug =
#ifdef QT_DEBUG
        true; ///< gets set to true on debug builds
#else
        false; ///< gets set to false on release builds
#endif
    std::atomic_bool verboseTrace = false; ///< this gets set if -d -d specified
    std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

    using Interface = QPair<QHostAddress, quint16>;
    QList<Interface> interfaces, ///< TCP interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT_TCP
                     sslInterfaces;  ///< SSL interfaces to use for binding SSL ports. Defaults to nothing.
    QList<Interface> statsInterfaces; ///< 'stats' server, defaults to empty (no stats server)
    QSslCertificate sslCert; ///< this must be valid if we have any SSL interfaces.
    QSslKey sslKey; ///< this must be valid if we have any SSL interfaces.
    Interface bitcoind;
    QString rpcuser, rpcpassword;
    QString datadir; ///< The directory to store the database. It exists and has appropriate permissions (otherwise the app would have quit on startup).
    /// If true, on db open/startup, we will perform some slow/paranoid db consistency checks
    bool doSlowDbChecks = false;
};

#endif // OPTIONS_H
