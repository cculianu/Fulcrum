#ifndef OPTIONS_H
#define OPTIONS_H

#include <atomic>
#include <QPair>
#include <QHostAddress>
#include <QString>
#include <QList>

struct Options {
    static const quint16 DEFAULT_PORT = 2641;

    std::atomic_bool verboseDebug =
#ifdef QT_DEBUG
        true; ///< gets set to true on debug builds
#else
        false; ///< gets set to false on release builds
#endif
    std::atomic_bool syslogMode = false; ///< if true, suppress printing of timestamps to logger

    typedef QPair<QHostAddress, quint16> Interface;
    QList<Interface> interfaces; ///< interfaces to use for binding, defaults to 0.0.0.0 DEFAULT_PORT
    QString serversFile = ":/file/servers.json";
};

#endif // OPTIONS_H
