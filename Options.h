//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program (see LICENSE.txt).  If not, see
// <https://www.gnu.org/licenses/>.
//
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

    static constexpr unsigned minPollTimeSecs = 1, maxPollTimeSecs = 30, defaultPollTimeSecs = 5;
    /// bitcoin poll time interval. This value will always be in the range [minPollTimeSecs, maxPollTimeSecs] aka [1, 30]
    unsigned pollTimeSecs = defaultPollTimeSecs;
};

#endif // OPTIONS_H
