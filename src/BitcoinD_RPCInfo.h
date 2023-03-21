//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
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
#pragma once

#include <QPair>
#include <QString>

/// Encapsulates all the info one needs to connect to the remote bitcoind RPC
/// server.
class BitcoinD_RPCInfo {
    /// Location in datadir of the cookie file: Iff not empty, this file will be read each time to get the user:pass,
    /// otherwise if empty, this->user and this->pass will be used
    QString cookieFile;
    /// Iff above is empty, use user:pass for HTTP basic auth
    QString user, pass;

public:
    /// hostname, port pair. We resolve bitcoind's actual IP address each time if it's a hostname and not an IP address string.
    QPair<QString, quint16> hostPort;
    /// CLI: --bitcoind-tls. If true, we will connect to the remote bitcoind via SSL/TLS. See BitcoinD.cpp.
    bool tls = false;

    /// Throws an BadArgs if file is the empty string, otherwise always succeeds
    void setCookieFile(const QString &file);
    QString getCookieFile() const { return cookieFile; }
    bool hasCookieFile() const { return !cookieFile.isEmpty(); }

    /// Sets this instance to use a cached user:pass; clears the cookieFile as a side-effect
    void setStaticUserPass(const QString &user, const QString &pass);

    /// If this->cookieFile is empty, uses the static user:pass. If it is not, parses the cookie file each time it is
    /// called.  Returns a pair of empty strings if the cookieFile cannot be read (and also logs a warning).
    QPair<QString, QString> getUserPass() const;
};
