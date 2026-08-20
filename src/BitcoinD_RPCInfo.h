//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2026 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <QList>
#include <QPair>
#include <QSslCertificate>
#include <QSslKey>
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

    /// Optional authentication settings for the TLS connection to the remote bitcoind (aka "mTLS"). These are only
    /// ever consulted if `tls` above is true.  Note that `tls` by itself only encrypts the connection; it does not
    /// authenticate either end of it.  The settings below add that authentication.
    struct TlsInfo {
        /// CLI: --bitcoind-tls-verify.  If true, verify the certificate presented by the remote bitcoind.  The default
        /// (false) preserves the historical behavior of accepting any certificate whatsoever.
        bool verify = false;
        /// CLI: --bitcoind-tls-ca.  The CA certificate(s) to trust when `verify` is true.  If empty, the system CA
        /// store is used instead.
        QList<QSslCertificate> caCerts;
        /// CLI: --bitcoind-tls-hostname.  The name we require to appear in the remote bitcoind's certificate (CN or
        /// SAN).  If empty, the host portion of --bitcoind is used.  Only used if `verify` is true.
        QString peerVerifyName;
        /// CLI: --bitcoind-tls-cert.  The client certificate chain we present to the remote bitcoind.  Either empty
        /// (present no client certificate), or 1 or more certificates (leaf first).
        QList<QSslCertificate> certChain;
        /// CLI: --bitcoind-tls-key.  The private key that goes with `certChain`.
        QSslKey key;
        /// The file names as specified by the user; saved here for Options::toMap() and for log messages.
        QString caFile, certFile, keyFile;

        /// True iff the user configured a client certificate for us to present to the remote bitcoind.
        bool hasClientCert() const { return !certChain.isEmpty() && !key.isNull(); }
    };
    TlsInfo tlsInfo;

    /// Reads the files specified by --bitcoind-tls-cert, --bitcoind-tls-key and --bitcoind-tls-ca into `tlsInfo`,
    /// leaving alone any of the three whose file name is empty.  Throws BadArgs if a file cannot be read, cannot be
    /// parsed as PEM, or if the cert and key are obviously mismatched.
    void setTlsFiles(const QString &certFile, const QString &keyFile, const QString &caFile);

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
