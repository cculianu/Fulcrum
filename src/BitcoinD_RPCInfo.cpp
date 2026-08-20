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

#include "BitcoinD_RPCInfo.h"
#include "Common.h"
#include "Util.h"

#include <QByteArray>
#include <QFile>
#include <QSslConfiguration>
#include <QSslEllipticCurve>

#include <cctype> // for std::isspace
#include <tuple>  // for std::tie

namespace {
    /// Opens `fileName` readonly, throwing BadArgs on failure. `what` is used in the error message, e.g. "cert".
    void OpenPemFileOrThrow(QFile &f, const QString &fileName, const char *what)
    {
        f.setFileName(fileName);
        if (!f.exists())
            throw BadArgs(QString("BitcoinD TLS %1 file not found: %2").arg(what, fileName));
        if (!f.open(QIODevice::ReadOnly))
            throw BadArgs(QString("Unable to open BitcoinD TLS %1 file %2: %3").arg(what, fileName, f.errorString()));
    }

    /// Reads a private key in PEM format from `f`, probing each key algorithm Qt supports (Qt offers no way to ask
    /// what algorithm a PEM file holds).  Returns a null QSslKey if no algorithm yielded a key.
    QSslKey ReadPrivateKeyPem(QFile &f)
    {
        QSslKey ret;
        for (auto algo : {QSsl::KeyAlgorithm::Rsa, QSsl::KeyAlgorithm::Ec, QSsl::KeyAlgorithm::Dsa,
                          QSsl::KeyAlgorithm::Dh}) {
            f.seek(0);
            ret = QSslKey(&f, algo, QSsl::EncodingFormat::Pem);
            if (!ret.isNull())
                break;
        }
        return ret;
    }
}

void BitcoinD_RPCInfo::setTlsFiles(const QString &certFile, const QString &keyFile, const QString &caFile)
{
    if (!caFile.isEmpty()) {
        QFile f;
        OpenPemFileOrThrow(f, caFile, "CA");
        tlsInfo.caCerts = QSslCertificate::fromDevice(&f, QSsl::EncodingFormat::Pem);
        if (tlsInfo.caCerts.isEmpty())
            throw BadArgs(QString("Unable to read any certificates from BitcoinD TLS CA file %1. Please make sure it"
                                  " contains one or more CA certificates in PEM format.").arg(caFile));
        tlsInfo.caFile = caFile;
    }

    if (certFile.isEmpty())
        return; // no client certificate configured; nothing further to do

    {
        QFile f;
        OpenPemFileOrThrow(f, certFile, "cert");
        // Unlike the server-side cert (see SSLCertMonitor.cpp), a client cert need not be a full chain -- the remote
        // end already has the CA -- so we accept either a single leaf cert or a leaf-first chain here.
        tlsInfo.certChain = QSslCertificate::fromDevice(&f, QSsl::EncodingFormat::Pem);
        if (tlsInfo.certChain.isEmpty())
            throw BadArgs(QString("Unable to read a certificate from BitcoinD TLS cert file %1. Please make sure it"
                                  " contains a valid certificate in PEM format.").arg(certFile));
        tlsInfo.certFile = certFile;
    }

    {
        QFile f;
        OpenPemFileOrThrow(f, keyFile, "key");
        tlsInfo.key = ReadPrivateKeyPem(f);
        if (tlsInfo.key.isNull())
            throw BadArgs(QString("Unable to read a private key from BitcoinD TLS key file %1. Please make sure it"
                                  " contains an unencrypted RSA, DSA, EC, or DH private key in PEM format"
                                  " (passphrase-protected keys are not supported).").arg(keyFile));
        if (tlsInfo.key.algorithm() == QSsl::KeyAlgorithm::Ec && QSslConfiguration::supportedEllipticCurves().isEmpty())
            throw BadArgs(QString("BitcoinD TLS key `%1` is an elliptic curve key, however this Qt installation lacks"
                                  " elliptic curve support. Please recompile and link Qt against the OpenSSL library"
                                  " in order to enable elliptic curve support in Qt.").arg(keyFile));
        tlsInfo.keyFile = keyFile;
    }

    // Sanity check that the key actually goes with the cert. Qt offers no way to definitively verify this (it cannot
    // derive a public key from a private one), so we compare what we can; a subtler mismatch will show up as a TLS
    // handshake failure at connect time.
    if (const auto pub = tlsInfo.certChain.front().publicKey(); !pub.isNull()) {
        const bool algoMismatch = pub.algorithm() != tlsInfo.key.algorithm();
        // only compare lengths if Qt gave us a length for both keys
        const bool lengthMismatch = pub.length() > 0 && tlsInfo.key.length() > 0
                                    && pub.length() != tlsInfo.key.length();
        if (algoMismatch || lengthMismatch)
            throw BadArgs(QString("BitcoinD TLS key %1 does not match cert %2 (the certificate's public key and the"
                                  " private key differ in algorithm and/or key length).").arg(keyFile, certFile));
    }
}

void BitcoinD_RPCInfo::setCookieFile(const QString &file)
{
    if (file.isEmpty()) throw BadArgs("BitcoinD cookie file cannot be the empty string");
    user.clear(), pass.clear();
    cookieFile = file;
}

void BitcoinD_RPCInfo::setStaticUserPass(const QString &u, const QString &p)
{
    cookieFile.clear();
    std::tie(user, pass) = std::tie(u, p);
}

QPair<QString, QString> BitcoinD_RPCInfo::getUserPass() const
{
    QPair<QString, QString> ret;

    if (!hasCookieFile()) {
        // static user/pass (e.g. rpcuser= rpcpassword= was specified in conf file)
        std::tie(ret.first, ret.second) = std::tie(user, pass);
        return ret;
    }

    // otherwise, user specified a cookie file -- read the cookie file..

    QFile f(cookieFile);
    if (!f.open(QIODevice::ReadOnly)) {
        Warning() << "Unable to open cookie file '" << cookieFile << "': " << f.errorString();
        return ret;
    }

    QByteArray line = f.readLine();
    f.close();
    // trim trailing whitespace, newlines, etc
    while (!line.isEmpty() && (std::isspace(char(line.back())) || char(line.back()) == '\0')) {
        line.resize(line.size() - 1);
    }

    const int colon = line.indexOf(':');
    if (colon < 0) {
        Warning() << "Cookie file '" << cookieFile << "' "
                  << "does not appear to be a valid bitcoind cookie file (missing ':' character)";
        return ret;
    }

    // extract user:pass
    ret.first = QString::fromUtf8(line.left(colon));
    ret.second = QString::fromUtf8(line.mid(colon+1));

    return ret;
}
