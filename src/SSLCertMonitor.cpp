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
#include "SSLCertMonitor.h"
#include "Util.h"

#include <QFile>
#include <QFileSystemWatcher>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslEllipticCurve>
#include <QSslSocket>

#include <algorithm>
#include <set>
#include <utility>

SSLCertMonitor::SSLCertMonitor(std::shared_ptr<Options> options_, QObject *parent)
    : QObject(parent), options(std::move(options_)), watcher(new QFileSystemWatcher(this))
{
    setObjectName("SSLCertMonitor");
    connect(watcher, &QFileSystemWatcher::fileChanged, this, &SSLCertMonitor::on_fileChanged);
}

void SSLCertMonitor::start(const QString &certFile, const QString &keyFile,
                           const QString &wssCertFile, const QString &wssKeyFile)
{
    cert = certFile;
    key = keyFile;
    wssCert = wssCertFile;
    wssKey = wssKeyFile;

    if (cert.isEmpty() && !wssCert.isEmpty()) {
        // copy over wssCert/wssKey to cert/key, clear wssCert/wssKey
        cert = wssCert;  wssCert.clear();
        key  = wssKey;   wssKey.clear();
    }
    // sanity check
    if (cert.isEmpty() || key.isEmpty()) throw InternalError("Internal Error: cert and/or key is empty");

    // may throw on error
    options->certs.store(readCerts());

    // re-initialize the watcher
    watchedFiles.clear();
    for (const auto &f : watcher->files()) watcher->removePath(f);
    watcher->addPath(cert);
    watchedFiles.append(cert);
    if (!wssCert.isEmpty() && !watcher->files().contains(wssCert)) {
        watcher->addPath(wssCert);
        watchedFiles.append(wssCert);
    }
    Util::AsyncOnObject(this, [this]{
        DebugM("SSLCertMonitor: Watching files [", watchedFiles.join(", "), "]");
    });
}

bool SSLCertMonitor::watcherWatchedFilesMismatch() const
{
    return Util::toCont<std::set<QString>>(watchedFiles) != Util::toCont<std::set<QString>>(watcher->files());
}

void SSLCertMonitor::on_fileChanged(const QString &path)
{
    DebugM("SSLCertMonitor: Watched file ", path, " changed on disk, enqueing readCerts in 1 second");
    callOnTimerSoon(1000 /* msec */, "readCertsSoon", [this]{
        DebugM("SSLCertMonitor: readCerts ...");
        if (watcherWatchedFilesMismatch() || !std::all_of(watchedFiles.begin(), watchedFiles.end(),
                                                          [](const auto &f){ return QFile::exists(f); })) {
            // a file may have been deleted, keep polling for it to appear
            DebugM("SSLCertMonitor: A watched file may have been deleted, trying again in 1 second ...");
            callOnTimerSoon(1000 /* msec */, "waitForDeletedToShowUp", [this, ct=0]() mutable {
                ++ct;
                QString changed, missing;
                for (const auto &f : watchedFiles) {
                    const bool watched = watcher->files().contains(f);
                    const bool exists = QFile::exists(f);
                    if (exists && !watched) {
                        watcher->addPath(changed = f);
                        DebugM("SSLCertMonitor: Watched file ", f, " is back!");
                    } else if (!exists && watched) {
                        watcher->removePath(changed = f);
                        DebugM("SSLCertMonitor: Watched file ", f, " is gone!");
                    }
                    if (!exists) missing = f;
                }

                // keep repeating until we get a result..
                const bool keepTrying = watcherWatchedFilesMismatch();
                if (!keepTrying) {
                    DebugM("SSLCertMonitor: Deleted file reappeared, re-enqueuing on_fileChanged");
                    // re-enqueue this function to propagate changes to observers
                    on_fileChanged(changed);
                } else {
                    const QString msg = QString("SSLCertMonitor: Deleted file '%1' still not there, trying again in"
                                                " 1 second ...").arg(missing);

                    if (ct % 10 == 0 && !missing.isEmpty()) Warning() << msg;
                    else Debug() << msg;
                }

                return keepTrying;
            });

            // bail early and wait for above timer to complete
            return false;
        }

        try {
            // this re-reads all the certs, if it doesn't throw they were read and stored successfully
            start(cert, key, wssCert, wssKey);
            emit certInfoChanged();
            return false; // don't keep trying, done
        } catch (const InternalError &e) {
            Fatal() << "SSLCertMonitor: Caught exception: " << e.what();
        } catch (const std::exception &e) {
            Warning() << "SSLCertMonitor: Failed to read changed certificate files from disk. Error was: " << e.what();
        }
        return true; // keep trying, caught exception above
    }, true /* force timer restart */);
}

Options::Certs SSLCertMonitor::readCerts() const
{
    Options::Certs certs;
    // the below always either returns a good CertInfo object, or throws on error
    certs.certInfo = SSLCertMonitor::makeCertInfo(this, cert, key);
    if (!wssCert.isEmpty()) {
        if (wssKey.isEmpty()) throw InternalError("Internal Error: wss-key is empty"); // sanity check
        certs.wssCertInfo = SSLCertMonitor::makeCertInfo(this, wssCert, wssKey);
    }
    return certs;
}

/*static*/
Options::CertInfo SSLCertMonitor::makeCertInfo(const QObject *context, const QString &cert, const QString &key)
{
    Options::CertInfo ret;

    if (!context)
        throw InternalError("`context` may not be nullptr! FIXME!");
    if (!QFile::exists(cert))
        throw BadArgs(QString("Cert file not found: %1").arg(cert));
    if (!QFile::exists(key))
        throw BadArgs(QString("Key file not found: %1").arg(key));

    QFile certf(cert), keyf(key);
    if (!certf.open(QIODevice::ReadOnly))
        throw BadArgs(QString("Unable to open cert file %1: %2").arg(cert, certf.errorString()));
    if (!keyf.open(QIODevice::ReadOnly))
        throw BadArgs(QString("Unable to open key file %1: %2").arg(key, keyf.errorString()));

    ret.cert = QSslCertificate(&certf, QSsl::EncodingFormat::Pem);
    // proble key algorithm by trying all the algorithms Qt supports
    for (auto algo : {QSsl::KeyAlgorithm::Rsa, QSsl::KeyAlgorithm::Ec, QSsl::KeyAlgorithm::Dsa,
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
         // This was added in Qt 5.13+
         QSsl::KeyAlgorithm::Dh,
#endif
                     }) {
        keyf.seek(0);
        ret.key = QSslKey(&keyf, algo, QSsl::EncodingFormat::Pem);
        if (!ret.key.isNull())
            break;
    }
    // check key is ok
    if (ret.key.isNull()) {
        throw BadArgs(QString("Unable to read private key from %1. Please make sure the file is readable and "
                              "contains an RSA, DSA, EC, or DH private key in PEM format.").arg(key));
    } else if (ret.key.algorithm() == QSsl::KeyAlgorithm::Ec && QSslConfiguration::supportedEllipticCurves().isEmpty()) {
        throw BadArgs(QString("Private key `%1` is an elliptic curve key, however this Qt installation lacks"
                              " elliptic curve support. Please recompile and link Qt against the OpenSSL library"
                              " in order to enable elliptic curve support in Qt.").arg(key));
    }
    ret.file = cert; // this is only used for /stats port advisory info
    ret.keyFile = key; // this is only used for /stats port advisory info
    if (ret.cert.isNull())
        throw BadArgs(QString("Unable to read ssl certificate from %1. Please make sure the file is readable and "
                              "contains a valid certificate in PEM format.").arg(cert));
    else {
        if (!ret.cert.isSelfSigned()) {
            certf.seek(0);
            ret.certChain = QSslCertificate::fromDevice(&certf, QSsl::EncodingFormat::Pem);
            if (ret.certChain.size() < 2)
                throw BadArgs(QString("File '%1' does not appear to be a full certificate chain.\n"
                                      "Please make sure your CA signed certificate is the fullchain.pem file.")
                              .arg(cert));
        }
        Util::AsyncOnObject(context, [ret]{
            // We do this logging later. This is to ensure that it ends up in the syslog if user specified -S
            QString name;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
            // Was added Qt 5.12+
            name = ret.cert.subjectDisplayName();
#else
            name = ret.cert.subjectInfo(QSslCertificate::Organization).join(", ");
#endif
            Log() << "Loaded SSL certificate: " << name << " "
                  << ret.cert.subjectInfo(QSslCertificate::SubjectInfo::EmailAddress).join(",")
                  //<< " self-signed: " << (options->sslCert.isSelfSigned() ? "YES" : "NO")
                  << " expires: " << (ret.cert.expiryDate().toString("ddd MMMM d yyyy hh:mm:ss"));
            if (Debug::isEnabled()) {
                QString cipherStr;
                for (const auto & ciph : QSslConfiguration::supportedCiphers()) {
                    if (!cipherStr.isEmpty()) cipherStr += ", ";
                    cipherStr += ciph.name();
                }
                if (cipherStr.isEmpty()) cipherStr = "(None)";
                Debug() << "Supported ciphers: " << cipherStr;
                QString curvesStr;
                for (const auto & curve : QSslConfiguration::supportedEllipticCurves()) {
                    if (!curvesStr.isEmpty()) curvesStr += ", ";
                    curvesStr += curve.longName();
                }
                if (curvesStr.isEmpty()) curvesStr = "(None)";
                Debug() << "Supported curves: " << curvesStr;
            }
        });
    }
    static const auto KeyAlgoStr = [](QSsl::KeyAlgorithm a) {
        switch (a) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
        // This was added in Qt 5.13+
        case QSsl::KeyAlgorithm::Dh: return "DH";
#endif
        case QSsl::KeyAlgorithm::Ec: return "EC";
        case QSsl::KeyAlgorithm::Dsa: return "DSA";
        case QSsl::KeyAlgorithm::Rsa: return "RSA";
        default: return "Other";
        }
    };
    Util::AsyncOnObject(context, [ret]{
        // We do this logging later. This is to ensure that it ends up in the syslog if user specified -S
        const auto algo = ret.key.algorithm();
        const auto algoName = KeyAlgoStr(algo);
        const auto keyTypeName = (ret.key.type() == QSsl::KeyType::PrivateKey ? "private" : "public");
        Log() << "Loaded key type: " << keyTypeName << " algorithm: " << algoName;
        if (algo != QSsl::KeyAlgorithm::Rsa)
            Warning() << "Warning: " << algoName << " key support is experimental."
                      << " Please consider switching your SSL certificate and key to use 2048-bit RSA.";
    });

    return ret;
}
