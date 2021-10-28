//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2021  Calin A. Culianu <calin.culianu@gmail.com>
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

#include "Common.h"
#include "Mixins.h"
#include "Options.h"

#include <QObject>
#include <QString>
#include <QStringList>

class QFileSystemWatcher;

/// This class allows for admins to swap out the cert files before their certs expire, without needing to restart
/// Fulcrum.
///
/// Monitors filesystem changes for the cert files specified in `options`. If they change, and are loaded successfully,
/// populates options->certs atomically and emits certInfoChanged(). ServerSSL is connected to this signal.
class SSLCertMonitor : public QObject, public TimersByNameMixin
{
    Q_OBJECT
public:
    explicit SSLCertMonitor(std::shared_ptr<Options> options, QObject *parent = nullptr);

    /// Actually starts the monitoring task and also populates the options->certs object with valid certs.
    /// May throw on error.
    void start(const QString &certFile, const QString &keyFile, const QString &wssCertFile, const QString &wssKeyFile);

signals:
    /// This is emitted when the (valid) cert files on disk have changed and been re-read by this class.
    /// Before this is emitted, the new CertInfo in the options object has already been atomically updated.
    void certInfoChanged();

private slots:
    void on_fileChanged(const QString &path);

private:
    std::shared_ptr<Options> options;
    QString cert, key, wssCert, wssKey;
    QFileSystemWatcher *watcher = nullptr;
    QStringList watchedFiles;

    /// Called from start().  Returns a valid CertInfo object given a cert & key filename, or throws on error.
    static Options::CertInfo makeCertInfo(const QObject *context, const QString &certFile, const QString &keyFile);
    /// Called from start().
    Options::Certs readCerts() const;
    /// Helper called from on_fileChanged()
    bool watcherWatchedFilesMismatch() const;
};

