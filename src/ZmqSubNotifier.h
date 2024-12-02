//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2024 Calin A. Culianu <calin.culianu@gmail.com>
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

#include <QByteArrayList>
#include <QObject>
#include <QString>

#include <memory>

class ZmqSubNotifier : public QObject {
    Q_OBJECT

    struct Pvt;
    std::unique_ptr<Pvt> p;

public:
    explicit ZmqSubNotifier(QObject *parent = nullptr);
    /// If this notifier is running, implicitly calls stop() and joins the listener thread.
    ~ZmqSubNotifier() override;

    /// Checks if the zmq subsystem is linked into the application.
    /// @returns true if zmq support was detected at compile-time and linked into the app, false otherwise
    static bool isAvailable();

    /// If available, returns the ZMQ version string suitable for adding to Fulcrum --version output
    /// @returns the full version string or the empty string if !isAvailable()
    static QString versionString();

    /// Starts the listener thread, and subscribes to a topic on an address.
    /// @param address is typically of the form "tcp://11.22.33.44:1234" for ip:port or "ipc:///path/to/socket"
    ///        for Unix domain sockets.
    /// @param topic is the topic, set to "" for all topics.
    /// @param retryInterval is the number of milliseconds to wait before re-creating the socket. That is, we assume a
    /// stale zmq socket if no data is received in retryInterval msec. Set to <= 0 to never re-create the socket.
    /// @returns true if successful, false otherwise. false may be be returned if: already running, if !isAvailable(),
    /// or if the zmq subsystem threw an exception (in the latter case an errored() signal will be emitted with the
    /// exception message).
    bool start(const QString &address, const QString &topic, long retryInverval = 0 /* msec */);

    /// If the notifier was running, joins its listener thread and stops the notifier.
    /// @post Blocks until the zmq listener thread is fully joined. isRunning() is false after this returns.
    void stop();

    /// @returns true if the listener thread is currently running and is joinable, false otherwise
    bool isRunning() const { return bool(p); }

signals:
    /// Emitted whenever a message is received on the subscribed topic.
    void gotMessage(const QString &topic, const QByteArrayList &parts);
    /// Emitted whenever there is an error from the zmq listener thread. This may be emitted before start() returns
    /// with a false result if the listener thread encountered problems connecting to the remote socket.
    void errored(const QString &errMsg);
};
