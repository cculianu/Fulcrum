//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2025 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "Util.h"

#include <QObject>

#include <cstdint>
#include <memory>
#include <set>
#include <thread>

/// A class for managing UPnP port mappings (only works if the app is compiled agains libminiupnpc).
class UPnP : public QObject
{
    Q_OBJECT
public:
    explicit UPnP(QObject *parent = nullptr, const QString &name = "UPnP");
    ~UPnP() override;

    /// Returns true if the app is compiled with UPnP support (is linked against the miniupnpc library), false otherwise.
    static bool isSupported();

    /// Returns a valid version string e.g. "miniupnpc 2.2.8" if isSupported(), or an emptry string otherwise.
    static QString versionString();

    struct MapSpec {
        uint16_t extPort = 0; ///< External (public) port
        uint16_t inPort = 0; ///< Internal (local) port that the external port maps to
        auto operator<=>(const MapSpec &o) const = default;
    };

    using MapSpecSet = std::set<MapSpec>;
    static constexpr int kDefaultTimeoutMsec = 2'000;

    /// Start the asynchronous UPnP mapper thread. Will emit error() if !isSupported() or if no UPnP IGDs were found.
    void start(MapSpecSet mappings, int timeoutMsec = kDefaultTimeoutMsec);

    /// Like start() except it waits at least timeoutMsec for all the mapping(s) to happen, or for failure, whichever
    /// comes first, and returns true on success or false on failure. Note that if there is an IGD but all mappings
    /// failed due to conflicts, will still return true. Only returns false on low-level miniupnpc error (no IGD, etc).
    bool startSync(MapSpecSet mappings, int timeoutMsec = kDefaultTimeoutMsec);

    /// Unmap any ports and stop the asynchronours UPnP mapper thread. When this returns the thread is already stopped.
    void stop();

    struct Context;

    struct Info {
        QString externalIP, internalIP;
        MapSpecSet activeMappings;
    };

    std::optional<Info> getInfo() const;

signals:
    /// Emitted on low-level miniupnpc error (such as no IGD found within the timeout period specified)
    void error();
    /// Emitted whenever a mapping succeeds
    void mapSuccess(uint16_t extPort, uint16_t inPort);
    /// Emitted whenever a specific mapping fails
    void mapFailure(uint16_t extPort, uint16_t inPort);

private:
    Util::ThreadInterrupt interrupt;
    MapSpecSet mappings;
    std::thread thread;
    std::unique_ptr<Context> ctx;

    void run(std::string name);
};
