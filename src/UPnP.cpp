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

#include "UPnP.h"

#include <QList>
#include <QMetaObject>

#include <atomic>
#include <future>
#include <utility>

#ifdef ENABLE_UPNP
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array" /* miniupnpc headers below trigger this */
#endif
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic" /* miniupnpc headers below trigger this */
#endif
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#include <cstring>
#include <shared_mutex>

/* static */
bool UPnP::isSupported() { return true; }

/* static */
QString UPnP::versionString()
{
    return QString::asprintf("miniupnpc %s (API version: %d)", MINIUPNPC_VERSION, int(MINIUPNPC_API_VERSION));
}

// Manages the upnp context, does RAII auto-cleanup, etc.
struct UPnP::Context {
    struct UPNPDev *devlist = nullptr;
    UPNPUrls urls = {};
    IGDdatas data = {};
    int delayMsec = kDefaultTimeoutMsec;
    mutable std::shared_mutex rwlock;
    // The below 3 members are all guarded by `rwlock`
    char externalIPAddress[80] = {0};
    char lanaddr[64] = {};
    MapSpecSet activeMappings;

    Context() = default;

    void cleanup() {
        std::shared_lock sg(rwlock);
        if (urls.controlURL) {
            for (const auto [eprt, iprt] : std::as_const(activeMappings)) {
                const std::string eport = QString::number(static_cast<int>(eprt)).toStdString();
                const std::string iport = QString::number(static_cast<int>(iprt)).toStdString();
                DebugM("UPnP: Unmapping ", eport, " -> ", iport, " ...");
                const int res = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, eport.c_str(), "TCP", 0);
                if (res == UPNPCOMMAND_SUCCESS) {
                    Log l; l << "Unmapped port " << eport;
                    if (eprt != iprt) l << " -> " << iport;
                } else {
                    Warning w; w << "UPNP_DeletePortMapping for port " << eport;
                    if (eprt != iprt) w << " -> " << iport;
                    w << " returned " << res << "(" << strupnperror(res) << ")";
                }
            }
        }
        sg.unlock();
        std::unique_lock g(rwlock);
        activeMappings.clear();
        FreeUPNPUrls(&urls);
        if (devlist) { freeUPNPDevlist(devlist); devlist = nullptr; }
        std::memset(lanaddr, 0, sizeof(lanaddr));
        std::memset(externalIPAddress, 0, sizeof(externalIPAddress));
        std::memset(&data, 0, sizeof(data));
        std::memset(&urls, 0, sizeof(urls));
    }
    bool setup() {
        cleanup();
        int r{}, i{}, error [[maybe_unused]] {};
        /* Discover */
#ifndef UPNPDISCOVER_SUCCESS
        /* miniupnpc 1.5 */
        devlist = upnpDiscover(delayMsec, nullptr, nullptr, 0);
#elif MINIUPNPC_API_VERSION < 14
        /* miniupnpc 1.6 */
        devlist = upnpDiscover(delayMsec, nullptr, nullptr, 0, 0, &error);
#else
        /* miniupnpc 1.9.20150730 */
        devlist = upnpDiscover(delayMsec, nullptr, nullptr, 0, 0, 2, &error);
#endif
        if (!devlist) {
            Error("upnpDiscover returned a null dev list");
            return false;
        }
        for (UPNPDev *d = devlist; d; d = d->pNext) {
            DebugM("Found UPnP Dev ", i, ": ", d->descURL);
            ++i;
        }

        std::unique_lock g(rwlock);

        /* Get valid IGD */
#if MINIUPNPC_API_VERSION <= 17
        r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
#else
        r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), nullptr, 0);
#endif

        if (r != 1) {
            Error("No valid UPnP IGDs found (r=%d; %s)", r, strupnperror(r));
            return false;
        }
        Log() << "Local IP = " << lanaddr;

        /* Probe external IP */
        r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
        if (r != UPNPCOMMAND_SUCCESS) {
            Log() << "GetExternalIPAddress() returned " << r << " (" << strupnperror(r) << ")";
        } else {
            if (externalIPAddress[0]) {
                Log() << "External IP = " << externalIPAddress;
            } else {
                Log() << "GetExternalIPAddress failed.";
            }
        }
        return true;
    }
    ~Context() { cleanup(); }
    Context &operator=(const Context &o) = delete;
    Context &operator=(Context &&o) = delete;
};

void UPnP::start(MapSpecSet mapSpec, int timeoutMsec)
{
    stop();
    if (timeoutMsec <= 0) timeoutMsec = kDefaultTimeoutMsec;
    ctx->delayMsec = timeoutMsec;

    mappings = std::move(mapSpec);

    thread = std::thread([this, name = objectName()]{
        Util::ThreadName::Trace(name, [this, name]{
            run(name.toStdString());
        });
    });
}

void UPnP::run(const std::string name)
{
    bool errorFlag = true;
    Defer d([this, &errorFlag]{
        interrupt();
        if (errorFlag) emit this->error();
    });

    if (mappings.empty()) {
        Error() << "MapSpec set is empty!";
        return;
    }
    Log() << "UPnP thread started, will manage " << mappings.size() << " port "
          << Util::Pluralize("mapping", mappings.size()) << ", probing for IGDs ...";

    if (!ctx->setup()) return; // failure, exit thread with errorFlag set

    errorFlag = false; // ok, we are not in an early error return anymore

    uint64_t iters{};
    std::chrono::milliseconds wait_time;
    do {
        if (interrupt) break;
        // Redo context setup if we couldn't map anything -- we may have gotten a new IP address or other
        // shenanigans...
        bool ok = true;
        if (iters++ && ctx->activeMappings.empty()) {
            DebugM("Redoing UPnP context ...");
            ok = ctx->setup();
        }
        if (ok) {
            for (const auto [extPrt, inPrt] : mappings) {
                const std::string extPort = QString::number(static_cast<int>(extPrt)).toStdString();
                const std::string inPort = QString::number(static_cast<int>(inPrt)).toStdString();
                DebugM("Mapping ", extPort, " (external) -> ", inPort, " (internal) ...");
                int r;
                {
                    std::shared_lock sg(ctx->rwlock);
#ifndef UPNPDISCOVER_SUCCESS
                    /* miniupnpc 1.5 */
                    r = UPNP_AddPortMapping(ctx->urls.controlURL, ctx->data.first.servicetype,
                                            extPort.c_str(), inPort.c_str(), ctx->lanaddr,
                                            name.c_str(), "TCP", 0);
#else
                    /* miniupnpc 1.6 */
                    r = UPNP_AddPortMapping(ctx->urls.controlURL, ctx->data.first.servicetype,
                                            extPort.c_str(), inPort.c_str(), ctx->lanaddr,
                                            name.c_str(), "TCP", 0, "0");
#endif
                }
                std::unique_lock g(ctx->rwlock);

                if (r != UPNPCOMMAND_SUCCESS) {
                    Warning("AddPortMapping(%s, %s, %s) failed with code %d (%s)",
                             extPort.c_str(), inPort.c_str(), ctx->lanaddr, r, strupnperror(r));
                    ctx->activeMappings.erase({extPrt, inPrt});
                    emit mapFailure(extPrt, inPrt);
                } else {
                    if (extPrt != inPrt)
                        Log() << "Mapped port " << extPort << " (ext) -> " << inPort << " (int)";
                    else
                        Log() << "Mapped port " << inPort;
                    ctx->activeMappings.insert({extPrt, inPrt});
                    emit mapSuccess(extPrt, inPrt);
                }
                if (interrupt) break;
            }
        }
        wait_time = !ok || ctx->activeMappings.empty() ? std::chrono::minutes{1} : std::chrono::minutes{20};
    } while (!interrupt.wait(wait_time));
}

void UPnP::stop()
{
    if (thread.joinable()) {
        interrupt();
        thread.join();
    }
    interrupt.reset();
    ctx = std::make_unique<Context>(); // clear state
}

std::optional<UPnP::Info> UPnP::getInfo() const
{
    std::optional<UPnP::Info> ret;
    if (ctx && thread.joinable()) {
        ret.emplace();
        std::shared_lock rg(ctx->rwlock);
        ret->externalIP = ctx->externalIPAddress;
        ret->internalIP = ctx->lanaddr;
        ret->activeMappings = ctx->activeMappings;
    }
    return ret;
}
#else /* !defined(ENABLE_UPNP) */
/* static */ bool UPnP::isSupported() { return false; }
/* static */ QString UPnP::versionString() { return QString{}; }
void UPnP::start(MapSpecSet, int) { Error("UPnP support is not compiled-in to this program"); emit error(); }
void UPnP::stop() {}
void UPnP::run(std::string) {}
std::optional<UPnP::Info> UPnP::getInfo() const { return std::nullopt; }
struct UPnP::Context {};
#endif /* ENABLE_UPNP */

UPnP::UPnP(QObject *parent, const QString &name)
    : QObject(parent), ctx(std::make_unique<Context>())
{
    setObjectName(name);
}

UPnP::~UPnP() { stop(); }

bool UPnP::startSync(MapSpecSet spec, int timeoutMsec)
{
    if (!isSupported()) return false;

    stop();

    std::promise<bool> p;
    std::atomic_bool alreadySet = false;
    std::atomic_size_t resultCtr;
    const size_t expectedResults = spec.size();
    auto f = p.get_future();
    auto result = [&] {
        if (++resultCtr == expectedResults && !alreadySet.exchange(true))
            p.set_value(true);
    };
    auto fail = [&] { if (!alreadySet.exchange(true)) p.set_value(false); };
    QList<QMetaObject::Connection> conns;
    Defer d([&conns]{
        for (const auto &conn : std::as_const(conns))
            QObject::disconnect(conn);
        conns.clear();
    });
    conns += connect(this, &UPnP::error, this, fail, Qt::DirectConnection);
    conns += connect(this, &UPnP::mapFailure, this, result, Qt::DirectConnection);
    conns += connect(this, &UPnP::mapSuccess, this, result, Qt::DirectConnection);

    start(std::move(spec), timeoutMsec);

    const std::future_status res = f.wait_for(std::chrono::milliseconds(timeoutMsec)
                                              + (std::chrono::milliseconds{200} * (expectedResults + 1)));

    switch (res) {
    case std::future_status::timeout:
        Warning("UPnP: startSync timed out");
        return false;
    case std::future_status::ready:
        return f.get();
    case std::future_status::deferred:
        // Should never happen.
        throw Exception("Future returned \"deferred\" status -- this is unexpected!");
    }
}
