//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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

#include "Mixins.h"
#include "Options.h"
#include "Util.h"

#include <QCoreApplication>
#include <QThread>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <shared_mutex>
#include <type_traits>

class Controller;
class Logger;
class SimpleHttpServer;
class SSLCertMonitor;
class ThreadPool;

extern "C" void signal_trampoline(int sig); ///< signal handler must be extern "C" according to the C++ standard.

class App final : public QCoreApplication, public TimersByNameMixin
{
    Q_OBJECT
    using AtomicInstanceT = std::conditional_t<std::atomic<App *>::is_always_lock_free, std::atomic<App *>, App * volatile>;
    static AtomicInstanceT _globalInstance;
public:
    explicit App(int argc, char *argv[]);
    ~App() override;

    static void miscPreAppFixups();

    Logger *logger() const { return _logger.get(); }

    std::shared_ptr<Options> options;

    /// app-global ids used for JSON-RPC 'id', as well as app-level objects we wish to track by id rather than pointer
    quint64 newId() { return ++globalId; }

    /// This is only ever true if the aboutToQuit signal has fired (as a result of this->exit() or this->quit())
    bool isQuitting() const { return quitting; }

    /// This is thread-safe. Returns the number of SIGINT, etc signals that were caught. If this is ever above
    /// 0, the app is about to exit. This is provided in case long-running tasks may wish to check this value
    /// periodically.
    int signalsCaught() const { return int(sigCtr); }

    ThreadPool *threadPool() const { return tpool.get(); }

    /// Performance optimization to avoid dynamic_cast<App *>(qApp) in ::app() below.
    static App * globalInstance() { return _globalInstance; }

    /// Convenience to obtain our singleton ThreadPool instance that goes with this singleton App instance.
    static ThreadPool *globalThreadPool() { App * a = globalInstance(); return a ? a->threadPool() : nullptr; }

    // -- Test & Bench support (requires -DENABLE_TESTS) --
    using RegisteredTest = struct{};
    using RegisteredBench = struct{};
    /// Call this from namespace-scope to register a test, e.g. static auto foo = registerTest(...)
    static RegisteredTest registerTest(const QString &name, const std::function<void()> &func);
    /// Call this from namespace scope to register a benchmark.
    static RegisteredBench registerBench(const QString &name, const std::function<void()> &func);

    /// If jemalloc is linked to this application and its headers were visible at compile-time, then
    /// this will return a Json-suitable QVariantMap of jemalloc stats.  If that is not the case, then
    /// an empty map will be returned.  This function is 100% reentrant and thread-safe.
    static QVariantMap jemallocStats();

    /// If simdjson is available and compiled-in, then this will return a Json-suitable QVariantMap of simdjson
    /// status.  If the previous is not the case, then an empty map will be returned.  This function is 100% reentrant
    /// and thread-safe.
    static QVariantMap simdJsonStats();

    /// Logs some information on the simdjson implementation. Uses the Log() logger.
    ///
    /// @returns true if it logged anything, false otherwise
    static bool logSimdJsonInfo();

    using QtLogSuppressionList = std::list<QString>;
    using QtLogSuppression = QtLogSuppressionList::const_iterator;

    /// Qt sometimes puts messages to the log that we would rather it not. Use this thread-safe function
    /// to add a substring filter.
    static QtLogSuppression addQtLogSuppression(const QString &substring);
    /// Remove a log suppression previously added with addQtLogSuppression. Note that after removing the item,
    /// suppression handle is invalidated. Thread-safe.
    static void rmQtLogSuppression(QtLogSuppression &);

    /// Returns the extended version string suitable for display for the --version CLI arg
    static QString extendedVersionString(bool justLibs=false);

signals:
    // other code emits the below two to tell the app (main) thread to call the corresponding protected slot to set
    // the corresponding values in the shared Options object.
    void setVerboseDebug(bool); ///< if true, sets verbose debug. If false, clears both verboseTrace and verboseDebug
    void setVerboseTrace(bool); ///< if true, implicitly sets verboseDebug as well

    /// Connected to this->quit() as its slot, useful for being able to quit from any thread.
    /// Pass `true` if this request came as the result of a signal handler.
    void requestQuit(bool signalled = false);

public slots:
    /// SrvMgr is connected to this when it requests a maxBuffer change.  If maxBufferBytes is out of range,
    /// this call has no effect.  Otherwise it updates the app-global Options object.  It is safe to call this
    /// from any thread and/or to use a Qt::DirectConnection here.
    void on_requestMaxBufferChange(int maxBufferBytes);

    /// SrvMgr is connected to this when AdminServer requests a param change.  If arguments are out of range,
    /// this call has no effect.  Otherwise it updates the app-global Options object.  It is safe to call this
    /// from any thread and/or to use a Qt::DirectConnection here.
    void on_bitcoindThrottleParamsChange(int hi, int lo, int decay);

private slots:
    void on_setVerboseDebug(bool);
    void on_setVerboseTrace(bool);

private:
    std::atomic<quint64> globalId = 0;
    const std::unique_ptr<ThreadPool> tpool;
    std::unique_ptr<Logger> _logger;
    std::unique_ptr<Controller> controller;
    QList<std::shared_ptr<SimpleHttpServer> > httpServers;
    std::atomic_bool quitting = false;
    std::unique_ptr<SSLCertMonitor> sslCertMonitor; ///< may be nullptr if no SSL. Once created, instance is persistent.

    void startup();
    void cleanup();

    void cleanup_WaitForThreadPoolWorkers();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
    void start_httpServer(const Options::Interface &iface); // may throw

    static QtLogSuppressionList qlSuppressions; // substrings in this list will be filtered from being logged
    static std::shared_mutex qlSuppressionsMut;

    /// Used to forward Qt messages to our Log() subsystem, installed by miscPreAppFixups()
    static void customQtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);

    /// Used for registerTest and registerBench
    using NameFuncMap = std::map<QString, std::function<void()>>;
    using NameFuncMapPtr = std::unique_ptr<NameFuncMap>;
    static std::unique_ptr<NameFuncMap> registeredTests, registeredBenches;
    static void registerTestBenchCommon(const char *fname, const char *brief, NameFuncMapPtr &map,
                                        const NameFuncMap::key_type &name, const NameFuncMap::mapped_type &func);
    /// Call this at app init and/or after the App object is initialized to undo the locale damage that Qt does
    /// for the C library for number formatting. Previous to this, this could break the JSON serializer.
    static void setCLocale();

    // - Ctrl-C / signal handling for shutdown -
    std::list<Defer<>> posixSignalRegistrations;
    Util::AsyncSignalSafe::Sem exitSem;
    std::unique_ptr<QThread> exitThr;
    using SigCtr = std::conditional_t<std::atomic_int::is_always_lock_free, std::atomic_int, volatile int>;
    SigCtr sigCtr = 0;
    /// Registered for SIGINT, SIGHUP, etc. Sets the condition variable exitSem
    void signalHandler(int sig);
    friend void ::signal_trampoline(int sig); // The extern "C" function declared at the top of this file.
    void startup_Sighandlers();
    void cleanup_Sighandlers();
};

inline App *app() { return App::globalInstance(); }
inline ThreadPool * AppThreadPool() { return App::globalThreadPool(); }
