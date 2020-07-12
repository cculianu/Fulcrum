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
#pragma once

#include <QCoreApplication>

#include <atomic>
#include <functional>
#include <map>
#include <memory>

#include "Mixins.h"
#include "Options.h"

class Controller;
class Logger;
class SimpleHttpServer;
class ThreadPool;

class App final : public QCoreApplication, public TimersByNameMixin
{
    Q_OBJECT
    static App *_globalInstance;
public:
    explicit App(int argc, char *argv[]);
    ~App() override;

    static void miscPreAppFixups();

    Logger *logger() const { return _logger.get(); }

    std::shared_ptr<Options> options;

    /// app-global ids used for JSON-RPC 'id', as well as app-level objects we wish to track by id rather than pointer
    inline quint64 newId() { return ++globalId; }

    /// This is only ever true if the aboutToQuit signal has fired (as a result of this->exit() or this->quit())
    inline bool isQuitting() const { return quitting; }

    inline ThreadPool *threadPool() const { return tpool.get(); }

    /// Performance optimization to avoid dynamic_cast<App *>(qApp) in ::app() below.
    static inline App * globalInstance() { return _globalInstance; }

    /// Convenience to obtain our singleton ThreadPool instance that goes with this singleton App instance.
    static inline ThreadPool *globalThreadPool() { return _globalInstance ? _globalInstance->threadPool() : nullptr; }

    // -- Test & Bench support (requires -DENABLE_TESTS) --
    using RegisteredTest = struct{};
    using RegisteredBench = struct{};
    /// Call this from namespace-scope to register a test, e.g. static auto foo = registerTest(...)
    static RegisteredTest registerTest(const QString &name, const std::function<void()> &func);
    /// Call this from namespace scope to register a benchmark.
    static RegisteredBench registerBench(const QString &name, const std::function<void()> &func);

signals:
    // other code emits the below two to tell the app (main) thread to call the corresponding protected slot to set
    // the corresponding values in the shared Options object.
    void setVerboseDebug(bool); ///< if true, sets verbose debug. If false, clears both verboseTrace and verboseDebug
    void setVerboseTrace(bool); ///< if true, implicitly sets verboseDebug as well

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

    void startup();
    void cleanup();

    void cleanup_WaitForThreadPoolWorkers();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
    void start_httpServer(const Options::Interface &iface); // may throw

    /// Used to forward Qt messages to our Log() subsystem, installed by miscPreAppFixups()
    static void customMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);

    /// Used for registerTest and registerBench
    using NameFuncMap = std::map<QString, std::function<void()>>;
    static NameFuncMap registeredTests, registeredBenches;
    static void registerTestBenchCommon(const char *fname, const char *brief, NameFuncMap &map,
                                        const NameFuncMap::key_type &name, const NameFuncMap::mapped_type &func);
    /// Call this at app init and/or after the App object is initialized to undo the locale damage that Qt does
    /// for the C library for number formatting. Previous to this, this could break the JSON serializer.
    static void setCLocale();
};

inline App *app() { return App::globalInstance(); }
inline ThreadPool * AppThreadPool() { return App::globalThreadPool(); }
