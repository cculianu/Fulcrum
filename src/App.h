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

signals:

public slots:

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
};

inline App *app() { return App::globalInstance(); }
inline ThreadPool * AppThreadPool() { return App::globalThreadPool(); }
