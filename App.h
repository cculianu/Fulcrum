#ifndef APP_H
#define APP_H

#include <QCoreApplication>

#include <atomic>
#include <memory>

#include "Mixins.h"
#include "Options.h"

class Controller;
class Logger;
class SimpleHttpServer;

class App final : public QCoreApplication, public TimersByNameMixin
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App() override;

    Logger *logger() { return _logger.get(); }

    std::shared_ptr<Options> options;

    /// app-global ids used for JSON-RPC 'id', as well as app-level objects we wish to track by id rather than pointer
    inline quint64 newId() { return ++globalId; }

signals:

public slots:

private:
    std::atomic<quint64> globalId = 0;
    std::unique_ptr<Logger> _logger;
    std::unique_ptr<Controller> controller;
    QList<std::shared_ptr<SimpleHttpServer> > httpServers;

    void startup();
    void cleanup();

    void cleanup_WaitForThreadPoolWorkers();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
    void start_httpServer(const Options::Interface &iface); // may throw
};

inline App *app() { return dynamic_cast<App *>(qApp); }

#endif // APP_H
