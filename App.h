#ifndef APP_H
#define APP_H

#include <QCoreApplication>
#include <atomic>
#include <memory>

#include "Options.h"

class Controller;
class Logger;
class SimpleHttpServer;

class App : public QCoreApplication
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App() override;

    Logger *logger() { return _logger.get(); }

    std::shared_ptr<Options> options;

    /// app-global ids used for everything from ElectrumX methods
    /// to client id's, etc.
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

    void cleanup_RunInThreads();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
    void start_httpServer(const Options::Interface &iface); // may throw
};

inline App *app() { return dynamic_cast<App *>(qApp); }

#endif // APP_H
