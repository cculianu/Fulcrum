#ifndef APP_H
#define APP_H

#include "Options.h"
#include <QCoreApplication>
#include <atomic>
#include <memory>

class Logger;
class SrvMgr;
class SimpleHttpServer;

class App : public QCoreApplication
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App();

    Logger *logger() { return _logger; }

    Options options;

    /// app-global ids used for everything from ElectrumX methods
    /// to client id's, etc.
    inline qint64 newId() { return ++globalId; }

signals:

public slots:

private:
    std::atomic<qint64> globalId = 0;
    Logger *_logger = nullptr;
    SrvMgr *srvmgr = nullptr;
    QList<std::shared_ptr<SimpleHttpServer> > httpServers;

    void startup();
    void cleanup();

    void cleanup_RunInThreads();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
    void start_httpServer(const Options::Interface &iface); // may throw
};

inline App *app() {
    if (auto app  = qApp ; app)
        return dynamic_cast<App *>(app);
    return nullptr;
}

#endif // APP_H
