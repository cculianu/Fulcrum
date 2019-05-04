#ifndef APP_H
#define APP_H

#include "Options.h"
#include <QCoreApplication>
#include <atomic>

class Logger;
class EXMgr;
class SrvMgr;
class Controller;

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
    EXMgr *exmgr = nullptr;
    Controller *controller = nullptr;

    void startup();
    void cleanup();

    void cleanup_RunInThreads();

    void parseArgs();

    /// This is defined in register_MetaTypes.cpp
    void register_MetaTypes();
};

inline App *app() {
    if (auto app  = qApp ; app)
        return dynamic_cast<App *>(app);
    return nullptr;
}

#endif // APP_H
