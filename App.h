#ifndef APP_H
#define APP_H

#include "Options.h"
#include <QCoreApplication>
#include <atomic>
#include <QHostAddress>
#include <QList>

class Logger;
class EXMgr;
class SrvMgr;

class App : public QCoreApplication
{
    Q_OBJECT
public:
    explicit App(int argc, char *argv[]);
    ~App();

    Logger *logger() { return _logger; }

    Options options;

signals:

public slots:

private:
    Logger *_logger = nullptr;
    SrvMgr *srvmgr = nullptr; // TODO: implement multiple servers, 1 per socket
    EXMgr *exmgr = nullptr;

    void startup();
    void cleanup();

    void cleanup_RunInThreads();

    void parseArgs();
};

inline App *app() { return qApp ? dynamic_cast<App *>(qApp) : nullptr; }

#endif // APP_H
