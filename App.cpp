#include "App.h"
#include "Logger.h"
#include "Util.h"
#include "EXMgr.h"
#ifdef Q_OS_UNIX
#include <signal.h>
#endif
App::App(int argc, char *argv[])
    : QCoreApplication (argc, argv)
{
    _logger = new ConsoleLogger(this);

    setApplicationName(APPNAME);
    setApplicationVersion(VERSION);
    Log() << applicationName() << " " << applicationVersion() << " starting up ...";

    connect(this, &App::aboutToQuit, this, &App::cleanup);
    QTimer::singleShot(10, this, &App::startup); // register to run after app event loop start
}

App::~App()
{
    Debug() << "App d'tor";
    /// child objects will be auto-deleted
}

void App::startup()
{
    try {
#ifdef Q_OS_UNIX
        auto gotsig = [](int sig) {
            Log() << "Got signal: " << sig << ", exiting";
            app()->exit(sig);
        };
        ::signal(SIGINT, gotsig);
        ::signal(SIGTERM, gotsig);
#endif
        exmgr = new EXMgr(this);
    } catch (const Exception & e) {
        Error () << "Caught exception: " << e.what();
        this->exit(1);
    }
}

void App::cleanup()
{
    Debug() << __PRETTY_FUNCTION__ ;
    if (exmgr) { delete exmgr; exmgr = nullptr; }
}
