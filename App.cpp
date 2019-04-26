#include "App.h"
#include "Logger.h"
#include "Util.h"
#include "EXMgr.h"
#include "SrvMgr.h"
#ifdef Q_OS_UNIX
#include <signal.h>
#endif
#include <QCommandLineParser>
#include <QFile>
#include <cstdlib>

App::App(int argc, char *argv[])
    : QCoreApplication (argc, argv)
{
#ifdef QT_DEBUG
    options.verboseDebug = true;
#else
    options.verboseDebug = false;
#endif
    options.interfaces = {{QHostAddress("0.0.0.0"), DEFAULT_PORT}};
    setApplicationName(APPNAME);
    setApplicationVersion(QString("%1 %2").arg(VERSION).arg(VERSION_EXTRA));

    _logger = new ConsoleLogger(this);

    try {
        parseArgs();
    } catch (const BadArgs &e) {
        options.syslogMode = true; // suppress timestamp stuff
        Error() << e.what();
        std::exit(1);
    }

    connect(this, &App::aboutToQuit, this, &App::cleanup);
    QTimer::singleShot(10, this, &App::startup); // register to run after app event loop start
}

App::~App()
{
    Debug() << "App d'tor";
    Log() << "Shudown complete";
    /// child objects will be auto-deleted
}

void App::startup()
{
    Log() << applicationName() << " " << applicationVersion() << " starting up ...";

    try {
#ifdef Q_OS_UNIX
        auto gotsig = [](int sig) {
            Log() << "Got signal: " << sig << ", exiting ...";
            app()->cleanup();
            app()->exit(sig);
        };
        ::signal(SIGINT, gotsig);
        ::signal(SIGTERM, gotsig);
#endif
        srvmgr = new SrvMgr(options.interfaces, this);
        exmgr = new EXMgr(options.serversFile, this);

        srvmgr->startup(); // may throw Exception
        exmgr->startup(); // may throw Exception
    } catch (const Exception & e) {
        Error () << "Caught exception: " << e.what();
        this->exit(1);
    }
}

void App::cleanup()
{
    Debug() << __PRETTY_FUNCTION__ ;
    if (srvmgr) { Log() << "Stopping SrvMgr ... "; srvmgr->cleanup(); delete srvmgr; srvmgr = nullptr; }
    if (exmgr) { Log() << "Stopping EXMgr ... "; exmgr->cleanup(); delete exmgr; exmgr = nullptr; }
}

void App::parseArgs()
{
    QCommandLineParser parser;
    parser.setApplicationDescription("A CashShuffle shuffle-up server with an integrated ElectrumX validation client.");
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addOptions({
        { { "i", "interface" },
          QString("Specify which <interface:port> to listen for connections on, defaults to 0.0.0.0:%1 (all interfaces,"
                  " port %1). This option may be specified more than once to bind to multiple interfaces.").arg(DEFAULT_PORT),
          QString("interface:port")
        },
        { { "f", "servers" },
          QString("Specify a <server.json> file to use for the master list of servers to connect to. The format for "
                  "this file should be identical to the Electron Cash servers.json format. Defaults to an internal "
                  "compiled-in servers.json."),
          QString("servers.json")
        },
        { { "d", "debug" },
          QString("Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q.")

        },
        { { "q", "quiet" },
          QString("Suppress debug output. This is the default on release builds. This is the opposite of -d.")
        },
        { { "S", "syslog" },
          QString("Syslog mode. Suppress printing of timestamps to the stdout log.")
        },

    });
    parser.process(*this);

    if (parser.isSet("v")) options.verboseDebug = true;
    if (parser.isSet("q")) options.verboseDebug = false;
    if (parser.isSet("S")) options.syslogMode = true;
    auto l = parser.values("i");
    if (!l.isEmpty()) {
        options.interfaces.clear();
        for (auto s : l) {
            auto toks = s.split(":");
            if (toks.length() < 2)
                throw BadArgs("Malformed interface spec. Please pass a address of the form 1.2.3.4:123 for IPv4 or ::1:123 for IPv6.");
            QString portStr = toks.last();
            toks.removeLast();
            QString hostStr = toks.join(":");
            QHostAddress h(hostStr);
            if (h.isNull())
                throw BadArgs(QString("Bad interface address: %1").arg(hostStr));
            bool ok;
            quint16 port = portStr.toUShort(&ok);
            if (!ok)
                throw BadArgs(QString("Bad port: %1").arg(portStr));
            options.interfaces.push_back({h, port});
        }
    }
    auto f = parser.value("f");
    if (!f.isEmpty()) {
        QFile file(f);
        if (!file.open(QFile::ReadOnly) || !file.size()) {
            throw BadArgs(QString("Bad servers.json file specified: %1").arg(f));
        }
        options.serversFile = f;
    }
}
