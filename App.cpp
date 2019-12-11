#include "App.h"
#include "BTC.h"
#include "Controller.h"
#include "Logger.h"
#include "Servers.h"
#include "Util.h"

#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <csignal>
#include <cstdlib>
#include <list>
#include <tuple>

#ifndef __clang__
#ifndef _MSC_VER
// GCC fails for mysterious reasons on Linux. Warn user to try clang.
#warning "Compilation on non-clang compiler may fail. If so, please try using clang >= 8.0 as the compiler!"
#endif
#endif

App::App(int argc, char *argv[])
    : QCoreApplication (argc, argv)
{
    register_MetaTypes();

    options = std::make_shared<Options>();
    options->interfaces = {{QHostAddress("0.0.0.0"), Options::DEFAULT_PORT}}; // start with default, will be cleared if -i specified
    setApplicationName(APPNAME);
    setApplicationVersion(QString("%1 %2").arg(VERSION).arg(VERSION_EXTRA));

    _logger = std::make_unique<ConsoleLogger>(this);

    try {
        parseArgs();
    } catch (const BadArgs &e) {
        options->syslogMode = true; // suppress timestamp stuff
        Error() << e.what();
        std::exit(1);
    }
    if (options->syslogMode) {
        _logger = std::make_unique<SysLogger>(this);
    }

    connect(this, &App::aboutToQuit, this, &App::cleanup);
    QTimer::singleShot(0, this, &App::startup); // register to run after app event loop start
}

App::~App()
{
    Debug() << "App d'tor";
    Log() << "Shudown complete";
    /// child objects will be auto-deleted
}

void App::startup()
{
    static const auto getBannerWithTimeStamp = [] {
        QString ret; {
            QTextStream ts(&ret, QIODevice::WriteOnly|QIODevice::Truncate);
            ts << applicationName() << " " << applicationVersion() << " - " << QDateTime::currentDateTime().toString("ddd MMM d, yyyy hh:mm:ss.zzz t");
        } return ret;
    };
    // print banner to log now
    Log() << getBannerWithTimeStamp() << " - starting up ...";
    // schedule print banner to log every hour
    callOnTimerSoon(60*60*1000, "printTimeStamp", []{ Log() << getBannerWithTimeStamp(); return true; }, Qt::TimerType::VeryCoarseTimer);

    if ( ! Util::isClockSteady() ) {
        Debug() << "High resolution clock provided by the std C++ library is not 'steady'. Log timestamps may drift.";
    } else {
        Debug() << "High resolution clock: isSteady = true";
    }

    try {
        BTC::CheckBitcoinEndiannessAndOtherSanityChecks();

        auto gotsig = [](int sig) {
            static int ct = 0;
            if (!ct++) {
                Log() << "Got signal: " << sig << ", exiting ...";
                app()->exit(sig);
            } else if (ct < 5) {
                std::printf("Duplicate signal %d already being handled, ignoring\n", sig);
            } else {
                std::printf("Signal %d caught more than 5 times, aborting\n", sig);
                std::abort();
            }
        };
        std::signal(SIGINT, gotsig);
        std::signal(SIGTERM, gotsig);
#ifdef Q_OS_UNIX
        std::signal(SIGQUIT, gotsig);
        std::signal(SIGHUP, SIG_IGN);
#endif

        controller = std::make_unique<Controller>(options);
        controller->startup(); // may throw

        if (!options->statsInterfaces.isEmpty()) {
            const auto num = options->interfaces.count();
            Log() << "Stats HTTP: starting " << num << " " << Util::Pluralize("server", num) << " ...";
            // start 'stats' http servers, if any
            for (const auto & i : options->statsInterfaces)
                start_httpServer(i); // may throw
        }

    } catch (const Exception & e) {
        Fatal() << "Caught exception: " << e.what();
    }
}

void App::cleanup()
{
    Debug() << __PRETTY_FUNCTION__ ;
    cleanup_RunInThreads();
    if (!httpServers.isEmpty()) {
        Log("Stopping Stats HTTP Servers ...");
        for (auto h : httpServers) { h->stop(); }
        httpServers.clear(); // deletes shared pointers
    }
    if (controller) { Log("Stopping Controller ... "); controller->cleanup(); controller.reset(); }
}

void App::cleanup_RunInThreads()
{
    static const int timeout = 5000;
    QElapsedTimer t0; t0.start();
    Util::RunInThread::setShuttingDown(true);
    int nWorkersRunning = 0;
    if (!Util::RunInThread::waitForAll(timeout, "Waiting for extant worker threads ...", &nWorkersRunning)) {
        Warning("After %d seconds, %d worker(s) were still active. App will likely abort with an error.", qRound(double(t0.elapsed())/1e3), nWorkersRunning);
    } else if (nWorkersRunning) {
        Debug("%d worker(s) successfully waited for (elapsed: %0.3f secs)", nWorkersRunning, t0.elapsed()/1e3);
    }
}


void App::parseArgs()
{
    QCommandLineParser parser;
    parser.setApplicationDescription("A Bitcoin Cash Blockchain SPV Server.");
    parser.addHelpOption();
    parser.addVersionOption();

    static constexpr auto RPCUSER = "RPCUSER", RPCPASSWORD = "RPCPASSWORD"; // optional env vars we use below

    parser.addOptions
    ({
         { { "D", "datadir" },
           QString("Specify a directory in which to store the database and other assorted data files. This is a "
           "required options. If the specified path does not exist, it will be created. Note that the directory in "
           "question should live on a fast drive such as an SSD and it should have plenty of free space available."),
           QString("path")
         },
         { { "i", "interface" },
           QString("Specify which <interface:port> to listen for connections on, defaults to 0.0.0.0:%1 (all interfaces,"
           " port %1). This option may be specified more than once to bind to multiple interfaces and/or ports.").arg(Options::DEFAULT_PORT),
           QString("interface:port")
         },
         { { "z", "stats" },
           QString("Specify listen address and port for the stats HTTP server. Format is same as the interface option, "
           "e.g.: <interface:port>. Default is to not start any starts HTTP servers. "
           "This option may be specified more than once to bind to multiple interfaces and/or ports."),
           QString("interface:port")
         },
         { { "b", "bitcoind" },
           QString("Specify a <hostname:port> to connect to the bitcoind rpc service. This is a required option, along "
           "with -u and -p. This hostname:port should be the same as you specified in your bitcoin.conf file "
           "under rpcbind= and rpcport=."),
           QString("interface:port")
         },
         { { "u", "rpcuser" },
           QString("Specify a username to use for authenticating to bitcoind. This is a required option, along "
           "with -b and -p.  This opton should be the same username you specified in your bitcoind.conf file "
           "under rpcuser=. For security, you may omit this option from the command-line and use the %1 "
           "environment variable instead (the CLI arg takes precedence if both are present).").arg(RPCUSER),
           QString("username")
         },
         { { "p", "rpcpassword" },
           QString("Specify a password to use for authenticating to bitcoind. This is a required option, along "
           "with -b and -u.  This opton should be the same password you specified in your bitcoind.conf file "
           "under rpcpassword=. For security, you may omit this option from the command-line and use the "
           "%1 environment variable instead (the CLI arg takes precedence if both are present).").arg(RPCPASSWORD),
           QString("password")
         },
         { { "d", "debug" },
           QString("Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q. "
           "(Specify this options twice to get network-level trace debug output.)")
         },
         { { "q", "quiet" },
           QString("Suppress debug output. This is the default on release builds. This is the opposite of -d.")
         },
         { { "S", "syslog" },
           QString("Syslog mode. If on Unix, use the syslog() facility to produce log messages. This option currently has no effect on Windows.")
         },
     });
    parser.process(*this);

    if (parser.isSet("d")) options->verboseDebug = true;
    // check for -d -d
    if (auto found = parser.optionNames(); found.count("d") + found.count("debug") > 1)
        options->verboseTrace = true;
    if (parser.isSet("q")) options->verboseDebug = false;
    if (parser.isSet("S")) options->syslogMode = true;
    // make sure -b -p and -u all present and specified exactly once
    using ReqOptsList = std::list<std::tuple<QString, QString, const char *>>;
    for (const auto & opt : ReqOptsList({{"D", "datadir", nullptr},
                                         {"b", "bitcoind", nullptr},
                                         {"u", "rpcuser", RPCUSER},
                                         {"p", "rpcpassword", RPCPASSWORD},}))
    {
        const auto & [s, l, env] = opt;
        const bool cliIsSet = parser.isSet(s);
        const auto envVar = env ? std::getenv(env) : nullptr;
        if (cliIsSet && envVar)
            Warning() << "Warning: -" << s <<  " is specified both via the CLI and the environement (as " << env << "). The CLI arg will take precendence.";
        if ((!parser.isSet(s) || parser.value(s).isEmpty()) && (!env || !envVar))
            throw BadArgs(QString("Required option missing or empty: -%1 (--%2)%3").arg(s).arg(l).arg(env ? QString(" (or env var: %1)").arg(env) : ""));
        else if (parser.values(s).count() > 1)
            throw BadArgs(QString("Option specified multiple times: -%1 (--%2)").arg(s).arg(l));
    }
    static const auto parseInterface = [](const QString &s) -> Options::Interface {
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
        if (!ok || port == 0)
            throw BadArgs(QString("Bad port: %1").arg(portStr));
        return {h, port};
    };
    static const auto parseInterfaces = [](decltype(Options::interfaces) & interfaces, const QStringList & l) {
        // functor parses -i and -z options, puts results in 'interfaces' passed-in reference.
        interfaces.clear();
        for (const auto & s : l)
            interfaces.push_back(parseInterface(s));
    };

    // grab datadir, check it's good, create it if needed
    options->datadir = parser.value("D");
    QFileInfo fi(options->datadir);
    if (auto path = fi.canonicalFilePath(); fi.exists()) {
        if (!fi.isDir()) // was a file and not a directory
            throw BadArgs(QString("The specified path \"%1\" already exists but is not a directory").arg(path));
        if (!fi.isReadable() || !fi.isExecutable() || !fi.isWritable())
            throw BadArgs(QString("Bad permissions for path \"%1\" (must be readable, writable, and executable)").arg(path));
        Debug() << "datadir: " << path;
    } else { // !exists
        if (!QDir().mkpath(options->datadir))
            throw BadArgs(QString("Unable to create directory: %1").arg(options->datadir));
        path = QFileInfo(options->datadir).canonicalFilePath();
        Debug() << "datadir: Created directory " << path;
    }

    // parse bitcoind
    options->bitcoind = parseInterface(parser.value("b"));
    // grab rpcuser
    options->rpcuser = parser.isSet("u") ? parser.value("u") : std::getenv(RPCUSER);
    // grab rpcpass
    options->rpcpassword = parser.isSet("p") ? parser.value("p") : std::getenv(RPCPASSWORD);
    // grab bind (listen) interfaces
    if (auto l = parser.values("i"); !l.isEmpty()) {
        parseInterfaces(options->interfaces, l);
    }
    parseInterfaces(options->statsInterfaces, parser.values("z"));
}

void App::start_httpServer(const Options::Interface &iface)
{
    std::shared_ptr<SimpleHttpServer> server(new SimpleHttpServer(iface.first, iface.second, 16384));
    httpServers.push_back(server);
    server->tryStart(); // may throw, waits for server to start
    server->set404Message("Error: Unknown endpoint. /stats is the only valid endpoint I understand.\r\n");
    server->addEndpoint("/stats",[this](SimpleHttpServer::Request &req){
        req.response.contentType = "application/json; charset=utf-8";
        auto stats = controller->statsSafe(9000);
        req.response.data = QString("%1\r\n").arg(Util::Json::toString(stats, false)).toUtf8();
    });
}
