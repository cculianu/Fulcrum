//
// Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
// Copyright (C) 2019-2022 Calin A. Culianu <calin.culianu@gmail.com>
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
#include "App.h"
#include "BTC.h"
#include "Compat.h"
#include "Controller.h"
#include "Json/Json.h"
#include "Logger.h"
#include "ServerMisc.h"
#include "Servers.h"
#include "Storage.h"
#include "SSLCertMonitor.h"
#include "ThreadPool.h"
#include "Util.h"
#include "ZmqSubNotifier.h"

#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostInfo>
#include <QLibraryInfo>
#include <QLocale>
#include <QRegularExpression>
#include <QSemaphore>
#include <QSslSocket>
#include <QTextStream>

#include <algorithm>
#include <array>
#include <cassert>
#include <clocale>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <list>
#include <locale>
#include <mutex>
#include <tuple>
#include <utility>

App::AtomicInstanceT App::_globalInstance = nullptr;

App::App(int argc, char *argv[])
    : QCoreApplication (argc, argv), tpool(std::make_unique<ThreadPool>(this))
{
    // Enforce "C" locale so JSON doesn't break. We do this because QCoreApplication
    // may set the C locale to something unexpected which may break JSON number
    // formatting & parsing.
    RAII localeParanoia([]{setCLocale();}, []{setCLocale();});

    assert(!_globalInstance);
    _globalInstance = this;
    register_MetaTypes();

    options = std::make_shared<Options>();
    options->interfaces = {{QHostAddress("0.0.0.0"), Options::DEFAULT_PORT_TCP}}; // start with default, will be cleared if -t specified
    setApplicationName(APPNAME);
    setApplicationVersion(QString("%1 %2").arg(VERSION, VERSION_EXTRA));

    _logger = std::make_unique<ConsoleLogger>(this);

    try {
        parseArgs();
    } catch (const std::exception &e) {
        options->syslogMode = true; // suppress timestamp stuff
        Error() << e.what();
        Log() << "Use the -h option to show help.";
        std::exit(1);
    }
    if (options->syslogMode) {
        _logger = std::make_unique<SysLogger>(this);
    }

    connect(this, &App::aboutToQuit, this, &App::cleanup);
    connect(this, &App::setVerboseDebug, this, &App::on_setVerboseDebug);
    connect(this, &App::setVerboseTrace, this, &App::on_setVerboseTrace);
    connect(this, &App::requestQuit, this, [this] (bool signalled) {
        Log() << "Shutdown requested" << (signalled ? " via signal" : "");
        this->quit();
    }, Qt::QueuedConnection);
    QTimer::singleShot(0, this, &App::startup); // register to run after app event loop start
}

App::~App()
{
    Debug() << "App d'tor";
    Log() << "Shutdown complete";
    _globalInstance = nullptr;
    /// child objects will be auto-deleted, however most are already gone in cleanup() at this point.
}

void App::signalHandler(int sig)
{
    // We must use writeStdErr() below since it is async signal safe (fprintf, std::cerr, etc are not).
    constexpr int thresh = 5;
    using Util::AsyncSignalSafe::writeStdErr, Util::AsyncSignalSafe::SBuf;
    if (const auto ct = ++sigCtr; ct == 1) {
        writeStdErr(SBuf{" -- Caught signal ", sig, ", exiting ..."});
    } else if (ct < thresh) {
        writeStdErr(SBuf{" -- Caught signal ", sig, " (count: ", ct, "/", thresh, "). "
                         APPNAME " is exiting, please wait ..."});
    } else {
        writeStdErr(SBuf{" -- Caught signal ", sig, ". Caught ", thresh, " or more signals, aborting."});
        std::abort();
    }
    if (const auto optError = exitSem.release()) { // wake exitThr
        writeStdErr(*optError); // unlikely to occur, but there was an error here!
    }
}

void App::startup_Sighandlers()
{
    if (exitThr && exitThr->isRunning())
        throw InternalError("Exit thread is already running!");

    sigCtr = 0;

    // "Quit" thread. Waits on exitSem and then does a quit.  Woken up precisely once from the signal handler,
    // or from the App::cleanup_Sighandlers() function (whichever executes first).
    class ExitThr : public QThread {
        App * const app;
        QSemaphore startedSem{0};
        std::atomic_bool deleting = false;
    public:
        explicit ExitThr(App *app_) : QThread(app_), app(app_) { setObjectName("ExitThr"); }
        ~ExitThr() override {
            deleting = true;
            if (isRunning()) {
                if (const auto optErr = app->exitSem.release()) {
                    // should never happen -- here to defend against programming errors.
                    Error() << "Error in exitSem.release(): " << static_cast<const char *>(*optErr);
                    terminate();
                }
                if (!wait(500)) terminate(), wait();
            }
        }
        void run() override {
            startedSem.release();
            setTerminationEnabled(true); // applies to currently running thread
            DebugM("started with stack size: ", stackSize() ? QString::number(stackSize()) : QString("default"));
            Defer d([]{DebugM("exited");});
            while (!deleting && !app->sigCtr) {
                // keep waiting to allow for spurious wake-ups -- stop waiting when either quitting or sigCtr != 0
                if (const auto optErr = app->exitSem.acquire()) {
                    // should never happen -- here to defend against programming errors.
                    Error() << "Error in exitSem.acquire(): " << static_cast<const char *>(*optErr);
                    return;
                }
            }
            if (!deleting) emit app->requestQuit(true);
        }
        void startSynched() {
            if (isRunning()) return;
            start();
            if (!startedSem.tryAcquire(1, 5000))
                throw InternalError("ExitThr did not start after 5 seconds. Please report this bug to the developers.");
        }
    };

    // ExitThr creation and start
    exitThr = std::make_unique<ExitThr>(this);
    ExitThr &et = dynamic_cast<ExitThr &>(*exitThr);
    // Ensure thread is started before proceeding -- wait up to 5 seconds for thread to start. This usually succeeds within 1 ms.
    et.startSynched();

#define Tup(x, b) std::tuple<decltype(SIGINT), const char *, bool>{x, #x, b}
    const auto pairs = {
        Tup(SIGINT, true), Tup(SIGTERM, true), // all platforms have these signals
#ifdef Q_OS_UNIX
        Tup(SIGQUIT, true), Tup(SIGHUP, false), // unix only
#endif
#undef Tup
    };
    int nreg = 0;
    for (const auto & [sig, name, reg] : pairs) {
        const auto prev = std::signal(sig, reg ? signal_trampoline : SIG_IGN);
        if (prev == SIG_ERR)
            Warning() << "Error registering " << name << ": " << std::strerror(errno);
        else {
            if (reg) {
                ++nreg;
                DebugM("Registered ", name);
            } else
                DebugM("Ignoring ", name);
            posixSignalRegistrations.emplace_back(
                // Executes at list destruction (unregister)
                [sig=sig, name=name, prev]{
                    std::signal(sig, prev);
                    DebugM("Restored ", name);
            });
        }
    }
    DebugM("Registered ", nreg, Util::Pluralize(" signal handler", nreg));
}

/// The standard says we must use C linkage for POSIX signal handlers
extern "C" void signal_trampoline(int sig) { if (App *a = App::globalInstance()) a->signalHandler(sig); }

void App::startup()
{
    static const auto getBannerWithTimeStamp = [] {
        QString ret; {
            QTextStream ts(&ret, QIODevice::WriteOnly|QIODevice::Truncate);
            ts << applicationName() << " " << applicationVersion() << " - " << QDateTime::currentDateTime().toString("ddd MMM d, yyyy hh:mm:ss.zzz t");
        } return ret;
    };

    // print the libs we are using to log now
    for (const auto &line : extendedVersionString(true).split("\n", Compat::SplitBehaviorSkipEmptyParts))
        Log() << line;

    // print banner to log now
    Log() << getBannerWithTimeStamp() << " - starting up ...";

    if ( ! Util::isClockSteady() ) {
        Debug() << "High resolution clock provided by the std C++ library is not 'steady'. Log timestamps may drift if system time gets adjusted.";
    } else {
        Debug() << "High resolution clock: isSteady = true";
    }
    // attempt to raise rlimit for max open files on Unix platforms (on Windows the limit is already absurdly high)
    if (const auto res = Util::raiseMaxOpenFilesToHardLimit(); res.status != res.NotRelevant) {
        if (res.status == res.Ok) {
            Log() << "Max open files: " << res.newLimit
                  << (res.oldLimit != res.newLimit ? QString(" (increased from default: %1)").arg(res.oldLimit) : "");
            constexpr int min = 2000;
            if (res.newLimit < min) {
                Warning() << "The max open file limit for this process is low. Please see about configuring your"
                             " system to raise the hard limit on open files beyond " << min << ".";
            }
        } else // error
            Warning() << "Failed to raise max open file limit: " << res.errMsg;
    }
    try {
        BTC::CheckBitcoinEndiannessAndOtherSanityChecks();

        startup_Sighandlers(); // register our signal handlers (SIGINT, SIGTERM, etc)

        controller = std::make_unique<Controller>(options, sslCertMonitor.get());
        controller->startup(); // may throw

        if (!options->statsInterfaces.isEmpty()) {
            const auto num = options->statsInterfaces.count();
            Log() << "Stats HTTP: starting " << num << " " << Util::Pluralize("server", num) << " ...";
            // start 'stats' http servers, if any
            for (const auto & i : options->statsInterfaces)
                start_httpServer(i); // may throw
        }

    } catch (const std::exception & e) {
        Fatal() << "Caught exception: " << e.what();
    }
}

void App::cleanup()
{
    Debug() << __PRETTY_FUNCTION__ ;
    quitting = true;
    cleanup_WaitForThreadPoolWorkers();
    if (!httpServers.isEmpty()) {
        Log("Stopping Stats HTTP Servers ...");
        for (auto h : httpServers) { h->stop(); }
        httpServers.clear(); // deletes shared pointers
    }
    if (controller) { Log("Stopping Controller ... "); controller->cleanup(); controller.reset(); }
    cleanup_Sighandlers();
}

void App::cleanup_Sighandlers()
{
    posixSignalRegistrations.clear(); // unregisters the registered signal handlers
    exitThr.reset(); // implicitly quits then joins the thread
}

void App::cleanup_WaitForThreadPoolWorkers()
{
    constexpr int timeout = 5000;
    QElapsedTimer t0; t0.start();
    const int nJobs = tpool->extantJobs();
    if (nJobs)
        Log() << "Waiting for extant thread pool workers ...";
    const bool res = tpool->shutdownWaitForJobs(timeout);
    if (!res) {
        Warning("After %d seconds, %d thread pool %s %s still active. App may abort with an error.",
                qRound(double(t0.elapsed())/1e3), nJobs, Util::Pluralize("worker", nJobs).toUtf8().constData(),
                qAbs(nJobs) == 1 ? "is" : "are");
    } else if (nJobs) {
        Debug("Successfully waited for %d thread pool %s (elapsed: %0.3f secs)", nJobs,
              Util::Pluralize("worker", nJobs).toUtf8().constData(), t0.elapsed()/1e3);
    }
}


void App::parseArgs()
{
    QCommandLineParser parser;
    parser.setApplicationDescription("A Bitcoin Cash (and Bitcoin BTC) Blockchain SPV Server");
    parser.addHelpOption();

    static constexpr auto RPCUSER = "RPCUSER", RPCPASSWORD = "RPCPASSWORD"; // optional env vars we use below

    QList<QCommandLineOption> allOptions{
    { { "D", "datadir" },
       QString("Specify a directory in which to store the database and other assorted data files. This is a"
       " required option. If the specified path does not exist, it will be created. Note that the directory in"
       " question should ideally live on a fast drive such as an SSD and it should have plenty of free space"
       " available.\n"),
       QString("path"),
    },
    { { "t", "tcp" },
       QString("Specify an <interface:port> on which to listen for TCP connections, defaults to 0.0.0.0:%1 (all"
       " interfaces, port %1 -- only if no other interfaces are specified via -t or -s)."
       " This option may be specified more than once to bind to multiple interfaces and/or ports."
       " Suggested values for port: %1 on mainnet and %2 on testnet.\n").arg(Options::DEFAULT_PORT_TCP).arg(Options::DEFAULT_PORT_TCP + 10000),
       QString("interface:port"),
    },
    { { "s", "ssl" },
       QString("Specify an <interface:port> on which to listen for SSL connections. Note that if this option is"
       " specified, then the `cert` and `key` options need to also be specified otherwise the app will refuse to run."
       " This option may be specified more than once to bind to multiple interfaces and/or ports."
       " Suggested values for port: %1 on mainnet and %2 on testnet.\n").arg(Options::DEFAULT_PORT_SSL).arg(Options::DEFAULT_PORT_SSL + 10000),
       QString("interface:port"),
    },
    {  { "w", "ws"},
       QString("Specify an <interface:port> on which to listen for Web Socket connections (unencrypted, ws://)."
       " This option may be specified more than once to bind to multiple interfaces and/or ports."
       " Suggested values for port: %1 on mainnet and %2 on testnet.\n").arg(Options::DEFAULT_PORT_WS).arg(Options::DEFAULT_PORT_WS + 10000),
       QString("interface:port"),
    },
    {  { "W", "wss"},
       QString("Specify an <interface:port> on which to listen for Web Socket Secure connections (encrypted, wss://)."
       " Note that if this option is specified, then the --cert and --key options (or alternatively, the --wss-cert"
       " and --wss-key options) need to also be specified otherwise the app will refuse to run."
       " This option may be specified more than once to bind to multiple interfaces and/or ports."
       " Suggested values for port: %1 on mainnet and %2 on testnet.\n").arg(Options::DEFAULT_PORT_WSS).arg(Options::DEFAULT_PORT_WSS + 10000),
       QString("interface:port"),
    },
    { { "c", "cert" },
       QString("Specify a PEM file to use as the server's SSL certificate. This option is required if the -s/--ssl"
       " and/or the -W/--wss options appear at all on the command-line. The file should contain either a single"
       " valid self-signed certificate or the full certificate chain if using CA-signed certificates.\n"),
       QString("crtfile"),
    },
    { { "k", "key" },
      QString("Specify a PEM file to use as the server's SSL key. This option is required if the -s/--ssl and/or"
      " the -W/--wss options apear at all on the command-line. The file should contain an RSA private key."
      " EC, DH, and DSA keys are also supported, but their support is experimental.\n"),
      QString("keyfile"),
    },
    { "wss-cert",
      QString("Specify a certificate PEM file to use specifically for only WSS ports. This option is intended to"
              " allow WSS ports to use a CA-signed certificate (required by web browsers), whereas legacy Electrum"
              " Cash ports may want to continue to use self-signed certificates. If this option is specified,"
              " --wss-key must also be specified. If this option is missing, then WSS ports will just fall-back to"
              " using the certificate specified by --cert.\n"),
      QString("crtfile"),
    },
    { "wss-key",
      QString("Specify a private key PEM file to use for WSS. This key must go with the certificate specified in"
              " --wss-cert. If this option is specified, --wss-cert must also be specified.\n"),
      QString("keyfile"),
    },
    { { "a", "admin" },
      QString("Specify a <port> or an <interface:port> on which to listen for TCP connections for the admin RPC service."
              " The admin service is used for sending special control commands to the server, such as stopping"
              " the server, and it should *NOT* be exposed to the internet. This option is required if you wish to"
              " use the FulcrumAdmin CLI tool to send commands to Fulcrum. It is recommended that you specify the"
              " loopback address as the bind interface for this option such as: <port> by itself or 127.0.0.1:<port> for"
              " IPv4 and/or ::1:<port> for IPv6. If no interface is specified, and just a port number by itself is"
              " used, then IPv4 127.0.0.1 is the bind interface used (along with the specified port)."
              " This option may be specified more than once to bind to multiple interfaces and/or ports.\n"),
      QString("[interface:]port"),
    },
    { { "z", "stats" },
       QString("Specify listen address and port for the stats HTTP server. Format is same as the -s, -t or -a options,"
       " e.g.: <interface:port>. Default is to not start any starts HTTP servers. Also, like the -a option, you may"
       " specify a port number by itself here and 127.0.0.1:<port> will be assumed."
       " This option may be specified more than once to bind to multiple interfaces and/or ports.\n"),
       QString("[interface:]port"),
    },
    { { "b", "bitcoind" },
       QString("Specify a <hostname:port> to connect to the bitcoind rpc service. This is a required option, along"
       " with -u and -p. This hostname:port should be the same as you specified in your bitcoin.conf file"
       " under rpcbind= and rpcport=.\n"),
       QString("hostname:port"),
    },
    { "bitcoind-tls",
       QString("If specified, connect to the remote bitcoind via HTTPS rather than the usual HTTP. Historically,"
               " bitcoind supported only JSON-RPC over HTTP; however, some implementations such as bchd support"
               " HTTPS. If you are using " APPNAME " with bchd, you either need to start bchd with the `notls`"
               " option, or you need to specify this option to " APPNAME ".\n"),
    },
    { { "u", "rpcuser" },
       QString("Specify a username to use for authenticating to bitcoind."
       " This option should be the same username you specified in your bitcoind.conf file"
       " under rpcuser=. For security, you may omit this option from the command-line and use the %1"
       " environment variable instead (the CLI arg takes precedence if both are present), or you may use -K"
       " instead.\n").arg(RPCUSER),
       QString("username"),
    },
    { { "p", "rpcpassword" },
       QString("Specify a password to use for authenticating to bitcoind."
       " This option should be the same password you specified in your bitcoind.conf file"
       " under rpcpassword=. For security, you may omit this option from the command-line and use the"
       " %1 environment variable instead (the CLI arg takes precedence if both are present), or you may use -K"
       " instead.\n").arg(RPCPASSWORD),
       QString("password"),
    },
    { { "K", "rpccookie" },
       QString("This option can be used instead of -u and -p. The file path for the bitcoind '.cookie' file (normally"
               " lives inside bitcoind's datadir). This file is auto-generated by bitcoind and will be read and"
               " re-parsed each time we (re)connect to bitcoind. Use this option only if your bitcoind is using"
               " cookie-file based RPC authentication.\n"),
       QString("cookiefile"),
    },
    { { "d", "debug" },
       QString("Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q."
       " (Specify this options twice to get network-level trace debug output.)\n"),
    },
    { { "q", "quiet" },
       QString("Suppress debug output. This is the default on release builds. This is the opposite of -d.\n"),
    },
    { { "S", "syslog" },
       QString("Syslog mode. If on Unix, use the syslog() facility to produce log messages."
               " This option currently has no effect on Windows.\n"),
    },
    { { "C", "checkdb" },
       QString("If specified, database consistency will be checked thoroughly for sanity & integrity."
               " Note that these checks are somewhat slow to perform and under normal operation are not necessary."
               " May be specified twice to do even more thorough checks.\n"),
    },
    { { "T", "polltime" },
       QString("The number of seconds for the bitcoind poll interval. Bitcoind is polled once every `polltime`"
               " seconds to detect mempool and blockchain changes. This value must be at least 0.5 and cannot exceed"
               " 30. If not specified, defaults to %1 seconds.\n").arg(Options::defaultPollTimeSecs),
       QString("polltime"), QString::number(Options::defaultPollTimeSecs)
    },
    {
       "ts-format",
       QString("Specify log timestamp format, one of: \"none\", \"uptime\", \"localtime\", or \"utc\". "
               "If unspecified, default is \"localtime\" (previous versions of " APPNAME " always logged using "
               "\"uptime\").\n"),
       QString("keyword"),
    },
    {
       "tls-disallow-deprecated",
       QString("If specified, restricts the TLS protocol used by the server to non-deprecated v1.2 or newer,"
               " disallowing connections from clients requesting TLS v1.1 or earlier. This option applies to all"
               " SSL and WSS ports server-wide.\n"),
    },
    {
        "no-simdjson",
        QString("If specified, disable the fast simdjson backend for JSON parsing. This parser is over 2x faster"
                " than the original parser, and is enabled by default as of " APPNAME " version 1.3.0.\n"),
    },
    {
        "bd-timeout",
        QString("Corresponds to the configuration file variable \"bitcoind_timeout\". The number of seconds to wait for"
                " unanswered bitcoind requests before we consider them as having timed-out (default: %1). You may wish"
                " to set this higher than the default if using BCH ScaleNet, or if you see \"bitcoind request timed"
                " out\" appear in the log.\n").arg(double(Options::defaultBdTimeout)/1e3),
        QString("seconds"),
    },
    {
        "bd-clients",
        QString("Corresponds to the configuration file variable \"bitcoind_clients\". The number of simultaneous"
                " bitcoin RPC clients that we spawn to connect to bitcoind (default: %1). If you raise this value from"
                " the default, be sure to also specify the option `rpcthreads=` to bitcoind so that there are enough"
                " threads to accommodate the clients we spawn, otherwise you may get errors from bitcoind.\n")
                .arg(Options::defaultBdNClients),
        QString("num"),
    },
    {
       "compact-dbs",
       QString("If specified, " APPNAME " will compact all databases on startup. The compaction process reduces"
               " database disk space usage by removing redundant/unused data. Note that rocksdb normally compacts the"
               " databases in the background while " APPNAME " is running, so using this option to explicitly compact"
               " the database files on startup is not strictly necessary.\n"),
    },
    {
       "fast-sync",
       QString("If specified, " APPNAME " will use a UTXO Cache that consumes extra memory but syncs up to to 2X"
               " faster. To use this feature, you must specify a memory value in MB to allocate to the cache. It is"
               " recommended that you give this facility at least 2000 MB for it to really pay off, although any amount"
               " of memory given (minimum 200 MB) should be beneficial. Note that this feature is currently"
               " experimental and the tradeoffs are: it is faster because it avoids redundant disk I/O, however, this"
               " comes at the price of considerable memory consumption as well as a sync that is less resilient to"
               " crashes mid-sync. If the process is killed mid-sync, the database may become corrupt and lose UTXO"
               " data. Use this feature only if you are 100% sure that won't happen during a sync. Specify as much"
               " memory as you can, in MB, here, e.g.: 3000 to allocate 3000 MB (3 GB). The default is off (0). This"
               " option only takes effect on initial sync, otherwise this option has no effect.\n"),
       QString("MB"),
    },
    {
       "dump-sh",
       QString("*** This is an advanced debugging option ***   Dump script hashes. If specified, after the database"
               " is loaded, all of the script hashes in the database will be written to outputfile as a JSON array.\n"),
       QString("outputfile"),
    },
    { { "v", "version" },
       QString("Print version information and exit.\n"),
    },
    };

    bool haveTests{}, haveBenches{};
    if ((haveTests = registeredTests && !registeredTests->empty())) {
        // add --test option if we have any registered tests
        const auto tests = Util::keySet<QStringList>(*registeredTests);
        allOptions.push_back({
            "test",
            QString("Run a test and exit. This option may be specified multiple times. Specify \"all\" to run all tests."
                    " Available tests: \"%1\"\n").arg(tests.join("\", \"")),
            QString("test")
        });
    }
    if ((haveBenches = registeredBenches && !registeredBenches->empty())) {
        // add --bench option if we have any registered benches
        const auto benches = Util::keySet<QStringList>(*registeredBenches);
        allOptions.push_back({
            "bench",
            QString("Run a benchmark and exit. This option may be specified multiple times. Specify \"all\" to run all benchmarks."
                    " Available benchmarks: \"%1\"\n").arg(benches.join("\", \"")),
            QString("benchmark")
        });
    }

    parser.addOptions(allOptions);
    parser.addPositionalArgument("config", "Configuration file (optional).", "[config]");
    parser.process(*this);

    // handle --version first, this exits immediately
    if (parser.isSet("v")) {
        std::cout << extendedVersionString().toStdString();
        std::exit(0);
    }

    // handle possible --test or --bench args before doing anything else, since
    // those immediately exit the app if they do run.
    try {
        int setCtr = 0;
        auto handleDebugPrtOpts = [&] {
            // custom hack used only for test/bench mode to enable/disable debug output in test mode from CLI args
            static std::once_flag once;
            std::call_once(once, [&] {
                if (auto found = parser.optionNames(); const auto dbgct = (found.count("d") + found.count("debug"))) {
                    if (dbgct) options->verboseDebug = true;
                    if (dbgct > 1) options->verboseTrace = true;
                } else if (found.count("q") || found.count("quiet")) {
                    options->verboseDebug = options->verboseTrace = false;
                }
            });
        };
        if (haveTests && parser.isSet("test")) {
            ++setCtr;
            handleDebugPrtOpts();
            auto vals = parser.values("test");
            if (vals.length() == 1 && vals.front() == "all") {
                // special keyword "all" means run all tests
                vals = Util::keySet<decltype(vals)>(*registeredTests);
                Log() << "Running all " << vals.count() << " tests ...";
            }
            // process tests and exit if we take this branch
            for (const auto & tname : vals) {
                auto it = registeredTests->find(tname);
                if (it == registeredTests->end())
                    throw BadArgs(QString("No such test: %1").arg(tname));
                Log(Log::Color::BrightGreen) << "Running test: " << it->first << " ...";
                it->second();
            }
        }
        if (haveBenches && parser.isSet("bench")) {
            ++setCtr;
            handleDebugPrtOpts();
            auto vals = parser.values("bench");
            if (vals.length() == 1 && vals.front() == "all") {
                // special keyword "all" means run all benchmarks
                vals = Util::keySet<decltype(vals)>(*registeredBenches);
                Log() << "Running all " << vals.count() << " benchmarks ...";
            }
            // process benches and exit if we take this branch
            for (const auto & tname : vals) {
                auto it = registeredBenches->find(tname);
                if (it == registeredBenches->end())
                    throw BadArgs(QString("No such bench: %1").arg(tname));
                Log(Log::Color::BrightCyan) << "Running benchmark: " << it->first << " ...";
                it->second();
            }
        }
        if (setCtr)
            std::exit(0);
    } catch (const std::exception & e) {
        // bench or test execution failed with an exception
        Error(Log::Color::Magenta) << "Caught exception: " << e.what();
        std::exit(1);
    }

    const auto checkSupportsSsl = [] {
        if (!QSslSocket::supportsSsl())
            throw InternalError("SSL support is not compiled and/or linked to this version. Cannot proceed with SSL support. Sorry!");
    };

    ConfigFile conf;

    // First, parse config file (if specified) -- We will take whatever it specified that matches the above options
    // but CLI args take precedence over config file options.
    if (auto posArgs = parser.positionalArguments(); !posArgs.isEmpty()) {
        if (posArgs.size() > 1)
            throw BadArgs("More than 1 config file was specified. Please specify at most 1 config file.");
        const auto file = posArgs.first();
        if (!conf.open(file))
            throw BadArgs(QString("Unable to open config file %1").arg(file));
        // ok, at this point the config file is slurped up and we can check it below
    }

    // first warn user about dupes
    for (const auto & opt : allOptions) {
        static const auto DupeMsg = [](const QString &arg) {
            Log() << "'" << arg << "' specified both via the CLI and the configuration file. The CLI arg will take precedence.";
        };
        for (const auto & name : opt.names()) {
            if (name.length() == 1) continue;
            if (conf.hasValue(name) && parser.isSet(name)) {
                DupeMsg(name);
                conf.remove(name);
            }
        }
    }

    if (parser.isSet("d") || conf.boolValue("debug")) {
        //if (config.hasValue("debug"))
        options->verboseDebug = true;
    }
    // check for -d -d
    if (auto found = parser.optionNames(); found.count("d") + found.count("debug") > 1)
        options->verboseTrace = true;
    else {
        // check for multiple debug = true in configFile (only present if no -d on CLI, otherwise config keys are deleted)
        const auto l = conf.values("debug");
        int ctr = 0;
        for (const auto & str : l)
            ctr += (str.toInt() || QStringList{{"yes","true","on",""}}.contains(str.toLower())) ? 1 : 0;
        if (ctr > 1)
            options->verboseTrace = true;
    }
    if (parser.isSet("q") || conf.boolValue("quiet")) options->verboseDebug = false;
    if (parser.isSet("S") || conf.boolValue("syslog")) options->syslogMode = true;
    if (const auto pset = parser.isSet("C"); pset || conf.boolValue("checkdb")) {
        if (pset)
            options->doSlowDbChecks = parser.optionNames().count("C");
        else
            options->doSlowDbChecks = conf.values("checkdb").size();
    }
    // parse --polltime
    // note despite how confusingly the below line reads, the CLI parser value takes precedence over the conf file here.
    const QString polltimeStr = conf.value("polltime", parser.value("T"));
    if (bool ok; (options->pollTimeSecs = polltimeStr.toDouble(&ok)) < options->minPollTimeSecs
            || !ok || options->pollTimeSecs > options->maxPollTimeSecs) {
        throw BadArgs(QString("The 'polltime' option must be a numeric value in the range [%1, %2]").arg(options->minPollTimeSecs).arg(options->maxPollTimeSecs));
    }
    // make sure -b, -D are present and specified exactly once
    // -p and -u may be missing only if -K is specified
    const bool specifiedRpcCookie = conf.hasValue("rpccookie") || parser.isSet("K");
    using ReqOptsList = std::list<std::tuple<QString, QString, const char *, bool>>;
    for (const auto & opt : ReqOptsList({{"D", "datadir", nullptr, true},
                                         {"b", "bitcoind", nullptr, true},
                                         {"u", "rpcuser", RPCUSER, !specifiedRpcCookie},
                                         {"p", "rpcpassword", RPCPASSWORD, !specifiedRpcCookie},}))
    {
        const auto & [s, l, env, shouldHave] = opt;
        const bool cliIsSet = parser.isSet(s);
        const bool confIsSet = conf.hasValue(l);
        const auto envVar = env ? std::getenv(env) : nullptr;
        if ((cliIsSet || confIsSet) && envVar)
            Warning() << "Warning: " << l <<  " is specified both via the " << (cliIsSet ? "CLI" : "config file")
                      << " and the environement (as " << env << "). The " << (cliIsSet ? "CLI arg" : "config file setting")
                      << " will take precendence.";
        const bool notFound = ((!cliIsSet && !confIsSet) || conf.value(l, parser.value(s)).isEmpty()) && (!env || !envVar);
        if (shouldHave && notFound)
            throw BadArgs(QString("Required option missing or empty: -%1 (--%2)%3")
                          .arg(s, l, env ? QString(" (or env var: %1)").arg(env) : QString{}));
        else if (!shouldHave && !notFound)
            throw BadArgs(QString("Option may not be specified along with the -K/--rpccookie option: -%1 (--%2)%3")
                          .arg(s, l, env ? QString(" (or env var: %1)").arg(env) : QString{}));
        else if (parser.values(s).count() > 1)
            throw BadArgs(QString("Option specified multiple times: -%1 (--%2)").arg(s).arg(l));
        else if (conf.values(l).count() > 1)
            throw BadArgs(QString("This option cannot be specified multiple times in the config file: %1").arg(l));
    }
    const auto parseInterface = [&options = options](const QString &s, bool allowImplicitLoopback = false,
                                                     bool allowHostNameLookup = false) -> Options::Interface {
        const auto pair = Util::ParseHostPortPair(s, allowImplicitLoopback);
        const auto & hostStr = pair.first;
        const auto port = pair.second;
        QHostAddress h(hostStr);
        if (h.isNull() && allowHostNameLookup) {
            Log() << "Resolving hostname: " << hostStr << " ...";
            // Hmm. Try and look up the host -- this is slow and blocks. We use this for tor_proxy currently.
            QHostInfo hi = QHostInfo::fromName(hostStr);
            if (const auto addrs = hi.addresses(); hi.error() == QHostInfo::HostInfoError::NoError && !addrs.isEmpty()) {
                // prefer ipv4 to ipv6
                for (const auto & addr : addrs) {
                    if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
                        h = addr;
                        break;
                    }
                }
                if (h.isNull())
                    h = addrs.front();
                if (!h.isNull())
                    Log() << hostStr << " -> " << h.toString();
            }
        }
        if (h.isNull())
            throw BadArgs(QString("Bad %1: %2").arg(allowHostNameLookup ? "host" : "interface address", hostStr));
        options->hasIPv6Listener = options->hasIPv6Listener || h.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv6Protocol;
        return {h, port};
    };
    const auto parseInterfaces = [&parseInterface](decltype(Options::interfaces) & interfaces, const QStringList & l,
                                                   bool supportsLoopbackImplicitly = false) {
        // functor parses -i and -z options, puts results in 'interfaces' passed-in reference.
        interfaces.clear();
        for (const auto & s : l)
            interfaces.push_back(parseInterface(s, supportsLoopbackImplicitly));
    };

    // grab datadir, check it's good, create it if needed
    options->datadir = conf.value("datadir", parser.value("D"));
    QFileInfo fi(options->datadir);
    if (auto path = fi.canonicalFilePath(); fi.exists()) {
        if (!fi.isDir()) // was a file and not a directory
            throw BadArgs(QString("The specified path \"%1\" already exists but is not a directory").arg(path));
        if (!fi.isReadable() || !fi.isExecutable() || !fi.isWritable())
            throw BadArgs(QString("Bad permissions for path \"%1\" (must be readable, writable, and executable)").arg(path));
        Util::AsyncOnObject(this, [path]{ Debug() << "datadir: " << path; }); // log this after return to event loop so it ends up in syslog (if -S mode)
    } else { // !exists
        if (!QDir().mkpath(options->datadir))
            throw BadArgs(QString("Unable to create directory: %1").arg(options->datadir));
        path = QFileInfo(options->datadir).canonicalFilePath();
        // log this after return to event loop so it ends up in syslog (in case user specified -S mode)
        Util::AsyncOnObject(this, [path]{ Debug() << "datadir: Created directory " << path; });
    }

    // parse bitcoind - conf.value is always unset if parser.value is set, hence this strange constrcution below (parser.value takes precedence)
    options->bdRPCInfo.hostPort = Util::ParseHostPortPair(conf.value("bitcoind", parser.value("b")));
    // --bitcoind-tls
    if ((options->bdRPCInfo.tls = parser.isSet("bitcoind-tls") || conf.boolValue("bitcoind-tls"))) {
        // check that Qt actually supports SSL since we now know that we require it to proceed
        checkSupportsSsl();
        Util::AsyncOnObject(this, []{ Debug() << "config: bitcoind-tls = true"; });
    }
    if (specifiedRpcCookie) {
        options->bdRPCInfo.setCookieFile(conf.value("rpccookie", parser.value("K")));
    } else {
        // grab rpcuser
        const QString rpcuser = conf.value("rpcuser", parser.isSet("u") ? parser.value("u") : std::getenv(RPCUSER));
        // grab rpcpass
        const QString rpcpassword = conf.value("rpcpassword", parser.isSet("p") ? parser.value("p") : std::getenv(RPCPASSWORD));
        options->bdRPCInfo.setStaticUserPass(rpcuser, rpcpassword);
    }
    bool tcpIsDefault = true;
    // grab bind (listen) interfaces for TCP -- this hard-to-read code here looks at both conf.value and parser, but conf.value only has values if parser does not (CLI parser takes precedence).
    if (auto l = conf.hasValue("tcp") ? conf.values("tcp") : parser.values("t");  !l.isEmpty()) {
        parseInterfaces(options->interfaces, l);
        tcpIsDefault = false;
        if (!options->interfaces.isEmpty())
            // save default publicTcp we will report now -- note this may get reset() to !has_value() later in
            // this function if user explicitly specified public_tcp_port=0 in the config file.
            options->publicTcp = options->interfaces.front().second;
    }
    // grab bind (listen) interfaces for WS -- this hard-to-read code here looks at both conf.value and parser, but conf.value only has values if parser does not (CLI parser takes precedence).
    if (auto l = conf.hasValue("ws") ? conf.values("ws") : parser.values("w");  !l.isEmpty()) {
        parseInterfaces(options->wsInterfaces, l);
        if (tcpIsDefault) options->interfaces.clear(); // they had default tcp setup, clear the default since they did end up specifying at least 1 real interface to bind to
        if (!options->wsInterfaces.isEmpty())
            // save default publicWs we will report now -- note this may get reset() to !has_value() later in
            // this function if user explicitly specified public_ws_port=0 in the config file.
            options->publicWs = options->wsInterfaces.front().second;
    }
    // grab bind (listen) interfaces for WSS -- this hard-to-read code here looks at both conf.value and parser, but conf.value only has values if parser does not (CLI parser takes precedence).
    if (auto l = conf.hasValue("wss") ? conf.values("wss") : parser.values("W");  !l.isEmpty()) {
        parseInterfaces(options->wssInterfaces, l);
        if (tcpIsDefault) options->interfaces.clear(); // they had default tcp setup, clear the default since they did end up specifying at least 1 real interface to bind to
        if (!options->wssInterfaces.isEmpty())
            // save default publicWss we will report now -- note this may get reset() to !has_value() later in
            // this function if user explicitly specified public_wss_port=0 in the config file.
            options->publicWss = options->wssInterfaces.front().second;
    }
    // grab bind (listen) interfaces for SSL (again, apologies for this hard to read expression below -- same comments as above apply here)
    if (auto l = conf.hasValue("ssl") ? conf.values("ssl") : parser.values("s"); !l.isEmpty()) {
        parseInterfaces(options->sslInterfaces, l);
        if (tcpIsDefault) options->interfaces.clear(); // they had default tcp setup, clear the default since they did end up specifying at least 1 real interface to bind to
        if (!options->sslInterfaces.isEmpty())
            // save default publicSsl we will report now -- note this may get reset() to !has_value() later in
            // this function if user explicitly specified public_ssl_port=0 in the config file.
            options->publicSsl = options->sslInterfaces.front().second;
    }
    // if they had either SSL or WSS, grab and validate the cert & key
    if (const bool hasSSL = !options->sslInterfaces.isEmpty(), hasWSS = !options->wssInterfaces.isEmpty(); hasSSL || hasWSS) {
        // check that Qt actually supports SSL since we now know that we require it to proceed
        checkSupportsSsl();
        QString cert    = conf.value("cert",     parser.value("c")),
                key     = conf.value("key",      parser.value("k")),
                wssCert = conf.value("wss-cert", parser.value("wss-cert")),
                wssKey  = conf.value("wss-key",  parser.value("wss-key"));
        // ensure --cert/--key and --wss-cert/--wss-key pairs are both specified together (or not specified at all)
        for (const auto & [c, k, txt] : { std::tuple(cert, key, static_cast<const char *>("`cert` and `key`")),
                                          std::tuple(wssCert, wssKey, static_cast<const char *>("`wss-cert` and `wss-key`")) }) {
            if (std::tuple(c.isEmpty(), k.isEmpty()) != std::tuple(k.isEmpty(), c.isEmpty()))
                throw BadArgs(QString("%1 must both be specified").arg(txt));
        }
        // . <-- at this point, cert.isEmpty() and/or wssCert.isEmpty() are synonymous for both the cert/key pair being either empty or non-empty

        // The rules are:  Default to using -c and -k.  (both must be present)
        // If they are using wss, allow --wss-cert and --wss-key (both must be present)
        // If the only secure port is wss, allow -c/-k to be missing (use --wss-cert and --wss-key instead).
        // Otherwise if no cert and key combo, throw.
        if ( cert.isEmpty() && (hasSSL || wssCert.isEmpty()) )  {
            throw BadArgs(QString("%1 option requires both -c/--cert and -k/--key options be specified")
                          .arg(hasSSL ? "SSL" : "WSS"));
        }
        // if they are using the wss-port and wss-key options, they *better* have a wss port
        if ( !wssCert.isEmpty() && !hasWSS )
            throw BadArgs("wss-cert option specified but no WSS listening ports defined");

        // This sets up the actual ssl certificates, and also starts the monitoring task to
        // detect filesystem changes. Below may throw if there is a problem reading/processing
        // the certs.
        if (!sslCertMonitor) sslCertMonitor = std::make_unique<SSLCertMonitor>(options, this);
        sslCertMonitor->start(cert, key, wssCert, wssKey);
    }
    // stats port -- this supports <port> by itself as well
    parseInterfaces(options->statsInterfaces, conf.hasValue("stats")
                                              ? conf.values("stats")
                                              : parser.values("z"), true);
    // admin port -- this supports <port> by itself as well
    parseInterfaces(options->adminInterfaces, conf.hasValue("admin")
                                              ? conf.values("admin")
                                              : parser.values("a"), true);
    // warn user if any of the admin rpc services are on non-loopback
    for (const auto &iface : options->adminInterfaces) {
        if (!iface.first.isLoopback()) {
            // print the warning later when logger is up
            Util::AsyncOnObject(this, [iface]{
                Warning() << "Warning: Binding admin RPC port to non-loopback interface " << iface.first.toString() << ":" << iface.second << " is not recommended. Please ensure that this port is not globally reachable from the internet.";
            });
        }
    }

    /// misc conf-only variables ...
    if (conf.hasValue("donation")) {
        options->donationAddress = conf.value("donation", options->donationAddress).left(80); // the 80 character limit is in case the user specified a crazy long string, no need to send all of it -- it's probably invalid anyway.
        options->isDefaultDonationAddress = false; // turns off the auto-transform mechanism for the author's address.
    }
    options->bannerFile = conf.value("banner", options->bannerFile);
    if (conf.hasValue("hostname"))
        options->hostName = conf.value("hostname");
    if (conf.hasValue("public_tcp_port")) {
        bool ok = false;
        int val = conf.intValue("public_tcp_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("public_tcp_port parse error: not an integer from 0 to 65535");
        if (!val) options->publicTcp.reset();
        else options->publicTcp = val;
    }
    if (conf.hasValue("public_ssl_port")) {
        bool ok = false;
        int val = conf.intValue("public_ssl_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("public_ssl_port parse error: not an integer from 0 to 65535");
        if (!val) options->publicSsl.reset();
        else options->publicSsl = val;
    }
    if (conf.hasValue("public_ws_port")) {
        bool ok = false;
        int val = conf.intValue("public_ws_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("public_ws_port parse error: not an integer from 0 to 65535");
        if (!val) options->publicWs.reset();
        else options->publicWs = val;
    }
    if (conf.hasValue("public_wss_port")) {
        bool ok = false;
        int val = conf.intValue("public_wss_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("public_wss_port parse error: not an integer from 0 to 65535");
        if (!val) options->publicWss.reset();
        else options->publicWss = val;
    }
    const auto ConfParseBool = [conf](const QString &key, bool def = false) -> bool {
        if (!conf.hasValue(key)) return def;
        const QString str = conf.value(key);
        return (str.toInt() || QStringList{{"yes","true","on",""}}.contains(str.toLower()));
    };
    options->peerDiscovery = ConfParseBool("peering", options->peerDiscovery);
    // set default first.. which is if we have hostName defined and peerDiscovery enabled
    options->peerAnnounceSelf = options->hostName.has_value() && options->peerDiscovery;
    // now set from conf fiel, specifying our default
    options->peerAnnounceSelf = ConfParseBool("announce", options->peerAnnounceSelf);
    // 'peering_enforce_unique_ip'
    options->peeringEnforceUniqueIPs = ConfParseBool("peering_enforce_unique_ip", options->peeringEnforceUniqueIPs);

    if (conf.hasValue("max_clients_per_ip")) {
        bool ok = false;
        options->maxClientsPerIP = conf.intValue("max_clients_per_ip", 0, &ok);
        if (const auto val = conf.value("max_clients_per_ip");  !ok && !val.isEmpty())
            throw BadArgs(QString("max_clients_per_ip parse error: cannot parse '%1' as an integer").arg(val));
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [this]{
            Debug() << "config: max_clients_per_ip = "
                    << (options->maxClientsPerIP > 0 ? QString::number(options->maxClientsPerIP) : "Unlimited");
        });
    }
    if (conf.hasValue("subnets_to_exclude_from_per_ip_limits")) {
        options->subnetsExcludedFromPerIPLimits.clear();
        const auto sl = conf.value("subnets_to_exclude_from_per_ip_limits").split(",");
        QStringList parsed;
        for (const auto & s : sl) {
            if (s.isEmpty())
                continue;
            auto subnet = Options::Subnet::fromString(s);
            if (!subnet.isValid())
                throw BadArgs(QString("subnets_to_exclude_from_per_ip_limits: Failed to parse %1").arg(s));
            options->subnetsExcludedFromPerIPLimits.push_back(subnet);
            parsed.push_back(subnet.toString());
        }
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [parsed]{
            Debug() << "config: subnets_to_exclude_from_per_ip_limits = " << (parsed.isEmpty() ? "None" : parsed.join(", "));
        });
    }
    if (conf.hasValue("max_history")) {
        bool ok;
        int mh = conf.intValue("max_history", -1, &ok);
        if (!ok || mh < options->maxHistoryMin || mh > options->maxHistoryMax)
            throw BadArgs(QString("max_history: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->maxHistoryMin).arg(options->maxHistoryMax));
        options->maxHistory = mh;
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [mh]{ Debug() << "config: max_history = " << mh; });
    }
    if (conf.hasValue("max_buffer")) {
        bool ok;
        int mb = conf.intValue("max_buffer", -1, &ok);
        if (!ok || !options->isMaxBufferSettingInBounds(mb))
            throw BadArgs(QString("max_buffer: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->maxBufferMin).arg(options->maxBufferMax));
        options->maxBuffer.store( mb );
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [mb]{ Debug() << "config: max_buffer = " << mb; });
    }
    // pick up 'workqueue' and 'worker_threads' optional conf params
    if (conf.hasValue("workqueue")) {
        bool ok;
        int val = conf.intValue("workqueue", 0, &ok);
        if (!ok || val < 10)
            throw BadArgs("workqueue: bad value. Specify an integer >= 10");
        if (!tpool->setExtantJobLimit(val))
            throw BadArgs(QString("workqueue: Unable to set workqueue to %1; SetExtantJobLimit returned false.").arg(val));
        options->workQueue = val; // save advisory value for stats(), etc code
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [this]{ Debug() << "config: workqueue = " << tpool->extantJobLimit(); });
    } else
        options->workQueue = tpool->extantJobLimit(); // so stats() knows what was auto-configured
    if (conf.hasValue("worker_threads")) {
        bool ok;
        int val = conf.intValue("worker_threads", 0, &ok);
        if (!ok || val < 0)
            throw BadArgs("worker_threads: bad value. Specify an integer >= 0");
        if (val > int(Util::getNVirtualProcessors()))
            throw BadArgs(QString("worker_threads: Specified value of %1 exceeds the detected number of virtual processors of %2")
                          .arg(val).arg(Util::getNVirtualProcessors()));
        if (val > 0 && !tpool->setMaxThreadCount(val))
            throw BadArgs(QString("worker_threads: Unable to set worker threads to %1").arg(val));
        options->workerThreads = val; // save advisory value for stats(), etc code
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [val,this]{ Debug() << "config: worker_threads = " << val << " (configured: " << tpool->maxThreadCount() << ")"; });
    } else
        options->workerThreads = tpool->maxThreadCount(); // so stats() knows what was auto-configured
    // max_pending_connections
    if (conf.hasValue("max_pending_connections")) {
        bool ok;
        auto val = conf.intValue("max_pending_connections", options->maxPendingConnections, &ok);
        if (!ok || val < options->minMaxPendingConnections || val > options->maxMaxPendingConnections)
            throw BadArgs(QString("max_pending_connections: Please specify an integer in the range [%1, %2]")
                          .arg(options->minMaxPendingConnections).arg(options->maxMaxPendingConnections));
        options->maxPendingConnections = val;
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [val]{ Debug() << "config: max_pending_connections = " << val; });
    }

    // handle tor-related params: tor_hostname, tor_banner, tor_tcp_port, tor_ssl_port, tor_proxy, tor_user, tor_pass
    if (const auto thn = conf.value("tor_hostname").toLower(); !thn.isEmpty()) {
        options->torHostName = thn;
        if (!thn.endsWith(".onion"))
            throw BadArgs(QString("Bad tor_hostname specified: must end with .onion: %1").arg(thn));
        Util::AsyncOnObject(this, [thn]{ Debug() << "config: tor_hostname = " << thn; });
    }
    if (conf.hasValue("tor_banner")) {
        const auto banner = conf.value("tor_banner");
        options->torBannerFile = banner;
        Util::AsyncOnObject(this, [banner]{ Debug() << "config: tor_banner = " << banner; });
    }
    if (conf.hasValue("tor_tcp_port")) {
        bool ok = false;
        int val = conf.intValue("tor_tcp_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("tor_tcp_port parse error: not an integer from 0 to 65535");
        if (!val) options->torTcp.reset();
        else {
            options->torTcp = val;
            Util::AsyncOnObject(this, [val]{ Debug() << "config: tor_tcp_port = " << val; });
        }
    }
    if (conf.hasValue("tor_ssl_port")) {
        bool ok = false;
        int val = conf.intValue("tor_ssl_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("torc_ssl_port parse error: not an integer from 0 to 65535");
        if (!val) options->torSsl.reset();
        else {
            options->torSsl = val;
            Util::AsyncOnObject(this, [val]{ Debug() << "config: tor_ssl_port = " << val; });
        }
    }
    if (conf.hasValue("tor_ws_port")) {
        bool ok = false;
        int val = conf.intValue("tor_ws_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("tor_ws_port parse error: not an integer from 0 to 65535");
        if (!val) options->torWs.reset();
        else {
            options->torWs = val;
            Util::AsyncOnObject(this, [val]{ Debug() << "config: tor_ws_port = " << val; });
        }
    }
    if (conf.hasValue("tor_wss_port")) {
        bool ok = false;
        int val = conf.intValue("tor_wss_port", -1, &ok);
        if (!ok || val < 0 || val > UINT16_MAX)
            throw BadArgs("tor_wss_port parse error: not an integer from 0 to 65535");
        if (!val) options->torWss.reset();
        else {
            options->torWss = val;
            Util::AsyncOnObject(this, [val]{ Debug() << "config: tor_wss_port = " << val; });
        }
    }
    if (conf.hasValue("tor_proxy")) {
        options->torProxy = parseInterface(conf.value("tor_proxy"), true, true /* allow hostname lookups */); // may throw if bad
        Util::AsyncOnObject(this, [val=options->torProxy]{ Debug() << "config: tor_proxy = " << val.first.toString() << ":" << val.second; });
    }
    if (conf.hasValue("tor_user")) {
        options->torUser = conf.value("tor_user");
        Util::AsyncOnObject(this, [val=options->torUser]{ Debug() << "config: tor_user = " << val; });
    }
    if (conf.hasValue("tor_pass")) {
        options->torUser = conf.value("tor_pass");
        Util::AsyncOnObject(this, []{ Debug() << "config: tor_pass = <hidden>"; });
    }
    // /Tor params

    if (conf.hasValue("bitcoind_throttle")) {
        const QStringList vals = conf.value("bitcoind_throttle").trimmed().simplified().split(QRegularExpression("\\W+"), Compat::SplitBehaviorSkipEmptyParts);
        constexpr size_t N = 3;
        std::array<int, N> parsed = {0,0,0};
        size_t i = 0;
        bool ok = false;
        for (const auto & val : vals) {
            if (i >= N) { ok = false; break; }
            parsed[i++] = val.toInt(&ok);
            if (!ok) break;
        }
        Options::BdReqThrottleParams p { parsed[0], parsed[1], parsed[2] };
        ok = ok && i == N && p.isValid();
        if (!ok)
            // failed to parse.. abort...
            throw BadArgs("Failed to parse \"bitcoind_throttle\" -- out of range or invalid format. Please specify 3 positive integers in range.");
        options->bdReqThrottleParams.store(p);
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [p]{ Debug() << "config: bitcoind_throttle = " << QString("(hi: %1, lo: %2, decay: %3)").arg(p.hi).arg(p.lo).arg(p.decay); });
    }
    if (conf.hasValue("max_subs_per_ip")) {
        bool ok;
        const int64_t subs = conf.int64Value("max_subs_per_ip", -1, &ok);
        if (!ok || !options->isMaxSubsPerIPSettingInBounds(subs))
            throw BadArgs(QString("max_subs_per_ip: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->maxSubsPerIPMin).arg(options->maxSubsPerIPMax));
        options->maxSubsPerIP = subs;
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [subs]{ Debug() << "config: max_subs_per_ip = " << subs; });
    }
    if (conf.hasValue("max_subs")) {
        bool ok;
        const int64_t subs = conf.int64Value("max_subs", -1, &ok);
        if (!ok || !options->isMaxSubsGloballySettingInBounds(subs))
            throw BadArgs(QString("max_subs: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->maxSubsGloballyMin).arg(options->maxSubsGloballyMax));
        options->maxSubsGlobally = subs;
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [subs]{ Debug() << "config: max_subs = " << subs; });
    }

    // DB options
    if (conf.hasValue("db_max_open_files")) {
        bool ok;
        const int64_t mof = conf.int64Value("db_max_open_files", 0, &ok);
        if (!ok || !options->db.isMaxOpenFilesSettingInBounds(mof))
            throw BadArgs(QString("db_max_open_files: bad value. Specify a value in the range [%1, %2] or -1.")
                          .arg(options->db.maxOpenFilesMin).arg(options->db.maxOpenFilesMax));
        options->db.maxOpenFiles = int(mof);
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [mof]{ Debug() << "config: db_max_open_files = " << mof; });
    }
    if (conf.hasValue("db_keep_log_file_num")) {
        bool ok;
        const int64_t klfn = conf.int64Value("db_keep_log_file_num", -1, &ok);
        if (!ok || !options->db.isKeepLogFileNumInBounds(klfn))
            throw BadArgs(QString("db_keep_log_file_num: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->db.minKeepLogFileNum).arg(options->db.maxKeepLogFileNum));
        options->db.keepLogFileNum = unsigned(klfn);
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [klfn]{ Debug() << "config: db_keep_log_file_num = " << klfn; });
    }
    if (conf.hasValue("db_mem")) {
        bool ok;
        const double mb = conf.doubleValue("db_mem", options->db.defaultMaxMem, &ok);
        if (const size_t bytes = mb*size_t(1024*1024); !ok || mb < 0. || !options->db.isMaxMemInBounds(bytes))
            throw BadArgs(QString("db_mem: bad value. Specify a value in the range [%1, %2]")
                          .arg(options->db.maxMemMin / 1024. / 1024., 0, 'f', 1).arg(options->db.maxMemMax / 1024. / 1024., 0, 'f', 1));
        else {
            options->db.maxMem = bytes;
            // log this later in case we are in syslog mode
            Util::AsyncOnObject(this, [mb]{ Debug() << "config: db_mem = " << mb; });
        }
    }
    if (conf.hasValue("db_use_fsync")) {
        bool ok;
        const bool val = conf.boolValue("db_use_fsync", options->db.defaultUseFsync, &ok);
        if (!ok)
            throw BadArgs("db_use_fsync: bad value. Specify a boolean value such as 0, 1, true, false, yes, no");
        options->db.useFsync = val;
        // log this later in case we are in syslog mode
        Util::AsyncOnObject(this, [val]{ Debug() << "config: db_use_fsync = " << (val ? "true" : "false"); });
    }

    // warn user that no hostname was specified if they have peerDiscover turned on
    if (!options->hostName.has_value() && options->peerDiscovery && options->peerAnnounceSelf) {
        // do this when we return to event loop in case user is logging to -S (so it appears in syslog which gets set up after we return)
        Util::AsyncOnObject(this, []{
            Warning() << "Warning: No 'hostname' variable defined in configuration. This server may not be peer-discoverable.";
        });
    }

    // parse --ts-format or ts-format= from conf (ts_format also supported from conf)
    if (auto fmt = parser.value("ts-format");
            !fmt.isEmpty() || !(fmt = conf.value("ts-format")).isEmpty() || !(fmt = conf.value("ts_format")).isEmpty()) {
        fmt = fmt.toLower().trimmed();
        if (fmt == "uptime" || fmt == "abs" || fmt == "abstime")
            options->logTimestampMode = Options::LogTimestampMode::Uptime;
        else if (fmt.startsWith("local"))
            options->logTimestampMode = Options::LogTimestampMode::Local;
        else if (fmt == "utc")
            options->logTimestampMode = Options::LogTimestampMode::UTC;
        else if (fmt == "none")
            options->logTimestampMode = Options::LogTimestampMode::None;
        else
            throw BadArgs(QString("ts-format: unrecognized value \"%1\"").arg(fmt));
        Util::AsyncOnObject(this, [this]{ DebugM("config: ts-format = ", options->logTimestampModeString()); });
    }
#ifdef Q_OS_UNIX
    else if (options->syslogMode) {
        options->logTimestampMode = Options::LogTimestampMode::None;
        Util::AsyncOnObject(this, []{ DebugM("syslog mode enabled, defaulting to \"--ts-format none\""); });
    }
#endif

    // --tls-disallow-deprecated from CLI and/or tls-disallow-deprecated from conf
    if (parser.isSet("tls-disallow-deprecated") || conf.boolValue("tls-disallow-deprecated")) {
        options->tlsDisallowDeprecated = true;
        Util::AsyncOnObject(this, []{ Log() << "TLS restricted to non-deprecated versions (version 1.2 or above)"; });
    }

    // --no-simdjson from CLI or simdjson=bool from conf -- note as of Fulcrum v1.3.0 we default simdjson to enabled
    {
        const bool clinosj = parser.isSet("no-simdjson"), confnosj = !conf.boolValue("simdjson", true),
                   enabled = !(clinosj || confnosj);

        // We do this on an asynch task since this call may log, and we wish to log later after startup
        // in case we are in --syslog mode.
        Util::AsyncOnObject(this, [enabled] {
            Debug() << "config: simdjson = " << (enabled ? "true" : "false");
            Options::setSimdJson(enabled, true);
        });
    }

    // --bd-timeout on CLI or bitcoind_timeout from conf
    if (const bool pset = parser.isSet("bd-timeout"); pset || conf.hasValue("bitcoind_timeout")) {
        bool ok{};
        const auto name = pset ? "bd-timeout" : "bitcoind_timeout";
        const int msec = int(1e3 * (pset ? parser.value("bd-timeout").toDouble(&ok)
                                         : conf.doubleValue("bitcoind_timeout", 0., &ok)));
        if (!ok || !options->isBdTimeoutInRange(msec))
            throw BadArgs(QString("%1: please specify a value in the range [%2, %3]").arg(name)
                          .arg(options->bdTimeoutMin/1e3).arg(options->bdTimeoutMax/1e3));
        options->bdTimeoutMS = msec;
        Util::AsyncOnObject(this, [secs=msec/1e3, name]{ DebugM("config: ", name, " = ", QString::number(secs, 'f', 3)); });
    }

    // --bd-clients on CLI or bitcoind_clients from conf
    if (const bool pset = parser.isSet("bd-clients"); pset || conf.hasValue("bitcoind_clients")) {
        bool ok{};
        const auto name = pset ? "bd-clients" : "bitcoind_clients";
        const unsigned n = pset ? parser.value("bd-clients").toUInt(&ok)
                                : unsigned(conf.intValue("bitcoind_clients", 0, &ok));
        if (!ok || !options->isBdNClientsInRange(n))
            throw BadArgs(QString("%1: please specify a value in the range [%2, %3]").arg(name)
                          .arg(options->bdNClientsMin).arg(options->bdNClientsMax));
        options->bdNClients = n;
        Util::AsyncOnObject(this, [n, name]{ DebugM("config: ", name, " = ", n); });
    }

    // conf: max_reorg
    if (conf.hasValue("max_reorg")) {
        bool ok{};
        const unsigned val = unsigned(conf.intValue("max_reorg", Options::defaultMaxReorg, &ok));
        if (!ok || !options->isMaxReorgInRange(val))
            throw BadArgs(QString("max_reorg: please specify a value in the range [%1, %2]")
                          .arg(options->maxReorgMin).arg(options->maxReorgMax));
        options->maxReorg = val;
        Util::AsyncOnObject(this, [val]{ DebugM("config: max_reorg = ", val); });
    }

    // conf: txhash_cache
    if (conf.hasValue("txhash_cache")) {
        bool ok{};
        // NB: units in conf file are in MB (1e6), but we store them in bytes internally.
        const unsigned val = unsigned(conf.doubleValue("txhash_cache", Options::defaultTxHashCacheBytes / 1e6, &ok) * 1e6);
        if (!ok || !options->isTxHashCacheBytesInRange(val))
            throw BadArgs(QString("txhash_cache: please specify a value in the range [%1, %2]")
                          .arg(options->txHashCacheBytesMin/1e6).arg(options->txHashCacheBytesMax/1e6));
        options->txHashCacheBytes = val;
        Util::AsyncOnObject(this, [val=val/1e6]{ DebugM("config: txhash_cache = ", val); });
    }

    // CLI: --compact-dbs
    if (parser.isSet("compact-dbs")) {
        options->compactDBs = true;
        Util::AsyncOnObject(this, []{ DebugM("config: compact-dbs = true"); });
    }

    // conf: max_batch
    if (conf.hasValue("max_batch")) {
        bool ok{};
        const unsigned val = unsigned(conf.intValue("max_batch", Options::defaultMaxBatch, &ok));
        if (!ok || !options->isMaxBatchInRange(val))
            throw BadArgs(QString("max_batch: please specify a value in the range [%1, %2]")
                          .arg(options->maxBatchMin).arg(options->maxBatchMax));
        options->maxBatch = val;
        Util::AsyncOnObject(this, [val]{ DebugM("config: max_batch = ", val); });
    }

    // parse --dump-*
    if (const auto outFile = parser.value("dump-sh"); !outFile.isEmpty()) {
        options->dumpScriptHashes = outFile; // we do no checking here, but Controller::startup will throw BadArgs if it cannot open this file for writing.
    }

    // CLI: --fast-sync (experimental)
    // conf: fast-sync
    if (const bool pset = parser.isSet("fast-sync"); pset || conf.hasValue("fast-sync")) {
        bool ok{};
        const QString strVal = pset ? parser.value("fast-sync") : conf.value("fast-sync");
        const double val = strVal.toDouble(&ok);
        if (!ok || val < 0.)
            throw BadArgs(QString("fast-sync: Slease specify a positive numeric value in MB, or 0 to disable"));
        const uint64_t bytes = static_cast<uint64_t>(val * 1e6);
        if (uint64_t memfree; bytes > (memfree = std::min<uint64_t>(Util::getAvailablePhysicalRAM(), std::numeric_limits<size_t>::max())))
            throw BadArgs(QString("fast-sync: Specified value (%1 bytes) is too large to fit in available"
                                  " system memory (limit is: %2 bytes)").arg(bytes).arg(qulonglong(memfree)));
        else if (bytes > 0 && bytes < Options::minUtxoCache)
            throw BadArgs(QString("fast-sync: Specified value %1 is too small (minimum: %2 MB)")
                          .arg(strVal, QString::number(Options::minUtxoCache / 1e6, 'f', 1)));
        options->utxoCache = static_cast<size_t>(bytes);
    }
}

namespace {
    auto ParseParams(const SimpleHttpServer::Request &req) -> StatsMixin::StatsParams {
        StatsMixin::StatsParams params;
        const auto nvps = req.queryString.split('&');
        for (const auto & nvp : nvps) {
            auto nv = nvp.split('=');
            if (nv.size() == 2)
                params[nv.front()] = nv.back();
        }
        return params;
    }
}

void App::start_httpServer(const Options::Interface &iface)
{
    std::shared_ptr<SimpleHttpServer> server(new SimpleHttpServer(iface.first, iface.second, 16384));
    httpServers.push_back(server);
    server->tryStart(); // may throw, waits for server to start
    server->set404Message("Error: Unknown endpoint. /stats & /debug are the only valid endpoint I understand.\r\n");
    static const auto CRLF = QByteArrayLiteral("\r\n");
    server->addEndpoint("/stats",[this](SimpleHttpServer::Request &req){
        req.response.contentType = "application/json; charset=utf-8";
        auto stats = controller->statsSafe();
        stats = stats.isNull() ? QVariantList{QVariant()} : stats;
        req.response.data = Json::toUtf8(stats, false) + CRLF; // may throw -- calling code will handle exception
    });
    server->addEndpoint("/debug",[this](SimpleHttpServer::Request &req){
        req.response.contentType = "application/json; charset=utf-8";
        const auto params = ParseParams(req);
        auto stats = controller->debugSafe(params);
        stats = stats.isNull() ? QVariantList{QVariant()} : stats;
        req.response.data = Json::toUtf8(stats, false) + CRLF; // may throw -- caller will handle exception
    });
}

/* static */ App::QtLogSuppressionList App::qlSuppressions;
/* static */ std::shared_mutex App::qlSuppressionsMut;

/* static */
auto App::addQtLogSuppression(const QString &s) -> QtLogSuppression {
    std::unique_lock l(qlSuppressionsMut);
    qlSuppressions.push_front(s);
    return qlSuppressions.begin();
}

/* static */
void App::rmQtLogSuppression(QtLogSuppression &it) {
    std::unique_lock l(qlSuppressionsMut);
    qlSuppressions.erase(it);
    it = qlSuppressions.end(); // invalidate
}

/* static */
void App::customQtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    // suppressions
    if ( msg.contains(QStringLiteral("QSslCertificate::isSelfSigned"))
         || msg.contains(QStringLiteral("Type conversion already registered"))
         // The below-two are safe to ignore. See: https://github.com/cculianu/Fulcrum/issues/132
         || msg.contains(QStringLiteral("cannot call unresolved function SSL_get_peer_certificate"))
         || msg.contains(QStringLiteral("cannot call unresolved function EVP_PKEY_base_id"))
         )
        return;
    {  // client-code specified suppressions, if any
        std::shared_lock l(qlSuppressionsMut);
        for (const auto &str : qlSuppressions)
            if (msg.contains(str))
                return; // filter
    }
    // /suppressions

    const QByteArray umsg = msg.toUtf8();
    const char *file = context.file ? context.file : "";
    const char *function = context.function ? context.function : "";

    switch (type) {
    case QtDebugMsg:
        DebugM("[Qt] ", umsg.constData(), " (", file, ":", context.line, ", ", function, ")");
        break;
    case QtInfoMsg:
        Log("[Qt] %s (%s:%d, %s)", umsg.constData(), file, context.line, function);
        break;
    case QtWarningMsg:
        Warning("[Qt Warning] %s (%s:%d, %s)", umsg.constData(), file, context.line, function);
        break;
    case QtCriticalMsg:
        Error("[Qt Critical] %s (%s:%d, %s)", umsg.constData(), file, context.line, function);
        break;
    case QtFatalMsg:
        Error("[Qt Fatal] %s (%s:%d, %s)", umsg.constData(), file, context.line, function);
        break;
    }
}

void App::miscPreAppFixups()
{
    qInstallMessageHandler(customQtMessageHandler);
#ifdef Q_OS_DARWIN
    // workaround for annoying macos keychain access prompt. see: https://doc.qt.io/qt-5/qsslsocket.html#setLocalCertificate
    setenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1", 1);
#endif
}

void App::on_setVerboseDebug(bool b)
{
    options->verboseDebug = b;
    if (!b)
        options->verboseTrace = false;
}
void App::on_setVerboseTrace(bool b)
{
    options->verboseTrace = b;
    if (b)
        options->verboseDebug = true;
}

void App::on_requestMaxBufferChange(int m)
{
    if (Options::isMaxBufferSettingInBounds(m))
        options->maxBuffer.store( Options::clampMaxBufferSetting(m) );
    else
        Warning() << __func__ << ": " << m << " is out of range, ignoring new max_buffer setting";
}

void App::on_bitcoindThrottleParamsChange(int hi, int lo, int decay)
{
    Options::BdReqThrottleParams p{hi, lo, decay};
    if (p.isValid())
        options->bdReqThrottleParams.store(p);
    else
        Warning() << __func__ << ": arguments out of range, ignoring new bitcoind_throttle setting";
}

/* static */
std::unique_ptr<std::map<QString, std::function<void()>>> App::registeredTests, App::registeredBenches;

/* static */
void App::registerTestBenchCommon(const char *fname, const char *brief, NameFuncMapPtr &map,
                                  const NameFuncMap::key_type &name, const NameFuncMap::mapped_type &func)
{
    if (globalInstance()) {
        Error() << fname << " cannot be called after the app has already started!"
                << " Ignoring request to register " << brief << " \"" << name << "\"";
        return;
    }
    if (!map) map = std::make_unique<NameFuncMap>(); // construct the map the first time through
    const auto & [it, inserted] = map->insert({name, func});
    if (!inserted)
        Error() << fname << ": ignoring duplicate " << brief << " \"" << name << "\"";
}

/* static */
auto App::registerTest(const QString &name, const std::function<void()> &func) -> RegisteredTest
{
    registerTestBenchCommon(__func__, "test", registeredTests, name, func);
    return {};
}

/* static */
auto App::registerBench(const QString &name, const std::function<void()> &func) -> RegisteredBench
{
    registerTestBenchCommon(__func__, "bench", registeredBenches, name, func);
    return {};
}

void App::setCLocale()
{
    try {
        QLocale::setDefault(QLocale::c());
        std::setlocale(LC_ALL, "C");
        std::setlocale(LC_NUMERIC, "C");
        std::locale::global(std::locale::classic());
    } catch (const std::exception &e) {
        Warning() << "Failed to set \"C\" locale: " << e.what();
    }
    try {
        // Also for paranoia call into the Json lib's own locale checker / setter.
        Json::checkLocale(true);
        // We don't need this check each time we parse since once set, it won't change in this app.
        Json::autoFixLocale = false;
    } catch (const std::exception &e) {
        Warning() << e.what();
    }
}


#if HAVE_JEMALLOC_HEADERS
#define JEMALLOC_NO_DEMANGLE
#include <jemalloc/jemalloc.h>
/* static */
QVariantMap App::jemallocStats()
{
    static const auto cb = [](void *ptr, const char *str) {
        QByteArray &buffer = *reinterpret_cast<QByteArray *>(reinterpret_cast<char *>(ptr));
        buffer += QByteArray(str);
    };
    QByteArray buffer;
    je_malloc_stats_print(cb, reinterpret_cast<void *>(reinterpret_cast<char *>(&buffer)), "Jmdax");
    QVariantMap m;
    try {
        m = Json::parseUtf8(buffer, Json::ParseOption::RequireObject).toMap();
        if (m.size() == 1) {
            // modify stats a little bit to be less verbose and less nested...
            if (const auto submap = m.take("jemalloc");
                    !submap.isNull() && submap.canConvert<QVariantMap>()) {
                // bring the single "jemalloc" submap up to top level
                m = submap.toMap();
                // find and delete the huge "bin" and "lextents" array that we don't need
                if (const auto arenasV = m.take("arenas");
                        !arenasV.isNull() && arenasV.canConvert<QVariantMap>()) {
                    auto arenas = arenasV.toMap();
                    // I can't figure out how to suppress these two in the options...
                    arenas.remove("bin");
                    arenas.remove("lextent");
                    m["arenas"] = arenas;
                }
            }
        }
    } catch (const std::exception &e) {
        m["raw"] = buffer;
        m["parse error"] = QString(e.what());
    }
    return m;
}
#undef JEMALLOC_NO_DEMANGLE
#else
/* static */
QVariantMap App::jemallocStats() { return {}; }
#endif

QVariantMap App::simdJsonStats()
{
    QVariantMap ret;
    auto info = Json::SimdJson::getInfo();
    if (info) {
        QVariantMap m;
        for (const auto & imp : info->implementations) {
            QVariantMap m2;
            m2["description"] = imp.description;
            m2["supported"] = imp.supported;
            m[imp.name] = m2;
        }
        ret["implementations"] = m;
        ret["active_implementation"] = Options::isSimdJson() ? info->active.name : QVariant();
    }
    return ret;
}

/* static */
bool App::logSimdJsonInfo()
{
    auto info = Json::SimdJson::getInfo();
    if (!info)
        // simdjson not available
        return false;
    Log() << "simdjson implementations:";
    for (const auto & imp : info->implementations) {
        Log() << "    " << imp.name << ": " << imp.description
              << (imp.supported ? "  [supported]" : "  [not supported]");
    }
    Log() << "active implementation: " << info->active.name;
    return true;
}

/* static */
QString App::extendedVersionString(bool justLibs)
{
    QString ret;
    const QString kUnavailable{"unavailable"};
    QTextStream ts(&ret, QIODevice::WriteOnly);
    auto getCompiler = [] {
        QString compiler;
#ifdef __clang_version__
        compiler = QString("clang ") + __clang_version__;
#elif defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
        compiler = QString("gcc %1.%2.%3").arg(__GNUC__).arg(__GNUC_MINOR__).arg(__GNUC_PATCHLEVEL__);
#endif
        return compiler;
    };

    if (!justLibs) {
        ts << applicationName() << " " << applicationVersion() << "\n";
        ts << "Protocol: version min: " << ServerMisc::MinProtocolVersion.toString()
           << ", version max: " << ServerMisc::MaxProtocolVersion.toString() << "\n";
        if (auto compiler = getCompiler(); !compiler.isEmpty())
            ts << "compiled: " << compiler << "\n";
    }

    ts << "jemalloc: ";
    if (auto v = jemallocStats().value("version").toString(); !v.isEmpty()) {
        if (v.contains("-g")) {
            // simplify: 5.2.1-0-gea6b3e973b477b8061e0076bb257dbd7f3faa756 -> 5.2.1-0-gea6b3e9
            const auto parts = v.split("-g");
            if (parts.length() > 1)
                v = (parts.mid(0, parts.length()-1) + QStringList{{parts.back().left(7)}}).join("-g");
        }
        ts << "version " << v;
    } else
        ts << kUnavailable;
    ts << "\n";

    ts << "Qt: version " << QLibraryInfo::version().toString() << "\n";

    ts << "rocksdb: version " << Storage::rocksdbVersion() << "\n";

    ts << "simdjson: ";
    if (auto v = Json::SimdJson::versionString(); !v.isEmpty())
        ts << "version " << v;
    else
        ts << kUnavailable;
    ts << "\n";

    ts << "ssl: ";
    if (QString v; QSslSocket::supportsSsl() && !(v = QSslSocket::sslLibraryVersionString()).isEmpty())
        ts << v;
    else
        ts << kUnavailable;
    ts << "\n";

    ts << "zmq: ";
    if (auto v = ZmqSubNotifier::versionString(); !v.isEmpty())
        ts << v;
    else
        ts << kUnavailable;
    ts << "\n";

    return ret;
}
