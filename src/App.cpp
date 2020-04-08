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
#include "App.h"
#include "BTC.h"
#include "Controller.h"
#include "Logger.h"
#include "Servers.h"
#include "ThreadPool.h"
#include "Util.h"

#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegExp>
#include <QSslSocket>

#include <array>
#include <csignal>
#include <cstdlib>
#include <list>
#include <tuple>

App *App::_globalInstance = nullptr;

App::App(int argc, char *argv[])
    : QCoreApplication (argc, argv), tpool(std::make_unique<ThreadPool>(this))
{
    assert(!_globalInstance);
    _globalInstance = this;
    register_MetaTypes();

    options = std::make_shared<Options>();
    options->interfaces = {{QHostAddress("0.0.0.0"), Options::DEFAULT_PORT_TCP}}; // start with default, will be cleared if -t specified
    setApplicationName(APPNAME);
    setApplicationVersion(QString("%1 %2").arg(VERSION).arg(VERSION_EXTRA));

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
    QTimer::singleShot(0, this, &App::startup); // register to run after app event loop start
}

App::~App()
{
    Debug() << "App d'tor";
    Log() << "Shudown complete";
    _globalInstance = nullptr;
    /// child objects will be auto-deleted, however most are already gone in cleanup() at this point.
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
    // schedule print banner to log every hour so admin has an idea of how log timestamps correlate to wall clock time
    callOnTimerSoon(60*60*1000, "printTimeStamp", []{ Log() << getBannerWithTimeStamp(); return true; }, false, Qt::TimerType::VeryCoarseTimer);

    if ( ! Util::isClockSteady() ) {
        Debug() << "High resolution clock provided by the std C++ library is not 'steady'. Log timestamps may drift if system time gets adjusted.";
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
            const auto num = options->statsInterfaces.count();
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
    quitting = true;
    cleanup_WaitForThreadPoolWorkers();
    if (!httpServers.isEmpty()) {
        Log("Stopping Stats HTTP Servers ...");
        for (auto h : httpServers) { h->stop(); }
        httpServers.clear(); // deletes shared pointers
    }
    if (controller) { Log("Stopping Controller ... "); controller->cleanup(); controller.reset(); }
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
    parser.setApplicationDescription("A Bitcoin Cash Blockchain SPV Server.");
    parser.addHelpOption();
    parser.addVersionOption();

    static constexpr auto RPCUSER = "RPCUSER", RPCPASSWORD = "RPCPASSWORD"; // optional env vars we use below

    QList<QCommandLineOption> allOptions{
         { { "D", "datadir" },
           QString("Specify a directory in which to store the database and other assorted data files. This is a"
           " required option. If the specified path does not exist, it will be created. Note that the directory in"
           " question should ideally live on a fast drive such as an SSD and it should have plenty of free space"
           " available."),
           QString("path"),
         },
         { { "t", "tcp" },
           QString("Specify an <interface:port> on which to listen for TCP connections, defaults to 0.0.0.0:%1 (all"
                   " interfaces, port %1 -- only if no other interfaces are specified via -t or -s)."
           " This option may be specified more than once to bind to multiple interfaces and/or ports."
           " Suggested values for port: %1 on mainnet and %2 on testnet.").arg(Options::DEFAULT_PORT_TCP).arg(Options::DEFAULT_PORT_TCP + 10000),
           QString("interface:port"),
         },
         { { "s", "ssl" },
           QString("Specify an <interface:port> on which to listen for SSL connections. Note that if this option is"
           " specified, then the `cert` and `key` options need to also be specified otherwise the app will refuse to run."
           " This option may be specified more than once to bind to multiple interfaces and/or ports."
           " Suggested values for port: %1 on mainnet and %2 on testnet.").arg(Options::DEFAULT_PORT_SSL).arg(Options::DEFAULT_PORT_SSL + 10000),
           QString("interface:port"),
         },
         { { "c", "cert" },
           QString("Specify a .crt file to use as the server's SSL cert. This option is required if the -s/--ssl option"
           " appears at all on the command-line. The file should contain a valid non-self-signed certificate in PEM format."),
           QString("crtfile"),
         },
         { { "k", "key" },
           QString("Specify a .key file to use as the server's SSL key. This option is required if the -s/--ssl option"
           " appears at all on the command-line. The file should contain an RSA private key in PEM format."),
           QString("keyfile"),
         },
        { { "a", "admin" },
          QString("Specify a <port> or an <interface:port> on which to listen for TCP connections for the admin RPC service."
                  " The admin service is used for sending special control commands to the server, such as stopping"
                  " the server, and it should *NOT* be exposed to the internet.  This option is required if you wish to"
                  " use the FulcrumAdmin CLI tool to send commands to Fulcrum. It is recommended that you specify the"
                  " loopback address as the bind interface for this option such as: <port> by itself or 127.0.0.1:<port> for"
                  " IPv4 and/or ::1:<port> for IPv6. If no interface is specified, and just a port number by itself is"
                  " used, then IPv4 127.0.0.1 is the bind interface used (along with the specified port)."
                  " This option may be specified more than once to bind to multiple interfaces and/or ports."),
          QString("[interface:]port"),
         },
         { { "z", "stats" },
           QString("Specify listen address and port for the stats HTTP server. Format is same as the -s, -t or -a options,"
           " e.g.: <interface:port>. Default is to not start any starts HTTP servers.  Also, like the -a option, you may"
           " specify a port number by itself here and 127.0.0.1:<port> will be assumed."
           " This option may be specified more than once to bind to multiple interfaces and/or ports."),
           QString("[interface:]port"),
         },
         { { "b", "bitcoind" },
           QString("Specify a <hostname:port> to connect to the bitcoind rpc service. This is a required option, along"
           " with -u and -p. This hostname:port should be the same as you specified in your bitcoin.conf file"
           " under rpcbind= and rpcport=."),
           QString("hostname:port"),
         },
         { { "u", "rpcuser" },
           QString("Specify a username to use for authenticating to bitcoind. This is a required option, along"
           " with -b and -p.  This option should be the same username you specified in your bitcoind.conf file"
           " under rpcuser=. For security, you may omit this option from the command-line and use the %1"
           " environment variable instead (the CLI arg takes precedence if both are present).").arg(RPCUSER),
           QString("username"),
         },
         { { "p", "rpcpassword" },
           QString("Specify a password to use for authenticating to bitcoind. This is a required option, along"
           " with -b and -u.  This option should be the same password you specified in your bitcoind.conf file"
           " under rpcpassword=. For security, you may omit this option from the command-line and use the"
           " %1 environment variable instead (the CLI arg takes precedence if both are present).").arg(RPCPASSWORD),
           QString("password"),
         },
         { { "d", "debug" },
           QString("Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q."
           " (Specify this options twice to get network-level trace debug output.)"),
         },
         { { "q", "quiet" },
           QString("Suppress debug output. This is the default on release builds. This is the opposite of -d."),
         },
         { { "S", "syslog" },
           QString("Syslog mode. If on Unix, use the syslog() facility to produce log messages. This option currently has no effect on Windows."),
         },
         { { "C", "checkdb" },
           QString("If specified, database consistency will be checked thoroughly for sanity & integrity."
                   " Note that these checks are somewhat slow to perform and under normal operation are not necessary."),
         },
         { { "T", "polltime" },
           QString("The number of seconds for the bitcoind poll interval. Bitcoind is polled once every `polltime`"
                   " seconds to detect mempool and blockchain changes. This value must be at least 0.5 and cannot exceed"
                   " 30. If not specified, defaults to %1 seconds.").arg(Options::defaultPollTimeSecs),
           QString("polltime"), QString::number(Options::defaultPollTimeSecs)
         },
         {
           "dump-sh",
           QString("*** This is an advanced debugging option ***   Dump script hashes. If specified, after the database"
                   " is loaded, all of the script hashes in the database will be written to outputfile as a JSON array."),
           QString("outputfile"),
         },
     };

    parser.addOptions(allOptions);
    parser.addPositionalArgument("config", "Configuration file (optional).", "[config]");
    parser.process(*this);

    ConfigFile conf;

    // First, parse config file (if specified) -- We will take whatever it specified that matches the above options
    // but CLI args take precedence over config file options.
    if (auto posArgs = parser.positionalArguments(); !posArgs.isEmpty()) {
        if (posArgs.size() > 1)
            throw BadArgs("More than 1 config file was specified.  Please specify at most 1 config file.");
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
    if (parser.isSet("C") || conf.boolValue("checkdb")) options->doSlowDbChecks = true;
    // parse --polltime
    // note despite how confusingly the below line reads, the CLI parser value takes precedence over the conf file here.
    const QString polltimeStr = conf.value("polltime", parser.value("T"));
    if (bool ok; (options->pollTimeSecs = polltimeStr.toDouble(&ok)) < options->minPollTimeSecs
            || !ok || options->pollTimeSecs > options->maxPollTimeSecs) {
        throw BadArgs(QString("The 'polltime' option must be a numeric value in the range [%1, %2]").arg(options->minPollTimeSecs).arg(options->maxPollTimeSecs));
    }
    // make sure -b -p and -u all present and specified exactly once
    using ReqOptsList = std::list<std::tuple<QString, QString, const char *>>;
    for (const auto & opt : ReqOptsList({{"D", "datadir", nullptr},
                                         {"b", "bitcoind", nullptr},
                                         {"u", "rpcuser", RPCUSER},
                                         {"p", "rpcpassword", RPCPASSWORD},}))
    {
        const auto & [s, l, env] = opt;
        const bool cliIsSet = parser.isSet(s);
        const bool confIsSet = conf.hasValue(l);
        const auto envVar = env ? std::getenv(env) : nullptr;
        if ((cliIsSet || confIsSet) && envVar)
            Warning() << "Warning: " << l <<  " is specified both via the " << (cliIsSet ? "CLI" : "config file")
                      << " and the environement (as " << env << "). The " << (cliIsSet ? "CLI arg" : "config file setting")
                      << " will take precendence.";
        if (((!cliIsSet && !confIsSet) || conf.value(l, parser.value(s)).isEmpty()) && (!env || !envVar))
            throw BadArgs(QString("Required option missing or empty: -%1 (--%2)%3").arg(s).arg(l).arg(env ? QString(" (or env var: %1)").arg(env) : ""));
        else if (parser.values(s).count() > 1)
            throw BadArgs(QString("Option specified multiple times: -%1 (--%2)").arg(s).arg(l));
        else if (conf.values(l).count() > 1)
            throw BadArgs(QString("This option cannot be specified multiple times in the config file: %1").arg(l));
    }
    static const auto parseHostnamePortPair = [](const QString &s, bool allowImplicitLoopback = false) -> QPair<QString, quint16> {
        constexpr auto parsePort = [](const QString & portStr) -> quint16 {
            bool ok;
            quint16 port = portStr.toUShort(&ok);
            if (!ok || port == 0)
                throw BadArgs(QString("Bad port: %1").arg(portStr));
            return port;
        };
        auto toks = s.split(":");
        constexpr const char *msg1 = "Malformed host:port spec. Please specify a string of the form <host>:<port>";
        if (const auto len = toks.length(); len < 2) {
            if (allowImplicitLoopback && len == 1)
                // this option allows bare port number with the implicit ipv4 127.0.0.1 -- try that (may throw if bad port number)
                return QPair<QString, quint16>{QHostAddress(QHostAddress::LocalHost).toString(), parsePort(toks.front())};
            throw BadArgs(msg1);
        }
        QString portStr = toks.last();
        toks.removeLast(); // pop off port
        QString hostStr = toks.join(":"); // rejoin on ':' in case it was IPv6 which is full of colons
        if (hostStr.isEmpty())
            throw BadArgs(msg1);
        return {hostStr, parsePort(portStr)};
    };
    const auto parseInterface = [&options = options](const QString &s, bool allowImplicitLoopback = false) -> Options::Interface {
        const auto pair = parseHostnamePortPair(s, allowImplicitLoopback);
        const auto & hostStr = pair.first;
        const auto port = pair.second;
        QHostAddress h(hostStr);
        if (h.isNull())
            throw BadArgs(QString("Bad interface address: %1").arg(hostStr));
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
    options->bitcoind = parseHostnamePortPair(conf.value("bitcoind", parser.value("b")));
    // grab rpcuser
    options->rpcuser = conf.value("rpcuser", parser.isSet("u") ? parser.value("u") : std::getenv(RPCUSER));
    // grab rpcpass
    options->rpcpassword = conf.value("rpcpassword", parser.isSet("p") ? parser.value("p") : std::getenv(RPCPASSWORD));
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
    // grab bind (listen) interfaces for SSL (again, apologies for this hard to read expression below -- same comments as above apply here)
    if (auto l = conf.hasValue("ssl") ? conf.values("ssl") : parser.values("s"); !l.isEmpty()) {
        if (!QSslSocket::supportsSsl()) {
            throw InternalError("SSL support is not compiled and/or linked to this version. Cannot proceed with SSL support. Sorry!");
        }
        parseInterfaces(options->sslInterfaces, l);
        if (tcpIsDefault) options->interfaces.clear(); // they had default tcp setup, clear the default since they did end up specifying at least 1 real interface to bind to
        if (!options->sslInterfaces.isEmpty())
            // save default publicSsl we will report now -- note this may get reset() to !has_value() later in
            // this function if user explicitly specified public_ssl_port=0 in the config file.
            options->publicSsl = options->sslInterfaces.front().second;
    }
    if (!options->sslInterfaces.isEmpty()) {
        const QString cert = conf.value("cert", parser.value("c")), key = conf.value("key", parser.value("k"));
        if (cert.isEmpty() || key.isEmpty()) {
            throw BadArgs("SSL option requires both -c/--cert and -k/--key options be specified on the command-line");
        } else if (!QFile::exists(cert)) {
            throw BadArgs(QString("Cert file not found: %1").arg(cert));
        } else if (!QFile::exists(key)) {
            throw BadArgs(QString("Key file not found: %1").arg(key));
        } else {
            QFile certf(cert), keyf(key);
            if (!certf.open(QIODevice::ReadOnly))
                throw BadArgs(QString("Unable to open cert file %1: %2").arg(cert).arg(certf.errorString()));
            if (!keyf.open(QIODevice::ReadOnly))
                throw BadArgs(QString("Unable to open key file %1: %2").arg(key).arg(keyf.errorString()));
            options->sslCert = QSslCertificate(&certf, QSsl::EncodingFormat::Pem);
            options->sslKey = QSslKey(&keyf, QSsl::KeyAlgorithm::Rsa, QSsl::EncodingFormat::Pem);
            options->certFile = cert; // this is only used for /stats port advisory info
            options->keyFile = key; // this is only used for /stats port advisory info
            if (options->sslCert.isNull())
                throw BadArgs(QString("Unable to read ssl certificate from %1. Please make sure the file is readable and "
                                      "contains a valid certificate in PEM format.").arg(cert));
            else {
                Util::AsyncOnObject(this, [this]{
                    // We do this logging later. This is to ensure that it ends up in the syslog if user specified -S
                    QString name;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
                    // Was added Qt 5.12+
                    name = options->sslCert.subjectDisplayName();
#else
                    name = options->sslCert.subjectInfo(QSslCertificate::Organization).join(", ");
#endif
                    Log() << "Loaded SSL certificate: " << name << " "
                          << options->sslCert.subjectInfo(QSslCertificate::SubjectInfo::EmailAddress).join(",")
                          //<< " self-signed: " << (options->sslCert.isSelfSigned() ? "YES" : "NO")
                          << " expires: " << (options->sslCert.expiryDate().toString("ddd MMMM d yyyy hh:mm:ss"));
                });
            }
            if (options->sslKey.isNull())
                throw BadArgs(QString("Unable to read private key from %1. Please make sure the file is readable and "
                                      "contains a single RSA private key in PEM format.").arg(key));
            static const auto KeyAlgoStr = [](QSsl::KeyAlgorithm a) {
                switch (a) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 13, 0))
                // This was added in Qt 5.13+
                case QSsl::KeyAlgorithm::Dh: return "DH";
#endif
                case QSsl::KeyAlgorithm::Ec: return "EC";
                case QSsl::KeyAlgorithm::Dsa: return "DSA";
                case QSsl::KeyAlgorithm::Rsa: return "RSA";
                default: return "Other";
                }
            };
            Util::AsyncOnObject(this, [this]{
                // We do this logging later. This is to ensure that it ends up in the syslog if user specified -S
                Log() << "Loaded key type: " << (options->sslKey.type() == QSsl::KeyType::PrivateKey ? "private" : "public")
                      << " algorithm: " << KeyAlgoStr(options->sslKey.algorithm());
            });
        }
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
    options->donationAddress = conf.value("donation", options->donationAddress).left(80); // the 80 character limit is in case the user specified a crazy long string, no need to send all of it -- it's probably invalid anyway.
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
            throw BadArgs(QString("worker_threads: specified value of %1 exceeds the detected number of virtual processors of %2")
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
    if (conf.hasValue("tor_proxy")) {
        options->torProxy = parseInterface(conf.value("tor_proxy"), true); // may throw if bad
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
        const QStringList vals = conf.value("bitcoind_throttle").trimmed().simplified().split(QRegExp("\\W+"), QString::SplitBehavior::SkipEmptyParts);
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

    // warn user that no hostname was specified if they have peerDiscover turned on
    if (!options->hostName.has_value() && options->peerDiscovery && options->peerAnnounceSelf) {
        // do this when we return to event loop in case user is logging to -S (so it appears in syslog which gets set up after we return)
        Util::AsyncOnObject(this, []{
            Warning() << "Warning: No 'hostname' variable defined in configuration. This server may not be peer-discoverable.";
        });
    }

    // parse --dump-*
    if (const auto outFile = parser.value("dump-sh"); !outFile.isEmpty()) {
        options->dumpScriptHashes = outFile; // we do no checking here, but Controller::startup will throw BadArgs if it cannot open this file for writing.
    }
}

namespace {
    auto ParseParams(const SimpleHttpServer::Request &req) -> StatsMixin::StatsParams {
        StatsMixin::StatsParams params;
        const auto nvps = req.queryString.split("&");
        for (const auto & nvp : nvps) {
            auto nv = nvp.split("=");
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
    server->addEndpoint("/stats",[this](SimpleHttpServer::Request &req){
        req.response.contentType = "application/json; charset=utf-8";
        auto stats = controller->statsSafe();
        stats = stats.isNull() ? QVariantList{QVariant()} : stats;
        req.response.data = QString("%1\r\n").arg(Util::Json::toString(stats, false)).toUtf8();
    });
    server->addEndpoint("/debug",[this](SimpleHttpServer::Request &req){
        req.response.contentType = "application/json; charset=utf-8";
        const auto params = ParseParams(req);
        auto stats = controller->debugSafe(params);
        stats = stats.isNull() ? QVariantList{QVariant()} : stats;
        req.response.data = QString("%1\r\n").arg(Util::Json::toString(stats, false)).toUtf8();
    });
}

void App::miscPreAppFixups()
{
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
