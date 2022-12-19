% FULCRUM(1) Version 1.9.0 | Fulcrum Manual
% Fulcrum is written by Calin Culianu (cculianu)
% December 15, 2022

# NAME

**fulcrum** - A Bitcoin Cash (and Bitcoin BTC) Blockchain SPV Server

# SYNOPSIS

| **fulcrum** \[options\] \[config\]

DESCRIPTION
===========

`fulcrum` requires a `bitcoind` instance running either on `testnet` or `mainnet` (or `regtest` for testing), which you must tell it about via the CLI options or via the config file. You also need to tell it what port(s) to listen on and optionally what SSL certificates to use (if using SSL).


**NOTE:**
Electron Cash and/or Electrum at this time no longer support connecting to non-SSL servers, so you should probably configure SSL for production use.

It is recommended you specify a data dir (`-D` via CLI or `datadir-` via config file)
on an SSD drive for best results.
Synching against `testnet` should take you about 10-20 minutes (more on slower
machines), and mainnet can take anywhere from 4 hours to 20+ hours, depending on
machine and drive speed. I have not tried synching against mainnet on an HDD and
it will probably take **days** if you are lucky.

Once the server finishes synching it will behave like an ElectronX/ElectrumX server and it can receive requests from Electron Cash.

# OPTIONS

-h, --help
:   Prints brief usage information.

-v, --version
:   Displays version information.


-D, --datadir <path>
:   Specify a directory in which to store the database and other assorted data files.  This is a required option. If the specified path does not exist, it will be created. Note that the directory in question should ideally live on a fast drive such as an SSD and it should have plenty of free space available.

-t, --tcp <interface:port>
:   Specify an <interface:port> on which to listen for TCP connections, defaults to 0.0.0.0:50001 (all interfaces, port 50001 -- only if no other interfaces are specified via -t or -s). This option may be specified more than once to bind to multiple interfaces and/or ports.  Suggested values for port: 50001 on mainnet and 60001 on testnet.

-s, --ssl <interface:port>
:   Specify an <interface:port> on which to listen for SSL connections. Note that if this option is specified, then the `cert` and `key` options need to also be specified otherwise the app will refuse to run. This option may be specified more than once to bind to multiple interfaces and/or ports. Suggested values for port: 50002 on mainnet and 60002 on testnet.

-w, --ws <interface:port>
:   Specify an <interface:port> on which to listen for Web Socket connections (unencrypted, ws://). This option may be specified more than once to bind to multiple interfaces and/or ports. Suggested values for port: 50003 on mainnet and 60003 on testnet.

-W, --wss <interface:port>
:   Specify an <interface:port> on which to listen for Web Socket Secure connections (encrypted, wss://). Note that if this option is specified, then the --cert and --key options (or alternatively, the --wss-cert and --wss-key options) need to also be specified otherwise the app will refuse to run. This option may be specified more than once to bind to multiple interfaces and/or ports. Suggested values for port: 50004 on mainnet and 60004 on testnet.

-c, --cert <crtfile>
:   Specify a PEM file to use as the server's SSL certificate.  This option is required if the -s/--ssl and/or the -W/--wss options appear at all on the command-line.  The file should contain either a single valid self-signed certificate or the full certificate chain if using CA-signed certificates.

-k, --key <keyfile>
:   Specify a PEM file to use as the server's SSL key.  This option is required if the -s/--ssl and/or the -W/--wss options apear at all on the command-line.  The file should contain an RSA private key.  EC, DH, and DSA keys are also supported, but their support is experimental.

--wss-cert <crtfile>
:   Specify a certificate PEM file to use specifically for only WSS ports. This option is intended to allow WSS ports to use a CA-signed certificate (required by web browsers), whereas legacy Electrum Cash ports may want to continue to use self-signed certificates. If this option is specified, --wss-key must also be specified. If this option is missing, then WSS ports will just fall-back to using the certificate specified by --cert.

--wss-key <keyfile>
:   Specify a private key PEM file to use for WSS. This key must go with the certificate specified in --wss-cert. If this option is specified, --wss-cert must also be specified.

-a, --admin <[interface:]port>
:   Specify a <port> or an <interface:port> on which to listen for TCP connections for the admin RPC service. The admin service is used for sending special control commands to the server, such as stopping the server, and it should *NOT* be exposed to the internet.  This option is required if you wish to use the FulcrumAdmin CLI tool to send commands to Fulcrum. It is recommended that you specify the loopback address as the bind interface for this option such as: <port> by itself or 127.0.0.1:<port> for IPv4 and/or ::1:<port> for IPv6. If no interface is specified, and just a port number by itself is used, then IPv4 127.0.0.1 is the bind interface used (along with the specified port). This option may be specified more than once to bind to multiple interfaces and/or ports.

-z, --stats <[interface:]port>
:   Specify listen address and port for the stats HTTP server. Format is same as the -s, -t or -a options, e.g.: <interface:port>. Default is to not start any starts HTTP servers.  Also, like the -a option, you may specify a port number by itself here and 127.0.0.1:<port> will be assumed. This option may be specified more than once to bind to multiple interfaces and/or ports.

-b, --bitcoind <hostname:port>
:   Specify a <hostname:port> to connect to the bitcoind rpc service. This is a required option, along with -u and -p. This hostname:port should be the same as you specified in your bitcoin.conf file under rpcbind- and rpcport-.

--bitcoind-tls
:   If specified, connect to the remote bitcoind via HTTPS rather than the usual HTTP. Historically, bitcoind supported only JSON-RPC over HTTP; however, some implementations such as *bchd* support HTTPS. If you are using *fulcrum* with *bchd*, you either need to start *bchd* with the `notls` option, or you need to specify this option to *fulcrum*.

-u, --rpcuser <username>
:   Specify a username to use for authenticating to bitcoind. This option should be the same username you specified in your bitcoind.conf file under rpcuser-. For security, you may omit this option from the command-line and use the RPCUSER environment variable instead (the CLI arg takes precedence if both are present), or you may use -K instead.

-p, --rpcpassword <password>
:   Specify a password to use for authenticating to bitcoind. This option should be the same password you specified in your bitcoind.conf file under rpcpassword-. For security, you may omit this option from the command-line and use the RPCPASSWORD environment variable instead (the CLI arg takes precedence if both are present), or you may use -K instead.

-K, --rpccookie <cookiefile>
:   This option can be used instead of -u and -p. The file path for the bitcoind '.cookie' file (normally lives inside bitcoind's datadir). This file is auto-generated by bitcoind and (re)connect to bitcoind. Use this option only if your bitcoind is using cookie-file based RPC authentication.

-d, --debug
:   Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q. (Specify this options twice to get network-level trace debug output.)

-q, --quiet
:   Suppress debug output. This is the default on release builds. This is the opposite of -d.

-S, --syslog
:   Syslog mode. If on Unix, use the syslog() facility to produce log messages. This option currently has no effect on Windows.

-C, --checkdb
:   If specified, database consistency will be checked thoroughly for sanity & integrity. Note that these checks are somewhat slow to perform and under normal operation are not necessary. May be specified twice to do even more thorough checks.

-T, --polltime <polltime>
:   The number of seconds for the bitcoind poll interval. Bitcoind is polled once every `polltime` seconds to detect mempool and blockchain changes. This value must be at least 0.5 and cannot exceed 30. If not specified, defaults to 2 seconds.

--ts-format <keyword>
:   Specify log timestamp format, one of: "none", "uptime", "localtime", or "utc". If unspecified, default is "localtime" (previous versions of Fulcrum always logged using "uptime").

--tls-disallow-deprecated
:   If specified, restricts the TLS protocol used by the server to non-deprecated v1.2 or newer, disallowing connections from clients requesting TLS v1.1 or earlier. This option applies to all SSL and WSS ports server-wide.

--no-simdjson
:   If specified, disable the fast simdjson backend for JSON parsing. This parser is over 2x faster than the original parser, and is enabled by default as of Fulcrum version 1.3.0.

--bd-timeout
:   Corresponds to the configuration file variable "bitcoind_timeout". The number of seconds to wait for unanswered bitcoind requests before we consider them as having timed-out (default: 30). You may wish to set this higher than the default if using BCH ScaleNet, or if you see "bitcoind request timed out" appear in the log.

--bd-clients
:   Corresponds to the configuration file variable "bitcoind_clients". The number of simultaneous bitcoin RPC clients that we spawn to connect to bitcoind (default: 3). If you raise this value from the default, be sure to also specify the option `rpcthreads=` to bitcoind so that there are enough threads to accommodate the clients we spawn, otherwise you may get errors from bitcoind.

--compact-dbs
:   If specified, Fulcrum will compact all databases on startup. The compaction process reduces database disk space usage by removing redundant/unused data. Note that rocksdb normally compacts the databases in the background while Fulcrum is running, so using this option to explicitly compact the database files on startup is not strictly necessary.

--fast-sync
:   If specified, Fulcrum will use a UTXO Cache that consumes extra memory but syncs up to to 2X faster. To use this feature, you must specify a memory value in MB to allocate to the cache. It is recommended that you give this facility at least 2000 MB for it to really pay off, although any amount of memory given (minimum 200 MB) should be beneficial. Note that this feature is currently experimental and the tradeoffs are: it is faster because it avoids redundant disk I/O, however, this comes at the price of considerable memory consumption as well as a sync that is less resilient to crashes mid-sync. If the process is killed mid-sync, the database may become corrupt and lose UTXO data. Use this feature only if you are 100% sure that won't happen during a sync. Specify as much memory as you can, in MB, here, e.g.: 3000 to allocate 3000 MB (3 GB). The default is off (0). This option only takes effect on initial sync, otherwise this option has no effect.

--dump-sh <outputfile>
:    *This is an advanced debugging option*. Dump script hashes. If specified, after the database is loaded, all of the script hashes in the database will be written to outputfile as a JSON array.

[config]
:   Configuration file (optional).


# FILES

*/etc/fulcrum.conf*

:   Default config file when running as a service.

# PORTS

The default port is 50001 and 50002 for TCP and SSL, respectively.

# BUGS

See GitHub Issues: <https://github.com/cculianu/Fulcrum/issues>
