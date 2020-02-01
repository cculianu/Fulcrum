% FULCRUM(1) Version 1.0.2 | Fulcrum Manual
% Fulcrum is written by Calin Culianu (cculianu)
% February 01, 2020

# NAME

**fulcrum** - SPV server for Bitcoin Cash.

# SYNOPSIS

| **fulcrum** \[options\] \[config\]

DESCRIPTION
===========

`fulcrum` requires a `bitcoind` instance running either on `testnet` or `mainnet` (or `regtest` for testing), which you must tell it about via the CLI options or via the config file. You also need to tell it what port(s) to listen on and optionally what SSL certificates to use (if using SSL).


**NOTE:**
Electron Cash at this time no longer supports connecting to non-SSL servers, so you should probably configure SSL for production use.

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
:   Specify a directory in which to store the database and other assorted data files.
    This is a required option. If the specified path does not exist, it will be
    created. Note that the directory in question should ideally live on a fast
    drive such as an SSD and it should have plenty of free space available.

-t, --tcp <interface:port>
:   Specify an <interface:port> on which to listen for TCP connections,
    defaults to 0.0.0.0:50001 (all interfaces, port 50001 -- only if no other
    interfaces are specified via -t or -s). This option may be specified more
    than once to bind to multiple interfaces and/or ports.
    Suggested values for port: 50001 on mainnet and 60001 on testnet.

-s, --ssl <interface:port>
:   Specify an <interface:port> on which to listen for SSL connections. Note that if this option is specified, then the `cert` and `key` options need to also be specified otherwise the app will refuse to run. This option may be specified more than once to bind to multiple interfaces and/or ports. Suggested values for port: 50002 on mainnet and 60002 on testnet.

-c, --cert <crtfile>
:   Specify a .crt file to use as the server's SSL cert. This option is required if the -s/--ssl option appears at all on the command-line. The file should contain a valid non-self-signed certificate in PEM format.

-k, --key <keyfile>
:   Specify a .key file to use as the server's SSL key. This option is required if the
-s/--ssl option appears at all on the command-line. The file should contain an RSA private key in PEM format.

-a, --admin <[interface:]port>
:   Specify a <port> or an <interface:port> on which to listen for TCP connections for the admin RPC service. The admin service is used for sending special control commands to the server, such as stopping the server, and it should *NOT* be exposed to the internet.  This option is required if you wish to use the FulcrumAdmin CLI tool to send commands to Fulcrum. It is recommended that you specify the loopback address as the bind interface for this option such as: <port> by itself or 127.0.0.1:<port> for IPv4 and/or ::1:<port> for IPv6. If no interface is specified, and just a port number by itself is used, then IPv4 127.0.0.1 is the bind interface used (along with the specified port). This option may be specified more than once to bind to multiple interfaces and/or ports.

-z, --stats <[interface:]port>
:   Specify listen address and port for the stats HTTP server. Format is same as the -s, -t or -a options, e.g.: <interface:port>. Default is to not start any starts HTTP servers.  Also, like the -a option, you may specify a port number by itself here and 127.0.0.1:<port> will be assumed. This option may be specified more than once to bind to multiple interfaces and/or ports.

-b, --bitcoind <hostname:port>
:   Specify a <hostname:port> to connect to the bitcoind rpc service. This is a required option, along with -u and -p. This hostname:port should be the same as you specified in your bitcoin.conf file under rpcbind- and rpcport-.

-u, --rpcuser <username>
:   Specify a username to use for authenticating to bitcoind. This is a required option, along with -b and -p.  This option should be the same username you specified in your bitcoind.conf file under rpcuser-. For security, you may omit this option from the command-line and use the RPCUSER environment variable instead (the CLI arg takes precedence if both are present).

-p, --rpcpassword <password>
:   Specify a password to use for authenticating to bitcoind. This is a required option, along with -b and -u.  This option should be the same password you specified in your bitcoind.conf file under rpcpassword-. For security, you may omit this option from the command-line and use the RPCPASSWORD environment variable instead (the CLI arg takes precedence if both are present).

-d, --debug
:   Print extra verbose debug output. This is the default on debug builds. This is the opposite of -q. (Specify this options twice to get network-level trace debug output.)

-q, --quiet
:   Suppress debug output. This is the default on release builds. This is the opposite of -d.

-S, --syslog
:   Syslog mode. If on Unix, use the syslog() facility to produce log messages. This option currently has no effect on Windows.

-C, --checkdb
:   If specified, database consistency will be checked thoroughly for sanity & integrity. Note that these checks are somewhat slow to perform and under normal operation are not necessary.

-T, --polltime <polltime>
:   The number of seconds for the bitcoind poll interval. Bitcoind is polled once every `polltime` seconds to detect mempool and blockchain changes. This value must be at least 0.5 and cannot exceed 30. If not specified, defaults to 2 seconds.

[config]
:   Configuration file (optional).


# FILES

*/etc/fulcrum.conf*

:   Default config file when running as a service.

# PORTS

The default port is 50001 and 50002

# BUGS

See GitHub Issues: <https://github.com/cculianu/Fulcrum/issues>
