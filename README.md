# Fulcrum

[![Travis CI Build](https://img.shields.io/travis/cculianu/Fulcrum/master)](https://travis-ci.org/cculianu/Fulcrum)
[![Docker Build](https://github.com/cculianu/Fulcrum/actions/workflows/publish.yml/badge.svg)](https://github.com/cculianu/Fulcrum/actions/workflows/publish.yml)
[![Copr build status](https://copr.fedorainfracloud.org/coprs/jonny/BitcoinCash/package/fulcrum/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/jonny/BitcoinCash/package/fulcrum/)

A fast & nimble SPV server for Bitcoin Cash, Bitcoin BTC, and Litecoin.

#### Copyright
(C) 2019-2022 Calin Culianu <calin.culianu@gmail.com>

#### License:
GPLv3. See the included `LICENSE.txt` file or [visit gnu.org and read the license](https://www.gnu.org/licenses/gpl-3.0.html).

![Image Fulcrum](https://c3-soft.com/downloads/BitcoinCash/Fulcrum/Fulcrum.png)

### Highlights:

- *Fast:* Written in 100% modern `C++17` using multi-threaded and asynchronous programming techniques.
- *A drop-in replacement for ElectronX/ElectrumX:* Fulcrum is 100% protocol-level compatible with the [Electrum Cash 1.4.5 protocol](https://electrum-cash-protocol.readthedocs.io/en/latest/). Existing server admins should feel right at home with this software since installation and management of it is nearly identical to ElectronX/ElectrumX server.
- *Cross-platform:* While this codebase was mainly developed and tested on MacOS, Windows and Linux, it should theoretically work on any modern OS (such as *BSD) that has Qt5 Core and Qt5 Networking available.
- ***NEW!*** *Triple-coin:* Supports BCH, BTC and LTC.

### Requirements

- *For running*:
  - A supported bitcoin full node with its JSON-RPC service enabled, preferably running on the same machine.
    - *For **BCH***: Bitcoin Cash Node, Bitcoin Unlimited Cash, Flowee, and bchd have all been tested extensively and are known to work well with this software.
    - *For **BTC***: Bitcoin Core v0.17.0 or later.  No other full nodes are supported by this software for BTC.
    - *For **LTC***: Litecoin Core v0.17.0 or later.  No other full nodes are supported by this software for LTC.
      - If using Litcoin Core v0.21.2 or above, your daemon is serializing data using mweb extensions. While Fulcrum understands this serialization format, your Electrum-LTC clients may not. You can run `litecoind` with `-rpcserialversion=1` to have your daemon return transactions in pre-mweb format which is understood by most Electrum-LTC clients.
    - The node must have txindex enabled e.g. `txindex=1`.
    - The node must not be a pruning node.
    - *Optional*: For best results, enable zmq for the "hasblock" topic using e.g. `zmqpubhashblock=tcp://0.0.0.0:8433` in your `bitcoin.conf` file (zmq is only available on: Core, BCHN, BU 1.9.1+, or Litecoin Core).
  - *Recommended hardware*: Minimum 1GB RAM, 64-bit CPU, ~40GB disk space for mainnet BCH (slightly more for BTC). For best results, use an SSD rather than an HDD.
- *For compiling*: 
  - `Qt Core` & `Qt Networking` libraries `5.12.5` or above (I use `5.15.2` myself).  Qt `5.12.4` (or earlier) is not supported.
  - *Optional but recommended*: `libzmq 4.x` development headers and library (also known as `libzmq3-dev` on Debian/Ubuntu and `zeromq-devel` on Fedora). Fulcrum will run just fine without linking against `libzmq`, but it will run better if you do link against `libzmq` and also turn on `zmqpubhashblock` notifications in `bitcoind` (zmq is only available on: Core, BCHN, or BU 1.9.1+).
  - A modern, 64-bit `C++17` compiler.  `clang` is recommended but `G++` also works. MSVC on Windows is not supported (please use `MinGW G++` instead, which ships with Qt Open Source Edition for Windows).

### Quickstart

1. Download a [pre-built static binary](https://github.com/cculianu/Fulcrum/releases).
2. Verify that the binary runs on your system by executing the binary with `./Fulcrum -h` to see the CLI options.
3. Setup a configuration file and to point Fulcrum to your bitcoind JSON-RPC server, specify listening ports, TLS certificates, etc.  See: [doc/fulcrum-example-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-example-config.conf) and/or [doc/fulcrum-quick-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-quick-config.conf)
4. Also see this section below on [Running Fulcrum](#running-fulcrum).

### How To Compile

Compiling is for those users that do not wish to use the [pre-built static binaries provided here](https://github.com/cculianu/Fulcrum/releases), or for users on platforms for which the static binaries are not provided (such as FreeBSD or macOS). To compile, it's recommended you use the Qt Creator IDE.

1. Get the latest version of Qt Open Source Edition for your platform.
2. Point the Qt Creator IDE at the `Fulcrum.pro` file.
3. Set the build configuration to "Release".  Hit Build.  It should "just work".

You may also build from the CLI (on Linux and MacOS):

1. Make sure you have `qmake` in your path and all the requisite Qt5 dev libs installed.
2. `qmake` (to generate the Makefile)
3. `make -j8`  (replace 8 here with the number of cores on your machine)

**A note for Linux users**: You may have to install the Qt5 networking package separately such as `libqt5network5` (depending on your distribution). You also need `libbz2-dev` otherwise compilation will fail. If you are having trouble finding the required Qt versions, you can try this link: https://launchpad.net/~beineri (for Ubuntu/Debian ppas). For best results, you may wish to also ensure you have `pkg-config` and `libzmq` installed (aka `libzmq3-dev` on Debian/Ubuntu, `zeromq-devel` on Fedora).

**A note for Windows users**: `Qt 5.13.2` (or above) with `MinGW G++ 7.x.x` is the compiler/Qt kit you should be using.  MSVC is not supported by this codebase at the present time.

#### What to do if compiling fails
If you have problems compiling, the most likely culprit would be your compiler not being `C++17` compliant (please use a recent version of `GCC` or `clang` on Linux, Apple's `Xcode` on Mac, or `MinGW G++ 7.x` on Windows).

The other likely culprit is the fact that at the present time I have included a statically-built `librocksdb` in the codebase. There are versions of this library for Windows, Mac, and Linux included right in the source tree, and `Fulcrum.pro` looks for them and links to them. Instructions are included within the `Fulcrum.pro` project file about how to build your own static `librocksdb` if the bundled one does not work on your system.

If you are still having trouble, [file an issue here in this github](https://github.com/cculianu/Fulcrum/issues).

#### Linking against the system `librocksdb.so` (experimental)

You may optionally build against the **system rocksdb** (Linux only) if your distribution offers `rocksdb` version `6.6.4` or newer.

1. `qmake LIBS=-lrocksdb`  (to generate the Makefile **without** linking to the included static lib)
2. `make clean && make -j8` (replace 8 here with the number of cores on your machine)

**Note**: Some Linux distributions have been known to package `librocksdb.so` incorrectly. [See here for an example](https://bugs.archlinux.org/task/65093), so until I can be confident most distributions do it right, I am considering using the system `librocksdb.so` an ***experimental feature*** for the time being (in principle it should work ok if the library is compiled correctly).

#### Making sure `libzmq` is detected and used (optional but recommended)

Ensure that `libzmq3` (Debian/Ubuntu) and/or `zeromq-devel` (Fedora/Redhat) is installed, and that `pkg-config` is also installed.  If on Unix (macOS, Linux, or Windows MinGW), then ideally the `qmake` step will find `libzmq` on your system and automatically use it. If that is not the case, you may try passing flags to `qmake` such as `LIBS+="-L/path/to/libdir_containting_libzmq -lzmq"` and `INCLUDEPATH+="/path/to/dir_containing_zmq_h"` as arguments when you invoke `qmake`.  Using `libzmq` is optional but highly recommended. If you have trouble getting Fulcrum to compile against your `libzmq`, [open a new issue](https://github.com/cculianu/Fulcrum/issues) and maybe I can help.

### Building the Windows static `Fulcrum.exe`

**New!** I recently added a mechanism using Docker to build a statically-linked
Windows `.exe`. This build is 100% compatible with any stock 64-bit Windows 7 or
above system -- you don't have to install anything -- it *just works*. You can
download the pre-built `.exe` yourself here from the [releases
page](https://github.com/cculianu/Fulcrum/releases).

If you want to build it yourself though, you can do so, but it requires
[Docker](https://www.docker.com/) on either a MacOS or a Linux host system (it
may work on Windows too with Linux tools for Windows -- but I haven't tried it
myself). It builds *all* dependencies, including a static Qt and static rocksdb.
As such, it may take a while so be patient.

1. Make sure Docker is installed such that you don't need to use `sudo`. This is the default on MacOS, but on Linux you may need to [follow these instructions here](https://docs.docker.com/install/linux/linux-postinstall/).

2. Run the build script:

    `$ contrib/build/build.sh windows master`

The first argument to the script is the platform to build (in this case
`windows`). The second argument to the script is a git `branch` or `tag` to
build. Two `.exe` files will be generated, `Fulcrum.exe` and `FulcrumAdmin.exe`,
which will appear in `dist/win` after the build process completes.

- *Note:* You can point the build script to any repository, not just this one, by giving it a `GIT_REPO` environment variable:

    `$ GIT_REPO=https://github.com/myusername/MyFulcrumFork contrib/build/build.sh windows master`

    `$ GIT_REPO=$(pwd) contrib/build/build.sh windows master`

### Building a static executable for Linux

**New!** I recently added a mechanism using Docker to build a statically-linked
Linux executable. This build is 100% compatible with most stock 64-bit Linux
systems with a new enough glibc and libstdc++. So on a relatively modern Linux system, you
don't have to install anything -- it *just works*. You can download the
pre-built binary yourself here from the [releases page](https://github.com/cculianu/Fulcrum/releases).

If you want to build it yourself though, you can do so, but it requires [Docker](https://www.docker.com/)
on either a MacOS or a Linux host system.  It builds a static Qt and static rocksdb.

1. Make sure Docker is installed such that you don't need to use `sudo`. This is the default on MacOS, but on Linux you may need to [follow these instructions here](https://docs.docker.com/install/linux/linux-postinstall/).

2. Run the build script:

    `$ contrib/build/build.sh linux master`

The first argument to the script is the platform to build (in this case
`linux`). You may also specify `oldlinux` as the first argument if you wish to
build for an older system (in which case the Docker container will use Ubuntu 16.04
to compile, instead of the Ubuntu "latest" tag). The second argument to the
script is a git `branch` or `tag` to build.

- *Note:* You can point the build script to any repository, not just this one, by giving it a `GIT_REPO` environment variable:

    `$ GIT_REPO=https://github.com/myusername/MyFulcrumFork contrib/build/build.sh linux master`

    `$ GIT_REPO=$(pwd) contrib/build/build.sh linux master`

---

### Running Fulcrum

Execute the binary, with `-h` to see the built-in help, e.g. `./Fulcrum -h`. You can set most options from the CLI, but you can also specify a **config file** as an argument. See:

 - [doc/fulcrum-example-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-example-config.conf) in the source tree. This sample config file is very well documented with comments.
 - [doc/fulcrum-quick-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-quick-config.conf) in the source tree. This is a more abbreviated config file you can use as a starting point as well.

`Fulcrum` requires a `bitcoind` instance running either on `testnet` or `mainnet` (or `regtest` for testing), which you must tell it about via the CLI options or via the config file.  You also need to tell it what port(s) to listen on and optionally what SSL certificates to use (if using SSL). ***Note:*** *Electron Cash (and/or Electrum) at this time no longer support connecting to non-SSL servers, so you should probably configure SSL for production use*.

It is recommended you specify a data dir (`-D` via CLI or `datadir=` via config file) on an SSD drive for best results.  Synching against `testnet` should take you about 10-20 minutes (more on slower machines), and mainnet can take anywhere from 4 hours to 20+ hours, depending on machine and drive speed.  I have not tried synching against mainnet on an HDD and it will probably take ***days*** if you are lucky.

As long as the server is still synchronizing, all public-facing ports will not yet be bound for listening and as such an attempt to connect to one of the RPC ports will fail with a socket error such as e.g. "Connection refused". Once the server finishes synching it will behave like an ElectronX/ElectrumX server and it can receive requests from Electron Cash (or Electrum if on BTC).

You may also wish to read the [Fulcrum manpage](https://github.com/cculianu/Fulcrum/blob/master/doc/unix-man-page.md).


#### Admin Script: FulcrumAdmin

`Fulcrum` comes with an admin script (`Python 3.6+` is required on the system to run this script).  You may send commands to `Fulcrum` using this script. The script requires that an **admin port** (config var `admin=`, CLI arg `-a`) be configured for your server.  To run the script, execute `./FulcrumAdmin -h` and you will see a list of possible subcommands that you can send to `Fulcrum`. Below you see all available commands (the below assumes the `admin` port is on port `8000`):

    $ ./FulcrumAdmin -p 8000 addpeer              Add a peer to the server's list of peers
    $ ./FulcrumAdmin -p 8000 ban                  Ban clients by ID and/or IP address
    $ ./FulcrumAdmin -p 8000 banpeer              Ban peers by hostname suffix
    $ ./FulcrumAdmin -p 8000 bitcoind_throttle    Query or set server bitcoind_throttle setting
    $ ./FulcrumAdmin -p 8000 clients (sessions)   Print information on all the currently connected clients
    $ ./FulcrumAdmin -p 8000 getinfo              Get server information
    $ ./FulcrumAdmin -p 8000 kick                 Kick clients by ID and/or IP address
    $ ./FulcrumAdmin -p 8000 listbanned (banlist) Print the list of banned IP addresses and peer hostnames
    $ ./FulcrumAdmin -p 8000 loglevel             Set the server's logging verbosity
    $ ./FulcrumAdmin -p 8000 maxbuffer            Query or set server max_buffer setting
    $ ./FulcrumAdmin -p 8000 peers                Print peering information
    $ ./FulcrumAdmin -p 8000 rmpeer               Remove peers by hostname suffix
    $ ./FulcrumAdmin -p 8000 simdjson             Get or set the server's 'simdjson' (JSON parser) setting
    $ ./FulcrumAdmin -p 8000 stop (shutdown)      Gracefully shut down the server
    $ ./FulcrumAdmin -p 8000 unban                Unban IP addresses
    $ ./FulcrumAdmin -p 8000 unbanpeer            Unban peers by hostname suffix

---

### Protocol Documentation

Documentation for the Electrum Cash protocol that Fulcrum uses is [available here](https://electrum-cash-protocol.readthedocs.io/en/latest/).

---

### Platform Notes

#### Windows

This codebase will not compile correctly (or at all) using MSVC. Please use the `MinGW` and/or `G++` kit in Qt Creator to build this software.

#### Linux

If you have `clang` on your system, configure the project to use it as the compiler preferentially over `g++`.  `g++` works great too, but `clang` is preferred.

#### MacOS

Everything should just work (I use MacOS as my dev machine).

---

### F.A.Q.



**Q:** Why Qt?  This isn't a GUI app!

**A:** Yes, I know.  However, Qt is a very robust, cross-platform and fast application framework.  You can use its "Core" library for console apps, servers, etc.  It has great network support and other basic things a programmer needs to get stuff done.

**Q:** Why is the compiled binary called `Fulcrum` (capital `F`) and not `fulcrum` (lowercase `f`) as is customary on Linux/Unix?

**A:** Because I like capital letters, even on Linux.  I also develop (this and other software) for macOS and Windows and over there the Linux/Unix lowecase thing looks a little out-of-place.  Perhaps my sensibilities have been affected by my win32 and macOS dev work, or perhaps I'm just unconventional.  Embrace the lack of convention here! That being said, if the capital `F` bothers you, feel free to rename it or represent it as `fulcrum` wherever you like.

---

### Donations

Sure!  Send **BCH** here:

[bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)

[![bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](https://raw.githubusercontent.com/cculianu/DonateSpareChange/master/donate.png)](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)

You may also send **BTC** to the BTC-equivalent of the above address, which is: **`1BCHBCH6TXBaXyc5HReLBm1sNytBF2kkPD`**

---

### Sponsors

![General Protocols](https://c3-soft.com/imgs/general-protocols.png)
