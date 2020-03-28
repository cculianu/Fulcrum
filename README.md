# Fulcrum

[![Travis CI Build](https://img.shields.io/travis/cculianu/Fulcrum/master)](https://travis-ci.org/cculianu/Fulcrum)
[![Docker Build](https://img.shields.io/docker/cloud/build/cculianu/fulcrum)](https://hub.docker.com/r/cculianu/fulcrum)
[![Copr build status](https://copr.fedorainfracloud.org/coprs/jonny/BitcoinCash/package/fulcrum/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/jonny/BitcoinCash/package/fulcrum/)

A fast & nimble SPV server for Bitcoin Cash.

#### Copyright
(C) 2019-2020 Calin Culianu <calin.culianu@gmail.com>

#### License:
GPLv3. See the included `LICENSE.txt` file or [visit gnu.org and read the license](https://www.gnu.org/licenses/gpl-3.0.html).

![Image Fulcrum](https://c3-soft.com/downloads/BitcoinCash/Fulcrum/Fulcrum.png)

### Highlights:

- *Fast:* Written in 100% modern `C++17` using multi-threaded and asynchronous programming techniques.
- *A drop-in replacement for ElectronX/ElectrumX:* Fulcrum is 100% protocol-level compatible with the [Electrum Cash 1.4.3 protocol](https://electrum-cash-protocol.readthedocs.io/en/latest/). Existing server admins should feel right at home with this software since installation and management of it is nearly identical to ElectronX/ElectrumX server.
- *Cross-platform:* While this codebase was mainly developed and tested on MacOS, Windows and Linux, it should theoretically work on any modern OS (such as *BSD) that has Qt5 Core and Qt5 Networking available.

### Requirements

- `Qt Core` & `Qt Networking` libraries `5.12.5` or above (I use `5.14.1` myself).  Qt `5.12.4` (or earlier) is not supported.
- A modern, 64-bit `C++17` compiler.  `clang` is recommended but `G++` also works. MSVC on Windows is not supported (please use `MinGW G++` instead, which ships with Qt Open Source Edition for Windows).

### How To Compile

It's recommended you use Qt Creator.

1. Get the latest version of Qt Open Source Edition for your platform.
2. Point the Qt Creator IDE at the `Fulcrum.pro` file.
3. Set the build configuration to "Release".  Hit Build.  It should "just work".

You may also build from the CLI (on Linux and MacOS):

1. Make sure you have `qmake` in your path and all the requisite Qt5 dev libs installed.
2. `qmake` (to generate the Makefile)
3. `make -j8`  (replace 8 here with the number of cores on your machine)

**A note for Linux users**: You may have to install the Qt5 networking package separately such as `libqt5network5` (depending on your distribution). You also need `libbz2-dev` otherwise compilation will fail. If you are having trouble finding the required Qt versions, you can try this link: https://launchpad.net/~beineri (for Ubuntu/Debian ppas).

**A note for Windows users**: `Qt 5.13.2` (or above) with `MinGW G++ 7.x.x` is the compiler/Qt kit you should be using.  MSVC is not supported by this codebase at the present time.

#### What to do if compiling fails
If you have problems compiling, the most likely culprit would be your compiler not being `C++17` compliant (please use a recent verson of `GCC` or `clang` on Linux, Apple's `Xcode` on Mac, or `MinGW G++ 7.x` on Windows).

The other likely culprit is the fact that at the present time I have included a statically-built `librocksdb` in the codebase. There are versions of this library for Windows, Mac, and Linux included right in the source tree, and `Fulcrum.pro` looks for them and links to them. Instructions are included within the `Fulcrum.pro` project file about how to build your own static `librocksdb` if the bundled one does not work on your system.

If you are still having trouble, [file an issue here in this github](https://github.com/cculianu/Fulcrum/issues).

#### Linking against the system `librocksdb.so` (experimental)

You may optionally build against the **system rocksdb** (Linux only) if your distribution offers `rocksdb` version `6.6.4` or newer.

1. `qmake features=`  (to generate the Makefile **without** the `staticlibs` feature)
2. `make clean && make -j8` (replace 8 here with the number of cores on your machine)

**Note**: Some Linux distributions have been known to package `librocksdb.so` incorrectly. [See here for an example](https://bugs.archlinux.org/task/65093), so until I can be confident most distributions do it right, I am considering using the system `librocksdb.so` an ***experimental feature*** for the time being (in principle it should work ok if the library is compiled correctly).

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

3. You can point the build script to any repository, not just this one, by giving it a `GIT_REPO` environment variable:

    `$ GIT_REPO=https://github.com/myusername/MyFulcrumFork contrib/build/build.sh windows master`

    `$ GIT_REPO=$(pwd) contrib/build/build.sh windows master`

The first argument to the script is the platform to build (in this case `windows`).
The second argument to the script is a git `branch` or `tag` to build.

Two `.exe` files will be generated, `Fulcrum.exe` and `FulcrumAdmin.exe` which
will appeare in `dist/win` after the build process is completes.

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

3. You can point the build script to any repository, not just this one, by giving it a `GIT_REPO` environment variable:

    `$ GIT_REPO=https://github.com/myusername/MyFulcrumFork contrib/build/build.sh linux master`

    `$ GIT_REPO=$(pwd) contrib/build/build.sh linux master`

The first argument to the script is the platform to build (in this case `linux`).
The second argument to the script is a git `branch` or `tag` to build.

---

### Running Fulcrum

Execute the binary, with `-h` to see the built-in help, e.g. `./Fulcrum -h`. You can set most options from the CLI, but you can also specify a **config file** as an argument. See:

 - [doc/fulcrum-example-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-example-config.conf) in the source tree. This sample config file is very well documented with comments.
 - [doc/fulcrum-quick-config.conf](https://github.com/cculianu/Fulcrum/blob/master/doc/fulcrum-quick-config.conf) in the source tree. This is a more abbreviated config file you can use as a starting point as well.

`Fulcrum` requires a `bitcoind` instance running either on `testnet` or `mainnet` (or `regtest` for testing), which you must tell it about via the CLI options or via the config file.  You also need to tell it what port(s) to listen on and optionally what SSL certificates to use (if using SSL). ***Note:*** *Electron Cash at this time no longer supports connecting to non-SSL servers, so you should probably configure SSL for production use*.

It is recommended you specify a data dir (`-D` via CLI or `datadir=` via config file) on an SSD drive for best results.  Synching against `testnet` should take you about 10-20 minutes (more on slower machines), and mainnet can take anywhere from 4 hours to 20+ hours, depending on machine and drive speed.  I have not tried synching against mainnet on an HDD and it will probably take ***days*** if you are lucky.

Once the server finishes synching it will behave like an ElectronX/ElectrumX server and it can receive requests from Electron Cash.

You may also wish to read the [Fulcrum manpage](https://github.com/cculianu/Fulcrum/blob/master/doc/unix-man-page.md).


#### Admin Script: FulcrumAdmin

`Fulcrum` comes with an admin script (`Python 3.6+` is required on the system to run this script).  You may send commands to `Fulcrum` using this script. The script requires that an **admin port** (config var `admin=`, CLI arg `-a`) be configured for your server.  To run the script, execute `./FulcrumAdmin -h` and you will see a list of possible subcommands that you can send to `Fulcrum`.  Here are two of the most popular commands to try (the below assumes the `admin` port is on port `8000`):

    $ ./FulcrumAdmin -p 8000 peers
    $ ./FulcrumAdmin -p 8000 clients
    $ ./FulcrumAdmin -p 8000 getinfo

***(This section is incomplete for now, all apologies -- more documentation is coming soon!)***

---

### Protocol Documentation

Documentation for the Electrum Cash protocol that Fulcrum uses is [available here](https://electrum-cash-protocol.readthedocs.io/en/latest/).

---

### Platform Notes

#### Big Endian Architectures

The code is more or less configured to assume a "little endian" architecture by default (which is what all Intel x86/x86_64 are).  If you're on a big endian machine, on Linux it should just auto-detect that fact.  However, on other OS's such as BSD, if you're on a big endian machine, you may need to uncomment this line from the `.pro` file:

    # DEFINES += WORDS_BIGENDIAN


#### Windows

This codebase will not compile correctly (or at all) using MSVC. Please use the `MinGW` and/or `G++` kit in Qt Creator to build this software.

#### Linux

If you have `clang` on your system, configure the project to use it as the compiler preferentially over `G++`.  `G++` works too, but `clang` is preferred.

#### MacOS

Everything should just work (I use MacOS as my dev machine).

---

### F.A.Q.



**Q:** Why Qt?  This isn't a GUI app!

**A:** Yes, I know.  However, Qt is a very robust, cross-platform and fast application framework.  You can use its "Core" library for console apps, servers, etc.  It has great network support and other basic things a programmer needs to get stuff done.


---

### Donations

Sure!  Send BCH here:

[bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)

[![bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc](https://raw.githubusercontent.com/cculianu/DonateSpareChange/master/donate.png)](bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc)
