#
# Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
# Copyright (C) 2019-2023 Calin A. Culianu <calin.culianu@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see LICENSE.txt).  If not, see
# <https://www.gnu.org/licenses/>.
#

# print CLI overrides to stdout immediately
!isEmpty(LIBS) {
    message("CLI overrides: LIBS=$$LIBS")
}
!isEmpty(INCLUDEPATH) {
    message("CLI overrides: INCLUDEPATH=$$INCLUDEPATH")
}

# Make qtCompileTest available
load(configure)

QT -= gui
QT += network

CONFIG += c++17 console warn_on
CONFIG -= app_bundle

versionAtMost(QT_VERSION, 5.12.4) {
    error("Fulcrum requires Qt 5.12.5 (or later) or Qt 5.13.1 (or later) to be successfully built without errors.  Please use Qt 5.12.5+ or Qt 5.13.1+ to build this codebase.")
}

QMAKE_CXXFLAGS_RELEASE += -DNDEBUG
QMAKE_CFLAGS_RELEASE += -DNDEBUG
QMAKE_CXXFLAGS_DEBUG -= -DNDEBUG
QMAKE_CFLAGS_DEBUG -= -DNDEBUG
release {
    CONFIG += optimize_full
}

macx {
    # Note: This is required because we use advanced C++ features such as std::visit
    # which requires newer Mojave+ C++ libs.  On a recent compiler SDK, this will
    # compile ok even on High Sierra with latest Xcode for High Sierra, so this requirement
    # isn't too bad.  It just affects what C++ runtime we link to on MacOS.
    versionAtMost(QT_VERSION, 6.4.3) {
        # Qt 6.4.3 was OK with this setting
        QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.14
    } else {
        # It appears Qt 6.5.0 requires at least 10.15 otherwise we get compile-time errors about std::filesystem
        # Since 6.5.0 is linked-to 11.0, we will just use that.
        QMAKE_MACOSX_DEPLOYMENT_TARGET = 11.0
    }
}

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# I added some Qt-specific calls to stuff inside the bitcoin:: namespace.
# This enables those functions.
DEFINES += USE_QT_IN_BITCOIN

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

# If defined, tests and benchmarks will be compiled-in to the app (accessed via --test and --bench CLI args).
#DEFINES += ENABLE_TESTS

win32-msvc {
    error("MSVC is not supported for this project. Please compile with MinGW G++ 7.3.0 or above.")
}
win32 {
    # Windows MSVC & mingw-g++ both have too many warnings due to bitcoin sources, so just disable warnings.
    CONFIG += warn_off
}
linux {
    QMAKE_CXXFLAGS += -std=c++1z
    DEFINES += HAVE_ENDIAN_H HAVE_DECL_HTOBE16 HAVE_DECL_HTOLE16 HAVE_DECL_BE16TOH HAVE_DECL_LE16TOH HAVE_DECL_HTOBE32 \
               HAVE_DECL_HTOLE32 HAVE_DECL_BE32TOH HAVE_DECL_LE32TOH HAVE_DECL_HTOBE64 HAVE_DECL_HTOLE64 HAVE_DECL_BE64TOH \
               HAVE_DECL_LE64TOH
}
linux-g++ {
    # Linux g++ has too many warnings due to bitcoin sources, so just disable warnings
    CONFIG += warn_off
}
freebsd {
    QMAKE_CXXFLAGS += -std=c++1z
    DEFINES += HAVE_SYS_ENDIAN_H HAVE_DECL_HTOBE16 HAVE_DECL_HTOLE16 HAVE_DECL_BE16TOH HAVE_DECL_LE16TOH HAVE_DECL_HTOBE32 \
               HAVE_DECL_HTOLE32 HAVE_DECL_BE32TOH HAVE_DECL_LE32TOH HAVE_DECL_HTOBE64 HAVE_DECL_HTOLE64 HAVE_DECL_BE64TOH \
               HAVE_DECL_LE64TOH
}

# define HAVE_DECL___BUILTIN_CLZL and HAVE_DECL___BUILTIN_CLZLL used by embedded bitcoin/ sources
qtCompileTest(builtin_clzl)
contains(CONFIG, config_builtin_clzl) {
    DEFINES += HAVE_DECL___BUILTIN_CLZL
}
qtCompileTest(builtin_clzll)
contains(CONFIG, config_builtin_clzll) {
    DEFINES += HAVE_DECL___BUILTIN_CLZLL
}

# Detect endianness and set WORDS_BIGENDIAN if on a big endian platform
qtCompileTest(endian_big)
qtCompileTest(endian_little)
contains(CONFIG, config_endian_big) {
    DEFINES += WORDS_BIGENDIAN
    contains(CONFIG, config_endian_little) {
        error("Detected both BIG and LITTLE endian at the same time. This should not happen. FIXME!")
    }
} else {
    contains(CONFIG, config_endian_little) {
        DEFINES -= WORDS_BIGENDIAN
    } else {
        error("Failed to detect either BIG or LITTLE endian. Unknown compiler? FIXME!")
    }
}

# Handle or add GIT_COMMIT=
!contains(DEFINES, GIT_COMMIT.*) {
    unix {
        exists( $$_PRO_FILE_PWD_/.git ) {  # If we have a .git directory at the top level
            system( git --version > /dev/null ) {  # And `git` is a valid command...
                # Then we define the git commit we are compiling against
                DEFINES += GIT_COMMIT="\\\"$(shell git -C \""$$_PRO_FILE_PWD_"\" describe --always --dirty --match 'NOT A TAG')\\\""
            }
        }
    } else {
        # NB: for Windows, caller should set DEFINES+=GIT_COMMIT=\"xxx\"
        #warning("Be sure to set DEFINES+=GIT_COMMIT=\\\"xxx\\\" in the final release build to embed the commit hash into the final application.")
    }
}
# /GIT_COMMIT=

# ZMQ
!contains(LIBS, -lzmq) {
    # Test for ZMQ, and if found, add pkg-config which we will rely upon to find libs
    qtCompileTest(zmq)
    contains(CONFIG, config_zmq) {
        QT_CONFIG -= no-pkg-config
        CONFIG += link_pkgconfig
        PKGCONFIG += libzmq
        DEFINES += ENABLE_ZMQ
        message("ZMQ version: $$system($$pkgConfigExecutable() --modversion libzmq)")
    }
} else {
    DEFINES += ENABLE_ZMQ
    message("ZMQ: using CLI override")
}
!contains(DEFINES, ENABLE_ZMQ) {
    message("ZMQ not found, install pkg-config and libzmq to enable ZMQ notifications.")
}
# /ZMQ

# - Try and detect rocksdb and if not, fall back to the staticlib.
# - User can suppress this behavior by specifying a "LIBS+=-lrocksdb..." on the
#   CLI when they invoked qmake. In that case, they must set-up the LIBS+= and
#   INCLUDEPATH+= fully when invoking qmake.
!contains(LIBS, -lrocksdb) {
    # Test if rocksdb is installed and meets the minimum version requirement
    qtCompileTest(rocksdb)
    contains(CONFIG, config_rocksdb) {
        message("rocksdb: using system lib")
    } else {
        # RocksDB Static Lib
        # ------------------
        #
        # Build information --
        #
        # Currently this was built from github sources of the v6.14.6 rocksdb release:
        #     https://github.com/facebook/rocksdb.git
        # Commit tag v6.14.6, commit hash (from Tue Dec 1 15:05:35 2020 -0800):
        #     ed4316166f67ec892603014634840d29f460f611
        #
        # OSX:
        #   Built on Apple clang version 11.0.0 (clang-1100.0.33.17), from Xcode 113.1.
        #   command: USE_RTTI=1 PORTABLE=1 DEBUG_LEVEL=0 make static_lib -j4 V=1
        #   Annoyingly, the produced .a file has debug symbols which we strip with: strip -S.
        #
        # Linux:
        #   Built on Ubuntu 18.10, g++ (Ubuntu 8.2.0-7ubuntu1) 8.2.0.
        #   command: USE_RTTI=1 PORTABLE=1 DEBUG_LEVEL=0 make static_lib -j4 V=1
        #   Annoyingly, the produced .a file has debug symbols which we strip with: strip -g.
        #
        # Windows:
        #   Built using the MinGW G++ 8.1.0 (compiler that ships with Qt 5.15+), from a cmd.exe prompt, via cmake.exe by
        #   following these steps:
        #   - Install a recent cmake into eg c:\cmake
        #   - Open up a Qt cmd.exe prompt that points to MinGW G++ 8.1.0 in the path (using the Start menu shortcut
        #     installed by Qt 5.15+ is easiest).
        #   - Put installed 'c:\cmake\bin' in the path so that 'cmake.exe' works from the cmd prompt, eg:
        #         set PATH=c:\cmake\bin;%PATH%
        #   - Checkout rocksdb (commit hash above), cd rocksdb
        #   - Now you will need to edit CMakeLists.txt:
        #     1. Open CMakeLists.txt in a text editor
        #     2. Search for '-fno-asynchronous-unwind-tables' and remove that compile option since it
        #        breaks building on MinGW against Qt, and replace it with -O3 for maximal speed.
        #     3. In that same MINGW section where you removed the above, add: '-Wno-cast-function-type -Wno-error=cast-function-type'
        #        since MinGW 8.1 seems to not like the function pointer casts in port/win/env_win.cc.
        #     4. Look for a section that contains 'if(NOT MINGW' and rename MINGW to XX_MINGW:
        #             if(NOT XX_MINGW)
        #        This ensures that port/win/win_thread.cc does get compiled and linked into the lib.
        #   - mkdir build, cd build
        #   - Run this command from within the rocksdb/build dir that you just created:
        #         cmake .. -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_SYSTEM_NAME=Windows -G"MinGW Makefiles" -DWITH_GFLAGS=0 -DWITH_JNI=0  -DCMAKE_BUILD_TYPE=Release -DUSE_RTTI=1 -DPORTABLE=1
        #   - Build with this command:
        #         mingw32-make -j4 V=1 rocksdb  <-- will build static lib only
        #   The generated librocksdb.a will be in the build/ directory you are currently in, ready to be put into the
        #   Fulcrum directory staticlibs/rocksdb/bin/win64.
        macx {
            LIBS += -L$$PWD/staticlibs/rocksdb/bin/osx
        }
        linux {
            # We support aarch64 (for RPis, etc) but the user needs to run a shell script to compile librocksdb.a
            # themselves: contrib/build/rocksdb-staticlib.sh
            contains(QMAKE_HOST.arch, aarch64) {
                aarch64_rocksdb = staticlibs/rocksdb/bin/linux/aarch64
                aarch64_rocksdb_path = $$PWD/$$aarch64_rocksdb
                exists($$aarch64_rocksdb_path/librocksdb.a) {
                    LIBS += -L$$aarch64_rocksdb_path
                    message("Linux-ARM64 detected: Using librocksdb.a from $$aarch64_rocksdb")
                } else {
                   message("Linux-ARM64 detected but missing librocksdb.a in $$aarch64_rocksdb")
                   error("Please run the shell script contrib/build/rocksdb-staticlib.sh to build it.")
                }
            } else {
                LIBS += -L$$PWD/staticlibs/rocksdb/bin/linux
            }
        }
        win32 {
            win32-g++ {
                LIBS += -L$$PWD/staticlibs/rocksdb/bin/win64
            } else {
                error("This project lacks a pre-compiled static librocksdb.a for this compiler! Either add one to staticlib/rocksdb/bin/win64/ or use MinGW G++ 8.1.0.")
            }
        }
        INCLUDEPATH += $$PWD/staticlibs/rocksdb/include
        message("rocksdb: using static lib")
        # /RocksDB Static Lib
    }
    macx {
        LIBS += -lrocksdb -lz -lbz2
    }
    linux {
        LIBS += -lrocksdb -lz -lbz2
    }
    freebsd {
        LIBS += -lrocksdb -lz -lbz2
    }
    win32 {
        LIBS += -lrocksdb
        contains(CONFIG, config_rocksdb) {
            LIBS += -lzstd -lbz2 -llz4 -lsnappy -lz
        }
    }
} else {
    message("rocksdb: using CLI override")
}

# - Try and detect jemalloc and if not, don't use jemalloc.
# - User can override auto-detection by specifying "LIBS+=-ljemaloc..." on the
#   CLI when they invoked qmake.
!contains(LIBS, -ljemalloc) {
    # Test if jemalloc is installed
    qtCompileTest(jemalloc)
    contains(CONFIG, config_jemalloc) {
        LIBS += -ljemalloc
        DEFINES += HAVE_JEMALLOC_HEADERS
    } else {
        message("jemalloc: not found, will use system allocator")
    }
} else {
    DEFINES += HAVE_JEMALLOC_HEADERS
    message("jemalloc: using CLI override")
}

linux {
    LIBS += -ldl
}
win32 {
    LIBS += -lshlwapi -lrpcrt4 -lpsapi
}

# Tell QMake all of the below is relative to src/.
VPATH += src/
INCLUDEPATH += src/

SOURCES += \
    AbstractConnection.cpp \
    App.cpp \
    BTC.cpp \
    BTC_Address.cpp \
    BitcoinD.cpp \
    BitcoinD_RPCInfo.cpp \
    BlockProc.cpp \
    CityHash.cpp \
    Common.cpp \
    Controller.cpp \
    Controller_SynchDSPsTask.cpp \
    Controller_SynchMempoolTask.cpp \
    CoTask.cpp \
    DSProof.cpp \
    Json/Json.cpp \
    Json/Json_Parser.cpp \
    Json/tests.cpp \
    Logger.cpp \
    main.cpp \
    Mempool.cpp \
    Merkle.cpp \
    Mixins.cpp \
    Mgr.cpp \
    Options.cpp \
    PeerMgr.cpp \
    RecordFile.cpp \
    ReusableBlock.cpp \
    RollingBloomFilter.cpp \
    RPC.cpp \
    RPCMsgId.cpp \
    ServerMisc.cpp \
    Servers.cpp \
    SrvMgr.cpp \
    Storage.cpp \
    SSLCertMonitor.cpp \
    SubsMgr.cpp \
    SubStatus.cpp \
    ThreadPool.cpp \
    TXO.cpp \
    Util.cpp \
    VarInt.cpp \
    Version.cpp \
    WebSocket.cpp \
    ZmqSubNotifier.cpp \
    register_MetaTypes.cpp

HEADERS += \
    AbstractConnection.h \
    App.h \
    BTC.h \
    BTC_Address.h \
    BitcoinD.h \
    BitcoinD_RPCInfo.h \
    BlockProc.h \
    BlockProcTypes.h \
    ByteView.h \
    CityHash.h \
    Common.h \
    Compat.h \
    Controller.h \
    Controller_SynchDSPsTask.h \
    CostCache.h \
    CoTask.h \
    DSProof.h \
    Json/Json.h \
    Logger.h \
    Mempool.h \
    Merkle.h \
    Mgr.h \
    Mixins.h \
    Options.h \
    PeerMgr.h \
    RecordFile.h \
    ReusableBlock.h \
    RollingBloomFilter.h \
    RPC.h \
    RPCMsgId.h \
    ServerMisc.h \
    Servers.h \
    Span.h \
    SrvMgr.h \
    Storage.h \
    SSLCertMonitor.h \
    SubsMgr.h \
    SubStatus.h \
    ThreadPool.h \
    ThreadSafeHashTable.h \
    TXO.h \
    TXO_Compact.h \
    Util.h \
    VarInt.h \
    Version.h \
    WebSocket.h \
    ZmqSubNotifier.h

# Robin Hood unordered_flat_map implememntation (single header and MUCH more efficient than unordered_map!)
HEADERS += robin_hood/robin_hood.h

# Tessil hat-trie implememntation (header only, supports prefix search and fast serialization/deserialization!)
HEADERS += \
    tsl/htrie_set.h \
    tsl/htrie_map.h \
    tsl/htrie_hash.h \
    tsl/array-hash/array_set.h \
    tsl/array-hash/array_map.h \
    tsl/array-hash/array_growth_policy.h \
    tsl/array-hash/array_hash.h

RESOURCES += \
    resources.qrc

# Bitcoin related sources & headers
SOURCES += \
    bitcoin/amount.cpp \
    bitcoin/base58.cpp \
    bitcoin/block.cpp \
    bitcoin/cashaddr.cpp \
    bitcoin/cashaddrenc.cpp \
    bitcoin/crypto/aes.cpp \
    bitcoin/crypto/chacha20.cpp \
    bitcoin/crypto/ctaes/ctaes.c \
    bitcoin/crypto/hmac_sha256.cpp \
    bitcoin/crypto/hmac_sha512.cpp \
    bitcoin/crypto/ripemd160.cpp \
    bitcoin/crypto/sha1.cpp \
    bitcoin/crypto/sha256.cpp \
    bitcoin/crypto/sha256_sse4.cpp \
    bitcoin/crypto/sha512.cpp \
    bitcoin/hash.cpp \
    bitcoin/interpreter.cpp \
    bitcoin/pubkey.cpp \
    bitcoin/script.cpp \
    bitcoin/script_error.cpp \
    bitcoin/script_standard.cpp \
    bitcoin/sigencoding.cpp \
    bitcoin/test.cpp \
    bitcoin/token.cpp \
    bitcoin/transaction.cpp \
    bitcoin/uint256.cpp \
    bitcoin/utilstrencodings.cpp \
    bitcoin/utilstring.cpp

HEADERS += \
    bitcoin/amount.h \
    bitcoin/base58.h \
    bitcoin/block.h \
    bitcoin/cashaddr.h \
    bitcoin/cashaddrenc.h \
    bitcoin/compat.h \
    bitcoin/crypto/byteswap.h \
    bitcoin/crypto/endian.h \
    bitcoin/crypto/aes.h \
    bitcoin/crypto/chacha20.h \
    bitcoin/crypto/common.h \
    bitcoin/crypto/ctaes/ctaes.h \
    bitcoin/crypto/hmac_sha256.h \
    bitcoin/crypto/hmac_sha512.h \
    bitcoin/crypto/ripemd160.h \
    bitcoin/crypto/sha1.h \
    bitcoin/crypto/sha256.h \
    bitcoin/crypto/sha512.h \
    bitcoin/hash.h \
    bitcoin/heapoptional.h \
    bitcoin/interpreter.h \
    bitcoin/litecoin_bits.h \
    bitcoin/prevector.h \
    bitcoin/pubkey.h \
    bitcoin/reverse_iterator.h \
    bitcoin/rpc/protocol.h \
    bitcoin/script.h \
    bitcoin/script_error.h \
    bitcoin/script_flags.h \
    bitcoin/script_standard.h \
    bitcoin/serialize.h \
    bitcoin/sigencoding.h \
    bitcoin/sighashtype.h \
    bitcoin/streams.h \
    bitcoin/tinyformat.h \
    bitcoin/token.h \
    bitcoin/transaction.h \
    bitcoin/txid.h \
    bitcoin/uint256.h \
    bitcoin/utilstrencodings.h \
    bitcoin/utilstring.h \
    bitcoin/utilvector.h \
    bitcoin/version.h

# Enable secp256k1 compilation on x86_64 only -- we don't actually use this lib
# yet in Fulcrum, so on platforms that aren't x86_64 it's ok to exclude it; it
# was included in case we wish to someday verify signatures in Fulcrum, etc.
contains(QT_ARCH, x86_64):!win32-msvc {
    message("Including embedded secp256k1")

    SOURCES += bitcoin/secp256k1/secp256k1.c
    HEADERS += \
        bitcoin/secp256k1/ecdsa.h \
        bitcoin/secp256k1/ecdsa_impl.h \
        bitcoin/secp256k1/eckey.h \
        bitcoin/secp256k1/eckey_impl.h \
        bitcoin/secp256k1/ecmult.h \
        bitcoin/secp256k1/ecmult_const.h \
        bitcoin/secp256k1/ecmult_const_impl.h \
        bitcoin/secp256k1/ecmult_gen.h \
        bitcoin/secp256k1/ecmult_gen_impl.h \
        bitcoin/secp256k1/ecmult_impl.h \
        bitcoin/secp256k1/field.h \
        bitcoin/secp256k1/field_10x26.h \
        bitcoin/secp256k1/field_10x26_impl.h \
        bitcoin/secp256k1/field_5x52.h \
        bitcoin/secp256k1/field_5x52_impl.h \
        bitcoin/secp256k1/field_5x52_int128_impl.h \
        bitcoin/secp256k1/field_impl.h \
        bitcoin/secp256k1/group.h \
        bitcoin/secp256k1/group_impl.h \
        bitcoin/secp256k1/hash.h \
        bitcoin/secp256k1/hash_impl.h \
        bitcoin/secp256k1/libsecp256k1-config.h \
        bitcoin/secp256k1/recovery_main_impl.h \
        bitcoin/secp256k1/schnorr_main_impl.h \
        bitcoin/secp256k1/schnorr.h \
        bitcoin/secp256k1/schnorr_impl.h \
        bitcoin/secp256k1/num.h \
        bitcoin/secp256k1/num_impl.h \
        bitcoin/secp256k1/scalar.h \
        bitcoin/secp256k1/scalar_4x64.h \
        bitcoin/secp256k1/scalar_4x64_impl.h \
        bitcoin/secp256k1/scalar_8x32.h \
        bitcoin/secp256k1/scalar_8x32_impl.h \
        bitcoin/secp256k1/scalar_impl.h \
        bitcoin/secp256k1/scalar_low.h \
        bitcoin/secp256k1/scalar_low_impl.h \
        bitcoin/secp256k1/secp256k1.h \
        bitcoin/secp256k1/secp256k1_recovery.h \
        bitcoin/secp256k1/secp256k1_schnorr.h \
        bitcoin/secp256k1/util.h
} else {
    message("Not including embedded secp256k1")
    DEFINES += DISABLE_SECP256K1
}

# Installation
unix:!android: {
    !defined(PREFIX, var) {
        PREFIX=$$(PREFIX)
        isEmpty(PREFIX) {
            PREFIX = /usr/local
        }
    }

    message("Installation dir prefix is $$PREFIX")

    target.path = $${PREFIX}/bin

    documentation.path = $${PREFIX}/share/doc/$${TARGET}
    documentation.files = doc/*

    QMAKE_STRIP = true # Trick qmake into not stripping files
    admin.path = $${PREFIX}/bin
    admin.files = FulcrumAdmin
}

!isEmpty(target.path): INSTALLS += target
!isEmpty(documentation.path): INSTALLS += documentation
!isEmpty(admin.path): INSTALLS += admin
