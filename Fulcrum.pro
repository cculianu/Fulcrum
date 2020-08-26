#
# Fulcrum - A fast & nimble SPV Server for Bitcoin Cash
# Copyright (C) 2019-2020  Calin A. Culianu <calin.culianu@gmail.com>
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
    clang|*-g++ {
        QMAKE_CXXFLAGS_RELEASE += -fomit-frame-pointer
        QMAKE_CFLAGS_RELEASE += -fomit-frame-pointer
    }
}

macx {
    # Note: This is required because we use advanced C++ features such as std::visit
    # which requires newer Mojave+ C++ libs.  On a recent compiler SDK, this will
    # compile ok even on High Sierra with latest Xcode for High Sierra, so this requirement
    # isn't too bad.  It just affects what C++ runtime we link to on MacOS.
    QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.14
}

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# I added some Qt-specific calls to stuff inside the bitcoin:: namespace.
# This enables those functions.
DEFINES += USE_QT_IN_BITCOIN

### It is recommended you use Qt Creator to build, and that you set
### your compiler to a clang variant for maximal benefit.
### NOTE: If on a BIG ENDIAN architecture that isn't Linux, be sure to set this:
# DEFINES += WORDS_BIGENDIAN

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

# If defined, tests and benchmarks will be compiled-in to the app (accessed via --test and --bench CLI args).
#DEFINES += ENABLE_TESTS

win32-msvc {
    error("MSVC is not supported for this project. Please compile with MinGW G++ 7.3.0.")
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

# Test if rocksdb is installed and meets the minimum version requirement
qtCompileTest(rocksdb)
!contains(CONFIG, config_rocksdb) {
    # RocksDB Static Lib
    # ------------------
    #
    # Build information --
    #
    # Currently this was built from github sources of the v6.6.4 rocksdb release:
    #     https://github.com/facebook/rocksdb.git
    # Commit tag v6.6.4, commit hash (from Fri Jan 31 13:03:51 2020 -0800):
    #     551a110918493a19d11243f53408b97485de1411
    #
    # OSX:
    #   Built on Apple clang version 11.0.0 (clang-1100.0.33.17), from Xcode 113.1.
    #   command: USE_RTTI=1 PORTABLE=1 make static_lib -j4 V=1
    #   Annoyingly, the produced .a file has debug symbols which we strip with: strip -S.
    #
    # Linux:
    #   Built on Ubuntu 18.10, g++ (Ubuntu 8.2.0-7ubuntu1) 8.2.0.
    #   command: USE_RTTI=1 PORTABLE=1 make static_lib -j4 V=1
    #   Annoyingly, the produced .a file has debug symbols which we strip with: strip -g.
    #
    # Windows:
    #   Built using the MinGW G++ 7.3.0 (compiler that ships with Qt), from a cmd.exe prompt, via cmake.exe by following
    #   these steps:
    #   - Install a recent cmake into eg c:\cmake
    #   - Open up a Qt cmd.exe prompt that points to MinGW G++ 7.3.0 in the path (using the Start menu shortcut installed by
    #     Qt 5.13.2+ or Qt 5.14.1+ is easiest).
    #   - Put installed 'c:\cmake\bin' in the path so that 'cmake.exe' works from the cmd prompt, eg:
    #         set PATH=c:\cmake\bin;%PATH%
    #   - Checkout rocksdb (commit hash above), cd rocksdb
    #   - Edit CMakeLists.txt and search for '-fno-asynchronous-unwind-tables' and remove that compile option since it
    #     breaks building on MinGW against Qt, and replace it with -O3 for maximal speed.
    #   - mkdir build, cd build
    #   - Run this command from within the rocksdb/build dir that you just created:
    #         cmake .. -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_SYSTEM_NAME=Windows -G"MinGW Makefiles" -DWITH_GFLAGS=0 -DWITH_JNI=0  -DCMAKE_BUILD_TYPE=Release -DUSE_RTTI=1 -DPORTABLE=1
    #   - Build with this command:
    #         mingw32-make -j4 V=1 rocksdb  <-- will build static lib only
    #   The generated librocksdb.a will be in the build/ directory you are currently in, ready to be put into the project.
    macx {
        LIBS += -L$$PWD/staticlibs/rocksdb/bin/osx
    }
    linux {
        LIBS += -L$$PWD/staticlibs/rocksdb/bin/linux
    }
    win32 {
        win32-g++ {
            LIBS += -L$$PWD/staticlibs/rocksdb/bin/win64
        } else {
            error("This project lacks a pre-compiled static librocksdb.a for this compiler! Either add one to staticlib/rocksdb/bin/win64/ or use MinGW G++ 7.3.0.")
        }
    }
    INCLUDEPATH += $$PWD/staticlibs/rocksdb/include
    # /RocksDB Static Lib
}

macx {
    LIBS += -lrocksdb -lz -lbz2
}
linux {
    LIBS += -lrocksdb -lz -lbz2 -ldl
}
win32 {
    LIBS += -lrocksdb -lshlwapi -lrpcrt4
    contains(CONFIG, config_rocksdb) {
        LIBS += -lzstd -lbz2 -llz4 -lsnappy -lz
    }
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
    BlockProc.cpp \
    CityHash.cpp \
    Common.cpp \
    Controller.cpp \
    Json.cpp \
    Json_Parser.cpp \
    Logger.cpp \
    main.cpp \
    Mempool.cpp \
    Merkle.cpp \
    Mixins.cpp \
    Mgr.cpp \
    Options.cpp \
    PeerMgr.cpp \
    RecordFile.cpp \
    RollingBloomFilter.cpp \
    RPC.cpp \
    RPCMsgId.cpp \
    ServerMisc.cpp \
    Servers.cpp \
    SrvMgr.cpp \
    Storage.cpp \
    SubsMgr.cpp \
    ThreadPool.cpp \
    TXO.cpp \
    Util.cpp \
    Version.cpp \
    WebSocket.cpp \
    register_MetaTypes.cpp

HEADERS += \
    AbstractConnection.h \
    App.h \
    BTC.h \
    BTC_Address.h \
    BitcoinD.h \
    BlockProc.h \
    BlockProcTypes.h \
    ByteView.h \
    CityHash.h \
    Common.h \
    Compat.h \
    Controller.h \
    CostCache.h \
    Json.h \
    Json_Parser.h \
    Logger.h \
    Mempool.h \
    Merkle.h \
    Mgr.h \
    Mixins.h \
    Options.h \
    PeerMgr.h \
    RecordFile.h \
    RollingBloomFilter.h \
    RPC.h \
    RPCMsgId.h \
    ServerMisc.h \
    Servers.h \
    SrvMgr.h \
    Storage.h \
    SubsMgr.h \
    ThreadPool.h \
    ThreadSafeHashTable.h \
    TXO.h \
    TXO_Compact.h \
    Util.h \
    Version.h \
    WebSocket.h

# Robin Hood unordered_flat_map implememntation (single header and MUCH more efficient than unordered_map!)
HEADERS += robin_hood/robin_hood.h

RESOURCES += \
    resources.qrc

# Bitcoin related sources & headers
SOURCES += \
    bitcoin/amount.cpp \
    bitcoin/base58.cpp \
    bitcoin/block.cpp \
    bitcoin/support/cleanse.cpp \
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
    bitcoin/feerate.cpp \
    bitcoin/hash.cpp \
    bitcoin/interpreter.cpp \
    bitcoin/pubkey.cpp \
    bitcoin/script.cpp \
    bitcoin/script_error.cpp \
    bitcoin/script_standard.cpp \
    bitcoin/secp256k1/secp256k1.c \
    bitcoin/sigencoding.cpp \
    bitcoin/test.cpp \
    bitcoin/transaction.cpp \
    bitcoin/uint256.cpp \
    bitcoin/utilstrencodings.cpp

HEADERS += \
    bitcoin/amount.h \
    bitcoin/base58.h \
    bitcoin/block.h \
    bitcoin/cashaddr.h \
    bitcoin/cashaddrenc.h \
    bitcoin/compat.h \
    bitcoin/compat/byteswap.h \
    bitcoin/compat/endian.h \
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
    bitcoin/feerate.h \
    bitcoin/hash.h \
    bitcoin/interpreter.h \
    bitcoin/prevector.h \
    bitcoin/pubkey.h \
    bitcoin/rpc/protocol.h \
    bitcoin/script.h \
    bitcoin/script_error.h \
    bitcoin/script_flags.h \
    bitcoin/script_standard.h \
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
    bitcoin/secp256k1/util.h \
    bitcoin/streams.h \
    bitcoin/support/cleanse.h \
    bitcoin/support/zeroafterfree.h \
    bitcoin/serialize.h \
    bitcoin/sigencoding.h \
    bitcoin/sighashtype.h \
    bitcoin/tinyformat.h \
    bitcoin/transaction.h \
    bitcoin/txid.h \
    bitcoin/uint256.h \
    bitcoin/utilstrencodings.h \
    bitcoin/version.h

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
