QT -= gui
QT += network testlib websockets

CONFIG += c++17 console
CONFIG -= app_bundle

# Test for ability to use c++latest; requires Qt 5.12.0 or above
greaterThan(QT_MAJOR_VERSION, 4):greaterThan(QT_MINOR_VERSION, 12) {
    # Qt 5.13+ supports "c++latest"
    CONFIG -= c++17
    CONFIG += c++latest
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

win32-msvc {
    QMAKE_CXXFLAGS += /std:c++17
}
win32 {
    CONFIG += warn_off
}
linux {
    QMAKE_CXXFLAGS += -std=c++1z
    DEFINES += HAVE_ENDIAN_H HAVE_DECL_HTOBE16 HAVE_DECL_HTOLE16 HAVE_DECL_BE16TOH HAVE_DECL_LE16TOH HAVE_DECL_HTOBE32 \
               HAVE_DECL_HTOLE32 HAVE_DECL_BE32TOH HAVE_DECL_LE32TOH HAVE_DECL_HTOBE64 HAVE_DECL_HTOLE64 HAVE_DECL_BE64TOH \
               HAVE_DECL_LE64TOH
}

SOURCES += \
    AbstractConnection.cpp \
    BTC.cpp \
    BitcoinD.cpp \
    Mgr.cpp \
    Mixins.cpp \
    Options.cpp \
    RPC.cpp \
    Servers.cpp \
    SrvMgr.cpp \
    main.cpp \
    App.cpp \
    Logger.cpp \
    Util.cpp \
    Common.cpp \
    register_MetaTypes.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    AbstractConnection.h \
    App.h \
    BTC.h \
    BitcoinD.h \
    Common.h \
    Logger.h \
    Mgr.h \
    Mixins.h \
    Options.h \
    RPC.h \
    Servers.h \
    SrvMgr.h \
    Util.h

RESOURCES += \
    resources.qrc

# Bitcoin related stuff
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
    bitcoin/script.h \
    bitcoin/script_error.h \
    bitcoin/script_flags.h \
    bitcoin/script_standard.h \
    bitcoin/serialize.h \
    bitcoin/sigencoding.h \
    bitcoin/sighashtype.h \
    bitcoin/tinyformat.h \
    bitcoin/transaction.h \
    bitcoin/txid.h \
    bitcoin/uint256.h \
    bitcoin/utilstrencodings.h \
    bitcoin/version.h \
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
    bitcoin/support/zeroafterfree.h

