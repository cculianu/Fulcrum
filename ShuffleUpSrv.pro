QT -= gui
QT += network

CONFIG += c++17 console
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

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

SOURCES += \
    AbstractConnection.cpp \
    BTC.cpp \
    Mgr.cpp \
    Mixins.cpp \
    Options.cpp \
    RPC.cpp \
    SrvMgr.cpp \
    TcpServer.cpp \
    bitcoin/amount.cpp \
    bitcoin/base58.cpp \
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
    bitcoin/script.cpp \
    bitcoin/test.cpp \
    bitcoin/transaction.cpp \
    bitcoin/uint256.cpp \
    bitcoin/utilstrencodings.cpp \
    main.cpp \
    App.cpp \
    Logger.cpp \
    Util.cpp \
    EXMgr.cpp \
    Common.cpp \
    EXClient.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    AbstractConnection.h \
    App.h \
    BTC.h \
    BTC_OpCodes.h \
    Logger.h \
    Mgr.h \
    Mixins.h \
    Options.h \
    RPC.h \
    SrvMgr.h \
    TcpServer.h \
    Util.h \
    EXMgr.h \
    Common.h \
    EXClient.h \
    bitcoin/amount.h \
    bitcoin/base58.h \
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
    bitcoin/prevector.h \
    bitcoin/script.h \
    bitcoin/script_flags.h \
    bitcoin/serialize.h \
    bitcoin/tinyformat.h \
    bitcoin/transaction.h \
    bitcoin/txid.h \
    bitcoin/uint256.h \
    bitcoin/utilstrencodings.h \
    bitcoin/version.h

RESOURCES += \
    resources.qrc

