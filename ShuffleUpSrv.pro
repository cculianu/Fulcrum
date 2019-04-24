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

SOURCES += \
    main.cpp \
    App.cpp \
    Logger.cpp \
    Util.cpp \
    EXMgr.cpp \
    Common.cpp \
    EXClient.cpp \
    bitcoin/bignum.cpp \
    bitcoin/test.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    App.h \
    Logger.h \
    Util.h \
    EXMgr.h \
    Common.h \
    EXClient.h \
    bitcoin/base58.h \
    bitcoin/bignum.h \
    bitcoin/uint256.h \
    bitcoin/util.h

RESOURCES += \
    resources.qrc

# Needed for OpenSSL.  Modify this for your platform  FIXME: add Windows support
unix: LIBS += -L/opt/local/lib/ -lssl -lcrypto
INCLUDEPATH += /opt/local/include
DEPENDPATH += /opt/local/include
