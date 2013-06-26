#-------------------------------------------------
#
# Project created by QtCreator 2013-06-26T10:29:43
#
#-------------------------------------------------

QT       += core network

QT       -= gui

TARGET = MarleneBridge
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    WalletClient.cpp \
    task.cpp \
    QtWalletClient.cpp \
    packetmachine.cpp \
    connectionhandler.cpp \
    cardcrypto.cpp

HEADERS += \
    WalletClient.h \
    util.h \
    task.h \
    QtWalletClient.h \
    packetmachine.h \
    connectionhandler.h \
    cardcrypto.h

unix {
LIBS += -lcrypto
}
