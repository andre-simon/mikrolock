#-------------------------------------------------
#
# Project created by QtCreator 2015-04-13T21:32:49
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = mlock-gui
TEMPLATE = app

SOURCES += main.cpp mlockmainwindow.cpp

HEADERS  += mlockmainwindow.h

FORMS    += mlockmainwindow.ui

RESOURCES += mlock-gui.qrc

INCLUDEPATH += ../../../libs
INCLUDEPATH += . ../../..

QMAKE_CXXFLAGS += -std=c++11

TRANSLATIONS = mlock_de_DE.ts

linux {
    LIBS += -L../../.. -lmlock -lsodium
}

win32 {
        DEFINES += WIN32

        INCLUDEPATH+=D:\Devel\cpp\libsodium-win32\include

        LIBS += -LD:\Devel\cpp\mlock-code\src\gui\build-mlock-lib-Desktop-Release\release -lmlock
        LIBS += -LD:\Devel\cpp\libsodium-win32\lib -lsodium

        DESTDIR = ..\\..\\..
        RC_FILE = icon.rc
        QMAKE_POST_LINK = $$quote(D:\Devel\upx308w\upx.exe --best D:\Devel\cpp\mlock-code\mlock-gui.exe)
}
