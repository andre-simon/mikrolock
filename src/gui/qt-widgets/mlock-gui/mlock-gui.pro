#-------------------------------------------------
#
# Project created by QtCreator 2015-04-13T21:32:49
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = mikrolock-gui
TEMPLATE = app

SOURCES += main.cpp mlockmainwindow.cpp \
    showmanualdialog.cpp

HEADERS  += mlockmainwindow.h \
    showmanualdialog.h

FORMS    += mlockmainwindow.ui \
    showmanualdialog.ui

RESOURCES += mlock-gui.qrc

INCLUDEPATH += ../../../libs
INCLUDEPATH += . ../../..

QMAKE_CXXFLAGS += -std=c++11

TRANSLATIONS = mikrolock_de_DE.ts

linux {
    LIBS += -L../../.. -lmikrolock -lsodium
}

win32  {

        QT += winextras

        # *64* bit config
        INCLUDEPATH+=E:\Devel\qt-everywhere-opensource-src-5.9.0_x64\qtwinextras\include\

        DEFINES += WIN32

        INCLUDEPATH+=E:\Devel\cpp\libsodium-win64\include

        LIBS += -LE:\Devel\git\mikrolock\src -lmikrolock
        #LIBS += -LE:\Devel\cpp\libsodium-win32\lib -lsodium
        LIBS += -LE:\Devel\cpp\libsodium-win64\lib -lsodium

        DESTDIR = ..\\..\\..\\..
        RC_FILE = icon.rc

        QMAKE_POST_LINK = $$quote(E:\Devel\upx393w\upx.exe --best E:\Devel\git\mikrolock\mikrolock-gui.exe)
}
