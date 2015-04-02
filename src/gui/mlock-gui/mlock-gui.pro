TEMPLATE = app

QT += qml quick

SOURCES += main.cpp \
    mlockinterface.cpp


INCLUDEPATH += ../../libs
INCLUDEPATH += . ../..

RESOURCES += qml.qrc


# Additional import path used to resolve QML modules in Qt Creator's code model

QMAKE_CXXFLAGS += -std=c++11 

HEADERS += \
    mlockinterface.h

TRANSLATIONS = mlock_de_DE.ts

lupdate_only{
    SOURCES = main.qml
}

linux {
    LIBS += -L../.. -lmlock -lsodium
    # Default rules for deployment.
    include(deployment.pri)
}

win32 {
        DEFINES += WIN32

        INCLUDEPATH+=D:\Devel\cpp\libsodium-win32\include

        LIBS += -LD:\Devel\cpp\mlock-code\src\gui\build-mlock-lib-Desktop-Release\release -lmlock
        LIBS += -LD:\Devel\cpp\libsodium-win32\lib -lsodium

        DESTDIR = ..\\..\\..
        RC_FILE = icon.rc
        QMAKE_POST_LINK = $$quote(D:\Devel\upx308w\upx.exe --best D:\Devel\cpp\mlock-code\mlock-gui.exe)

        LIBS += -L"D:\Devel\qt-everywhere-opensource-src-5.4.0\qtbase\qml\QtQuick.2" -lqtquick2plugin
        LIBS += -L"D:\Devel\qt-everywhere-opensource-src-5.4.0\qtbase\qml\QtQuick\Controls" -lqtquickcontrolsplugin
        LIBS += -L"D:\Devel\qt-everywhere-opensource-src-5.4.0\qtbase\qml\QtQuick\Layouts" -lqquicklayoutsplugin
        LIBS += -L"D:\Devel\qt-everywhere-opensource-src-5.4.0\qtbase\qml\QtQuick\Dialogs" -ldialogplugin
        LIBS += -L"D:\Devel\qt-everywhere-opensource-src-5.4.0\qtbase\qml\QtQuick\Window.2" -lwindowplugin
}

DISTFILES +=
