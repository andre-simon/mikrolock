QT -= core gui
TARGET = mikrolock
CONFIG += console
CONFIG -= app_bundle
TEMPLATE = app


SOURCES += ../mikrolock.c

INCLUDEPATH += ../libs ../../

#does not work:
#win32: QMAKE_CXXFLAGS += -Wl,--stack,4194304 -Wl,--heap=4194304

QMAKE_CXXFLAGS += -std=c++11 

unix:LIBS += -lm -lsodium -L.. -lmikrolock
win32 {
        DEFINES += WIN32
	
        INCLUDEPATH+=D:\Devel\cpp\libsodium-win32\include

        LIBS += -L.. -lmikrolock
	LIBS += -LD:\Devel\cpp\libsodium-win32\lib -lsodium

        DESTDIR = ..\\..
        QMAKE_POST_LINK = $$quote(D:\Devel\upx391w\upx.exe --best D:\Devel\cpp\mlock-code\mikrolock.exe)
}

