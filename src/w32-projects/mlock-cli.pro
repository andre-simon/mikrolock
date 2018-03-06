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
	
        INCLUDEPATH+=E:\Devel\cpp\libsodium-win64\include

        LIBS += -L.. -lmikrolock
   #     LIBS += -LE:\Devel\cpp\libsodium-win32\lib -lsodium

        LIBS += -LE:\Devel\cpp\libsodium-win64\lib -lsodium

        DESTDIR = ..\\..
        QMAKE_POST_LINK = $$quote(E:\Devel\upx393w\upx.exe --best E:\Devel\git\mikrolock\mikrolock.exe)
}

