#-------------------------------------------------
#
# Project created by QtCreator 2015-02-18T20:04:59
#
#-------------------------------------------------

QT -= core gui

TARGET = mikrolock
TEMPLATE = lib
QMAKE_CFLAGS += -std=c99

#does not work:
#win32: QMAKE_CFLAGS += -Wl,--stack,4194304  -Wl,--heap,4194304

SOURCES += ..\\utils.c ..\\minilock.c \
    ..\\libs\\b58\\base58.c ..\\libs\\json\\json.c ..\\libs\\libb64\\cencode.c ..\\libs\\libb64\\cdecode.c \
        ..\\libs\\blake2\\blake2s-ref.c
		
win32 {
        DESTDIR = ..
	DEFINES += WIN32

        INCLUDEPATH += ../../../libsodium-win32/include
        INCLUDEPATH += ../libs

        LIBS += -L../../libsodium-win32/lib -lsodium
}
unix {
    target.path = /usr/lib
    INSTALLS += target
}
