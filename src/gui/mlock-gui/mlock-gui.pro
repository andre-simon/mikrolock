TEMPLATE = app

QT += qml quick

SOURCES += main.cpp \
    mlockinterface.cpp

RESOURCES += qml.qrc


INCLUDEPATH += . ../../..
# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH =

QMAKE_CFLAGS +=

LIBS += -L../.. -lmlock
LIBS += -lm -lssl -lcrypto -lsodium

# Default rules for deployment.
include(deployment.pri)

HEADERS += \
    mlockinterface.h
