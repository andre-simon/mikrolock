TEMPLATE = app

QT += qml quick

SOURCES += main.cpp \
    mlockinterface.cpp


INCLUDEPATH += ../../libs
INCLUDEPATH += . ../..

RESOURCES += qml.qrc


# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH =

QMAKE_CXXFLAGS += -std=c++11 

LIBS += -lm -lssl -lcrypto -lsodium -L../.. -lmlock

# Default rules for deployment.
include(deployment.pri)

HEADERS += \
    mlockinterface.h
