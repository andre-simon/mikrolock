# Simple Makefile for mlock
# This file will compile the mlock binary.
# See INSTALL for instructions.

CC=gcc

LIBS=libs/

QMAKE=qmake-qt5


GUI_QT_DIR=./gui/qt-widgets/mlock-gui/

OWASP_FLAGS=-Wextra  -fPIE -Wno-unused-parameter -Wformat=2 -Wformat-security -fstack-protector-all -Wstrict-overflow

CFLAGS=-O2 -Wall ${OWASP_FLAGS} -std=gnu99 -I${LIBS} -I${LIBS}pinentry/pinentry

LDFLAGS=-lm -lsodium

# cmdline user interface
CLI_OBJECTS=mlock.o

# Qt user interface
GUI_OBJECTS:=${GUI_QT_DIR}main.cpp ${GUI_QT_DIR}mlockmainwindow.cpp

CORE_OBJECTS=minilock.o utils.o ${LIBS}b58/base58.o ${LIBS}json/json.o ${LIBS}libb64/cencode.o \
        ${LIBS}blake2/blake2s-ref.o \
        ${LIBS}libb64/cdecode.o  \
        ${LIBS}pinentry/pinentry.o

EXECUTABLE=mlock


cli: lib$(EXECUTABLE).a ${CLI_OBJECTS}
	${CC} -o $(EXECUTABLE) ${CLI_OBJECTS} -L. -l$(EXECUTABLE) ${LDFLAGS}

lib-static lib$(EXECUTABLE).a: ${CORE_OBJECTS}
	${AR} ${ARFLAGS} lib$(EXECUTABLE).a ${CORE_OBJECTS}
	
gui-qt: lib$(EXECUTABLE).a ${GUI_OBJECTS}
	cd ${GUI_QT_DIR} && ${QMAKE} 'DEFINES+=DATA_DIR=\\\"${DATA_DIR}\\\"' && $(MAKE)

clean:
	@rm -f *.o
	@rm -f ./mlock
	@rm -f *.a
	@rm -f gui/qt-widgets/mlock-gui/mlock-gui
	@rm -f gui/qt-widgets/mlock-gui/*.o
	@rm -f gui/qt-widgets/mlock-gui/qrc_*.cpp
	@rm -f gui/qt-widgets/mlock-gui/moc_*.cpp
	@rm -f gui/qt-widgets/mlock-gui/ui_*.h
	@rm -f libs/b58/base58.o
	@rm -f libs/json/json.o
	@rm -f libs/libb64/*.o
	@rm -f libs/blake2/*.o
	@rm -f libs/pinentry/*.o