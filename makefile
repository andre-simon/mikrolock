# Installation script for mlock.
# See INSTALL for details.

# Installation directories:

# Destination directory for installation (intended for packagers)
DESTDIR =

# Root directory for final installation
PREFIX = /usr

# Location of the binary:
bin_dir = ${PREFIX}/bin/

# Location of the man page:
man_dir = ${PREFIX}/share/man/man1/

# Location of the documentation:
doc_dir = ${PREFIX}/share/doc/mlock/

# Location of the mlock data files:
data_dir = ${PREFIX}/share/mlock/

# Location of additional gui files
desktop_apps = ${PREFIX}/share/applications/
desktop_pixmaps = ${PREFIX}/share/pixmaps/

INSTALL_DATA=install -m644
INSTALL_PROGRAM=install -m755
MKDIR=mkdir -p -m 755
RMDIR=rm -r -f

all:
	${MAKE} -C ./src -f ./makefile


install:
	@echo "This script will install mlock in the following directories:"
	@echo "Documentation directory: ${DESTDIR}${doc_dir}"
	@echo "Manual directory:        ${DESTDIR}${man_dir}"
	@echo "Binary directory:        ${DESTDIR}${bin_dir}"
	@echo

	${MKDIR} ${DESTDIR}${doc_dir}
	${MKDIR} ${DESTDIR}${man_dir}
	${MKDIR} ${DESTDIR}${bin_dir}

	${INSTALL_DATA} ./man/mlock.1.gz ${DESTDIR}${man_dir}
	${INSTALL_DATA} ./AUTHORS ${DESTDIR}${doc_dir}
	${INSTALL_DATA} ./README ${DESTDIR}${doc_dir}
	${INSTALL_DATA} ./README_DE ${DESTDIR}${doc_dir}
	${INSTALL_DATA} ./ChangeLog ${DESTDIR}${doc_dir}
	${INSTALL_DATA} ./COPYING ${DESTDIR}${doc_dir}
	${INSTALL_DATA} ./INSTALL ${DESTDIR}${doc_dir}
	${INSTALL_PROGRAM} ./src/mlock ${DESTDIR}${bin_dir}

	@echo
	@echo "Done."
	@echo "Type mlock --help or man mlock for instructions."
	@echo "Do not hesitate to report problems. Unknown bugs are hard to fix."

install-gui:
	${MKDIR} ${DESTDIR}${data_dir}
	${MKDIR} ${DESTDIR}${data_dir}l10n
	${MKDIR} ${DESTDIR}${desktop_apps} \
		${DESTDIR}${desktop_pixmaps}

	${INSTALL_DATA} ./l10n/*.qm ${DESTDIR}${data_dir}l10n
	${INSTALL_DATA} ./mlock.desktop ${DESTDIR}${desktop_apps}
	${INSTALL_DATA} ./src/gui/qt-widgets/mlock-gui/mlock.xpm ${DESTDIR}${desktop_pixmaps}
	${INSTALL_PROGRAM} ./src/gui/qt-widgets/mlock-gui/mlock-gui ${DESTDIR}${bin_dir}


gui:
	${MAKE} -C ./src -f ./makefile DATA_DIR=${data_dir}  gui-qt
	@echo
	@echo "You need to run 'make install' AND 'make install-gui' now!"
	
uninstall:
	@echo "Removing mlock files from system..."
	${RMDIR} ${DESTDIR}${doc_dir}
	rm -f ${DESTDIR}${man_dir}mlock.1.gz
	rm -f ${DESTDIR}${bin_dir}mlock
	rm -f ${DESTDIR}${bin_dir}mlock-gui
	rm -rf ${DESTDIR}${desktop_apps}mlock.desktop
	rm -rf ${DESTDIR}${desktop_pixmaps}mlock.xpm
	${RMDIR} ${DESTDIR}${data_dir}
	@echo "Done. Have a nice day!"

clean:
	$(MAKE) -C ./src -f ./makefile clean

apidocs:
	doxygen Doxyfile

help:
	@echo "This makefile offers the following options:"
	@echo
	@echo "(all)            Compile."
	@echo "install*         Copy all data files to ${data_dir}."
	@echo "clean            Remove object files and binary."
	@echo "uninstall*       Remove mlock files from system."
	@echo
	@echo "* Command needs root privileges."
	@echo "See src/makefile for compilation and linking options."

# Target needed for redhat 9.0 rpmbuild
install-strip:

.PHONY: clean all install apidocs help uninstall install-strip
