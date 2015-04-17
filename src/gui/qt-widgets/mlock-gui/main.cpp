#include "mlockmainwindow.h"
#include <QtGlobal>

#if (QT_VERSION < QT_VERSION_CHECK(5,0,0))
#include <QtGui/QApplication>
#else
#include <QtWidgets/QApplication>
#endif
#include <QTranslator>
#include <QLocale>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QTranslator translator;
        #ifdef DATA_DIR
         translator.load(QString("%1/l10n/mlock_%2").arg(DATA_DIR).arg(QLocale::system().name()));
        #else
         translator.load(QString("%1/gui_files/l10n/mlock_%2").arg(QDir::currentPath()).arg(QLocale::system().name()));
        #endif
        app.installTranslator(&translator);


    MlockMainWindow w;
    w.show();

    QStringList args=QCoreApplication::arguments();
    if (args.count()>1){
        w.setInitialInputFile(args[1]);
    }

    return app.exec();
}
