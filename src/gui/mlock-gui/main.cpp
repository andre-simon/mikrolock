/*
mlock reads and writes encrypted files in the minilock format

Copyright (C) 2015 Andre Simon

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <QGuiApplication>
#include <QQmlEngine>

#include <QTranslator>
#include <QLocale>
#include <QDir>

#include <qqml.h>
#include <QQmlApplicationEngine>

#include "mlockinterface.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    QTranslator translator;
    #ifdef DATA_DIR
     translator.load(QString("%1/l10n/mlock_%2").arg(DATA_DIR).arg(QLocale::system().name()));
    #else
     translator.load(QString("%1/l10n/mlock_%2").arg(QDir::currentPath()).arg(QLocale::system().name()));
    #endif
    app.installTranslator(&translator);

    qmlRegisterType<MlockInterface>("de.andresimon", 1, 0, "MlockInterface");

    QQmlApplicationEngine engine;
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

    return app.exec();
}
