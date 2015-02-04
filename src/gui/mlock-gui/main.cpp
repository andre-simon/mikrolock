#include <QGuiApplication>
#include <QQmlEngine>
#include <qqml.h>
#include <QQmlApplicationEngine>

#include "mlockinterface.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    qmlRegisterType<MlockInterface>("de.andresimon", 1, 0, "MlockInterface");

    QQmlApplicationEngine engine;
    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

    return app.exec();
}
