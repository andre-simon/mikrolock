#ifndef MLOCKINTERFACE_H
#define MLOCKINTERFACE_H

#include <QObject>

class MlockInterface : public QObject
{
    Q_OBJECT
public:
    explicit MlockInterface(QObject *parent = 0);
    ~MlockInterface();


    Q_INVOKABLE QString aufruf(QString test){
      return QString(test + " BLA");
    }


signals:

public slots:
};

#endif // MLOCKINTERFACE_H
