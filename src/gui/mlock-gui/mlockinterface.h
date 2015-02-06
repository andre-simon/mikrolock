#ifndef MLOCKINTERFACE_H
#define MLOCKINTERFACE_H

#include <QObject>

#include <string.h>

extern "C" {
#include "scrypt/crypto/crypto_scrypt.h"
#include "utils.h"
#include "minilock.h"
}

class MlockInterface : public QObject
{
    Q_OBJECT
public:
    explicit MlockInterface(QObject *parent = 0);
    ~MlockInterface();


    Q_INVOKABLE QString unlock(QString, QString);

signals:

public slots:
};

#endif // MLOCKINTERFACE_H
