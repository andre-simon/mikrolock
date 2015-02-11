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
    uint8_t b_my_sk[KEY_LEN] = {0};
    uint8_t b_my_pk[KEY_LEN + 1]= {0};
    uint8_t c_minilock_id[KEY_LEN * 2]= {0};

    uint8_t c_override_out_name[BUF_PATH_LEN]  = {0};
    uint8_t c_final_out_name[BUF_PATH_LEN]  = {0};

    Q_OBJECT
public:
    explicit MlockInterface(QObject *parent = 0);
    ~MlockInterface();

    Q_INVOKABLE QString unlock(QString, QString);
    Q_INVOKABLE int decrypt(QString);
    Q_INVOKABLE int encrypt(QString inFileName, bool omitMyId, QString rcpt1, QString rcpt2, QString rcpt3);

signals:

public slots:
};

#endif // MLOCKINTERFACE_H
