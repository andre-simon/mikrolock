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

#ifndef MLOCKINTERFACE_H
#define MLOCKINTERFACE_H

#include <QObject>
#include <QUrl>

#include <string.h>

extern "C" {
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include "utils.h"
#include "minilock.h"
}

class MlockInterface : public QObject
{
    uint8_t b_my_sk[KEY_LEN] = {0};
    uint8_t b_my_pk[KEY_LEN + 1]= {0};
    uint8_t c_minilock_id[KEY_LEN * 2]= {0};
    uint8_t c_final_out_name[BUF_PATH_LEN]  = {0};

    char* c_rcpt_list[50]= {0};
    unsigned int num_rcpts=0;

    Q_OBJECT
public:
    explicit MlockInterface(QObject *parent = 0);
    ~MlockInterface();

    Q_INVOKABLE bool checkMiniLockID(QString);
    Q_INVOKABLE QString unlock(QString, QString);
    Q_INVOKABLE QString localFilePath(QString);
    Q_INVOKABLE int decrypt(QString, QString);
    Q_INVOKABLE int encrypt(QString, QString, bool , QString, QString, QString);
    Q_INVOKABLE void freeMem();

signals:

public slots:
};

#endif // MLOCKINTERFACE_H
