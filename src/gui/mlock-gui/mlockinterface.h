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
#include <QThread>

#include <QDebug>


#include <string.h>

extern "C" {
#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include "utils.h"
#include "minilock.h"
}

class MlockInterface : public QObject
{


    Q_OBJECT
public:

    static char* c_rcpt_list[5];
    static unsigned int num_rcpts;
    static QObject *qml_root;
    static uint8_t b_my_sk[KEY_LEN] ;
    static uint8_t b_my_pk[KEY_LEN + 1];
    static uint8_t c_minilock_id[KEY_LEN * 2];
    static uint8_t c_final_out_name[BUF_PATH_LEN]  ;

    explicit MlockInterface(QObject *parent = 0);
    ~MlockInterface();

    Q_INVOKABLE bool checkMiniLockID(QString);
    Q_INVOKABLE QString unlock(QString, QString);
    Q_INVOKABLE QString localFilePath(QString);
    Q_INVOKABLE void decrypt(QString, QString);
    Q_INVOKABLE void encrypt(QString, QString, bool , QString, QString, QString);
    Q_INVOKABLE void freeMem(bool exitApp=false);

public slots:
    void handleResults(int);
};

class DecryptThread : public QThread
{
    QString inFileName, overrideOutDir;

    Q_OBJECT
    void run() Q_DECL_OVERRIDE {

        QUrl url(inFileName);
        std::string std_inFileName = url.toLocalFile().toStdString();
        std::string std_overrideOutDir= overrideOutDir.toStdString();

        int result= minilock_decode((uint8_t*) std_inFileName.c_str(),
                                    MlockInterface::b_my_sk, MlockInterface::b_my_pk,
                                    (uint8_t*)std_overrideOutDir.c_str(),
                                    MlockInterface::c_final_out_name, sizeof MlockInterface::c_final_out_name, 1);
        emit resultReady(result);
    }

public:

    void setArgs(const QString &f, const QString &o){
        inFileName  = f;
        overrideOutDir = o;
    }

signals:
    void resultReady(const int s);
};


class EncryptThread : public QThread
{
   QString inFileName, overrideOutDir;

    Q_OBJECT
    void run() Q_DECL_OVERRIDE {

        QUrl url(inFileName);
        std::string std_inFileName = url.toLocalFile().toStdString();
        std::string std_overrideOutDir= overrideOutDir.toStdString();

        int result= minilock_encode((uint8_t*) std_inFileName.c_str(), MlockInterface::c_minilock_id, MlockInterface::b_my_sk,
                                    MlockInterface::c_rcpt_list, MlockInterface::num_rcpts,
                                    (uint8_t*)std_overrideOutDir.c_str(), MlockInterface::c_final_out_name, sizeof MlockInterface::c_final_out_name, 1);
        emit resultReady(result);
    }

public:

    void setArgs(const QString &f, const QString &o){
        inFileName  = f;
        overrideOutDir = o;
    }

signals:
    void resultReady(const int s);
};



#endif // MLOCKINTERFACE_H
