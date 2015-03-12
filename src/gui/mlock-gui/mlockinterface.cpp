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

#include "mlockinterface.h"

QObject *MlockInterface::qml_root = 0;


char* MlockInterface::c_rcpt_list[5]= {0};
unsigned int MlockInterface::num_rcpts=0;

uint8_t MlockInterface::b_my_sk[KEY_LEN] = {0};
uint8_t MlockInterface::b_my_pk[KEY_LEN + 1]= {0};
uint8_t MlockInterface::c_minilock_id[KEY_LEN * 2]= {0};
uint8_t MlockInterface::c_final_out_name[BUF_PATH_LEN]  = {0};

extern int silent_mode;

MlockInterface::MlockInterface(QObject *parent) : QObject(parent)
{
    silent_mode=1;
}

MlockInterface::~MlockInterface()
{
}

QString MlockInterface::unlock(QString passphrase, QString salt){

    std::string std_passphrase = passphrase.toStdString();
    std::string std_salt  = salt.toStdString();

    uint8_t b_cs[1];
    uint8_t b_passphrase_blake2[KEY_LEN] = {0};


    blake_2s_array((uint8_t*)std_passphrase.c_str(), std_passphrase.length(),
                   b_passphrase_blake2, KEY_LEN);

    int scrypt_retval= crypto_pwhash_scryptsalsa208sha256_ll(b_passphrase_blake2, KEY_LEN,
                                     (uint8_t*)std_salt.c_str(), std_salt.length(),
                                     131072, 8, 1,
                                     b_my_sk, sizeof b_my_sk);
    if (scrypt_retval) {
        return "ERROR: key derivation failed";
    }

    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof b_cs);
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    return QString((const char*)c_minilock_id);
}


void MlockInterface::decrypt(QString inFileName, QString overrideOutDir){
    MlockInterface::qml_root->setProperty("isBusy", true);
    DecryptThread *workerThread = new DecryptThread();
    workerThread->setArgs(inFileName, overrideOutDir);
    connect(workerThread, &DecryptThread::resultReady, this, &MlockInterface::handleResults);
    connect(workerThread, &DecryptThread::finished, workerThread, &QObject::deleteLater);
    workerThread->start();
}

void MlockInterface::handleResults(int result){
   // qDebug()<<"handleResults  "<<result;
    MlockInterface::qml_root->setProperty("isBusy", false);
    MlockInterface::qml_root->setProperty("errorCode", result);
    MlockInterface::qml_root->setProperty("resultString", result ? "FAILED":"SUCCESS");
}

void MlockInterface::encrypt(QString inFileName, QString overrideOutDir, bool omitMyId, QString rcpt1, QString rcpt2, QString rcpt3) {

    freeMem();

    if (!omitMyId){
        c_rcpt_list[num_rcpts] = (char*)malloc(strlen((char*)c_minilock_id)+1);
        snprintf(c_rcpt_list[num_rcpts], strlen((char*)c_minilock_id)+1, "%s",(char*)c_minilock_id);
        num_rcpts++;
    }

    if (rcpt1.size()){
        c_rcpt_list[num_rcpts] =  (char*)malloc(rcpt1.size()+1);
        snprintf(c_rcpt_list[num_rcpts], rcpt1.size()+1, "%s",(char*)rcpt1.toStdString().c_str());
        num_rcpts++;
    }
    if (rcpt2.size()){
        c_rcpt_list[num_rcpts] =  (char*)malloc(rcpt2.size()+1);
        snprintf(c_rcpt_list[num_rcpts], rcpt2.size()+1, "%s",(char*)rcpt2.toStdString().c_str());
        num_rcpts++;
    }
    if (rcpt3.size()){
        c_rcpt_list[num_rcpts] =  (char*)malloc(rcpt3.size()+1);
        snprintf(c_rcpt_list[num_rcpts], rcpt3.size()+1, "%s",(char*)rcpt3.toStdString().c_str());
        num_rcpts++;
    }

    MlockInterface::qml_root->setProperty("isBusy", true);
    EncryptThread *workerThread = new EncryptThread();
    workerThread->setArgs(inFileName, overrideOutDir);
    connect(workerThread, &EncryptThread::resultReady, this, &MlockInterface::handleResults);
    connect(workerThread, &EncryptThread::finished, workerThread, &QObject::deleteLater);
    workerThread->start();
}

void MlockInterface::freeMem(bool exitApp){
    if (num_rcpts>0){
        while (num_rcpts--  ) {
            free(c_rcpt_list[num_rcpts]);
        }
    }
    num_rcpts=0;

    if (exitApp){
        sodium_memzero( b_my_sk, sizeof b_my_sk);
    }
}

bool MlockInterface::checkMiniLockID(QString id){
    if (id.isEmpty()) return true;

     std::string std_id= id.toStdString();
    uint8_t b_rcpt_pk[KEY_LEN + 1]= {0};
    uint8_t b_cs[1];

    base58_decode(b_rcpt_pk, (const unsigned char*)std_id.c_str());
    blake_2s_array(b_rcpt_pk, KEY_LEN , b_cs, sizeof b_cs);
    return b_cs[0]==b_rcpt_pk[KEY_LEN];
}

QString MlockInterface::localFilePath(QString s){
    QUrl url(s);
    return url.toLocalFile();
}
