#include "mlockinterface.h"


MlockInterface::MlockInterface(QObject *parent) : QObject(parent)
{

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

    //sodium_memzero(c_user_passphrase, strlen((char *)c_user_passphrase));
    int scrypt_retval= crypto_scrypt(b_passphrase_blake2, KEY_LEN,
                                     (uint8_t*)std_salt.c_str(), std_salt.length(),
                                     131072, 8, 1,
                                     b_my_sk, sizeof b_my_sk);
    if (scrypt_retval) {
        return "ERROR: key derivation failed";
        //goto main_exit_on_failure;
    }

    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof b_cs);
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    return QString((const char*)c_minilock_id);
}


int MlockInterface::decrypt(QString inFileName, QString overrideOutName){

    std::string std_inFileName = inFileName.mid(7).toStdString();
    std::string std_overrideOutName= overrideOutName.toStdString();
    return minilock_decode((uint8_t*) std_inFileName.c_str(), b_my_sk, b_my_pk, (uint8_t*)std_overrideOutName.c_str(), c_final_out_name, sizeof c_final_out_name);
}

int MlockInterface::encrypt(QString inFileName, QString overrideOutName, bool omitMyId, QString rcpt1, QString rcpt2, QString rcpt3) {
    std::string std_inFileName = inFileName.mid(7).toStdString();
    std::string std_overrideOutName= overrideOutName.toStdString();

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

    return minilock_encode((uint8_t*) std_inFileName.c_str(), c_minilock_id, b_my_sk,  b_my_pk, c_rcpt_list, num_rcpts, (uint8_t*)std_overrideOutName.c_str(), c_final_out_name, sizeof c_final_out_name);
}

void MlockInterface::freeMem(){
    if (num_rcpts>0){
        while (num_rcpts--  ) {
            free(c_rcpt_list[num_rcpts]);
        }
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
