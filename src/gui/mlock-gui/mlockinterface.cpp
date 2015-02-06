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
    uint8_t b_my_sk[KEY_LEN] = {0};

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

    uint8_t b_my_pk[KEY_LEN + 1]= {0};
    uint8_t c_minilock_id[KEY_LEN * 2]= {0};
    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof b_cs);
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    return QString((const char*)c_minilock_id);
}
