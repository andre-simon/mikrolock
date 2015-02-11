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


int MlockInterface::decrypt(QString inFileName){

    std::string std_inFileName = inFileName.mid(7).toStdString();

    return minilock_decode((uint8_t*) std_inFileName.c_str(), b_my_sk, b_my_pk, c_override_out_name, c_final_out_name, sizeof c_final_out_name);
    //fprintf(stdout, "DONE c_final_out_name: %s, errcode: %d", c_final_out_name, err_code);

    /*switch (err_code){
      case  err_file_write:
        fprintf(stderr, "ERROR: could not write to file %s\n", c_final_out_name);
        break;
      case err_file_open:
        //fprintf(stderr, "ERROR: could not open file %s\n", do_dec ? c_input_file : c_final_out_name);
        break;
      case err_file_read:
        //fprintf(stderr, "ERROR: could not read file %s\n", do_dec ? c_input_file :c_final_out_name);
        break;
      case err_format:
        fprintf(stderr, "ERROR: invalid file format of %s\n", std_inFileName.c_str());
        break;
      case err_no_rcpt:
        fprintf(stderr, "ERROR: no recipients defined\n");
        break;
      default:
        break;
    }

    return err_code;*/
}

int MlockInterface::encrypt(QString inFileName, bool omitMyId, QString rcpt1, QString rcpt2, QString rcpt3) {
    std::string std_inFileName = inFileName.mid(7).toStdString();

    char* c_rcpt_list[5]= {0};
    unsigned int num_rcpts=0;

    if (rcpt1.size()){
        c_rcpt_list[num_rcpts] = (char*)rcpt1.toStdString().c_str();
        num_rcpts++;
    }
    if (rcpt2.size()){
        c_rcpt_list[num_rcpts] = (char*)rcpt2.toStdString().c_str();
        num_rcpts++;
    }
    if (rcpt3.size()){
        c_rcpt_list[num_rcpts] = (char*)rcpt3.toStdString().c_str();
        num_rcpts++;
    }

    if (!omitMyId){
        c_rcpt_list[num_rcpts] = (char*)c_minilock_id;
        num_rcpts++;
    }

    return minilock_encode((uint8_t*) std_inFileName.c_str(), c_minilock_id, b_my_sk,  b_my_pk, c_rcpt_list, num_rcpts, c_override_out_name, c_final_out_name, sizeof c_final_out_name);
}
