#ifndef _MINILOCK_H
#define _MINILOCK_H

#define VERSION "0.5"

//TODO add in win32 lib pro file
//#define QUIET_MODE 1

// for ftelloo: off_t
#define _FILE_OFFSET_BITS 64

#include "utils.h"

enum error_code { err_ok, err_failed, err_open, err_box,  err_file_open, err_file_read, err_file_write, err_hash, err_format, err_no_rcpt};
typedef enum error_code error_code;

error_code decode_file(FILE* input_file, off_t crypt_block_start, off_t eof_pos, uint8_t* b_file_nonce_prefix,
                uint8_t* b_file_key, uint8_t *c_override_out_name, uint8_t *c_out_name, size_t out_name_len, int override_out_name_as_dir);

error_code encode_file(FILE* output_file, uint8_t* b_file_nonce_prefix, uint8_t* b_file_key, uint8_t *c_input_file);

error_code minilock_encode(uint8_t* c_filename, uint8_t* c_sender_id, uint8_t* b_my_sk, char**c_rcpt_list, int num_rcpts, uint8_t *c_override_out_name, uint8_t *c_out_name, size_t out_name_len, int override_out_name_as_dir);

error_code minilock_decode(uint8_t* c_filename, uint8_t* b_my_sk, uint8_t* b_my_pk, uint8_t *c_override_out_name, uint8_t *c_out_name, size_t out_name_len, int override_out_name_as_dir);

#endif
