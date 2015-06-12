#ifndef _MINILOCK_H
#define _MINILOCK_H

#define MLOCK_VERSION "0.13"

// for ftelloo: off_t
#define _FILE_OFFSET_BITS 64

#include "utils.h"

enum error_code { 
  err_ok, err_failed, err_open, err_box,  
  err_file_open, err_file_read, err_file_write, 
  err_hash, err_format, err_no_rcpt, err_not_allowed, 
  err_file_empty, err_file_exists
};
typedef enum error_code error_code;

struct rcpt_list {
  char id[50];
  struct rcpt_list* next;
};

error_code file_decode(FILE* input_file, off_t crypt_block_start, off_t eof_pos, uint8_t* b_file_nonce_prefix,
                uint8_t* b_file_key, struct output_options* out_opts);

error_code file_encode(FILE* output_file, uint8_t* b_file_nonce_prefix, uint8_t* b_file_key, uint8_t *c_input_file, struct output_options* out_opts);

error_code minilock_encode(uint8_t* c_filename, uint8_t* c_sender_id, uint8_t* b_my_sk, struct rcpt_list* id_list, struct output_options* out_opts);

error_code minilock_decode(uint8_t* c_filename, uint8_t* b_my_sk, uint8_t* b_my_pk, struct output_options* out_opts);

int rcpt_list_add(struct rcpt_list** list, char* id);

void rcpt_list_free(struct rcpt_list** list);

#endif
