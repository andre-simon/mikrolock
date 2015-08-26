#ifndef _UTILS_H
#define _UTILS_H

#ifndef WIN32
#include <termios.h>
#include <sys/ioctl.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <math.h>

#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_box.h>
#include <sodium/utils.h>

#include "json/json.h"
#include "libb64/b64/cencode.h"
#include "libb64/b64/cdecode.h"
#include "blake2/blake2.h"
#include "b58/base58.h"

#define KEY_LEN crypto_box_PUBLICKEYBYTES
#define NONCE_PREFIX_LEN crypto_box_PUBLICKEYBYTES/2
#define MAC_LEN  crypto_secretbox_MACBYTES

#ifndef WIN32
#define BUF_READ_FILE_LEN 1048576
#else
#define BUF_READ_FILE_LEN 1048576/2
#endif

#define BUF_PATH_LEN 256
#define BUF_DECRYPTINFO_ITEM_LEN 550

// for ftelloo: off_t
#define _FILE_OFFSET_BITS 64

// Win32 gcc ignores _FILE_OFFSET_BITS...
#ifdef WIN32
#define off_t off64_t
#endif

#ifndef WIN32
int ttyraw(int fd);
int ttyreset(int fd);
void sigcatch(int sig);
#endif


struct output_options  {
  uint8_t c_override_out_name[BUF_PATH_LEN];
  uint8_t c_final_out_name[BUF_PATH_LEN];
  int override_out_name_as_dir;
  float crypto_progress;
  float hash_progress;
  int task_mode;
  int silent_mode;
  int random_outname;
  int exclude_my_id;
};

int array_to_number(uint8_t* array, int size);

void number_to_array(uint8_t* array, int size, int num );

void number_to_array2(uint8_t* array, int size, int num );

uint8_t* base64_encode(const char *b_input, int in_len);

uint8_t* base64_decode(const char *c_input, int* cnt);

void dump(const char *what, uint8_t *s, int len);

int check_minilock_id(const unsigned char* new_id);

int blake2s_stream( FILE *stream, void *resstream,  struct output_options *out_opts);

void blake_2s_array(uint8_t *b_in, int in_len, uint8_t *b_out, int out_len);

uint8_t* get_json_b64_string(json_value *json_file_info, const char *c_node_wanted, int *b64_cnt);

uint8_t* get_json_b58_string(json_value *json_file_info, const char *c_node_wanted, int *b58_cnt);

int get_json_integer(json_value *json_file_info, const char *c_node_wanted);

json_value* get_json_value (json_value *json_file_info, const char *c_node_wanted);

#endif
