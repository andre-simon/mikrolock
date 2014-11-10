#ifndef _UTILS_H
#define _UTILS_H

#include <signal.h>
#include <termios.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
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

#define BUF_READ_FILE_LEN 1048576
#define BUF_PATH_LEN 256
#define BUF_DECRYPTINFO_ITEM_LEN 550


int ttyraw(int fd);

int ttyreset(int fd);

void sigcatch(int sig);

int array_to_number(uint8_t* array, int size);

void number_to_array(uint8_t* array, int size, int num );

void number_to_array2(uint8_t* array, int size, int num );

uint8_t* base64_encode(const char *b_input, int in_len);

uint8_t* base64_decode(const char *c_input, int* cnt);

void dump(const char *what, uint8_t *s, int len);

int blake2s_stream( FILE *stream, void *resstream );

void blake_2s_array(uint8_t *b_in, int in_len, uint8_t *b_out, int out_len);

uint8_t* get_json_b64_string(json_value *json_file_info, const char *c_node_wanted, int *b64_cnt);

uint8_t* get_json_b58_string(json_value *json_file_info, const char *c_node_wanted, int *b58_cnt);

int get_json_integer(json_value *json_file_info, const char *c_node_wanted);

json_value* get_json_value (json_value *json_file_info, const char *c_node_wanted);

#endif
