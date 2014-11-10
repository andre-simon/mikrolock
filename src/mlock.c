/*
mlock reads and writes encrypted files in the minilock format

Copyright (C) 2014 Andre Simon

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

#include <getopt.h>
#include <string.h>

#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_box.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>

#include "json/json.h"
#include "libb64/b64/cencode.h"
#include "libb64/b64/cdecode.h"
#include "blake2/blake2.h"
#include "b58/base58.h"
#include "scrypt/crypto/crypto_scrypt.h"

#include "utils.h"

#define VERSION "0.1"

#ifndef AS_SODIUM_MEMZERO
	#error "JSON lib needs to be patched to safely overwrite released memory"
#endif


int decode_file(FILE* input_file, long eof_pos, uint8_t* b_file_nonce_prefix,
		uint8_t* b_file_key, uint8_t *c_override_out_name) {
    unsigned char b_file_nonce[KEY_LEN-8]= {0};
    unsigned char b_nonce_cnt[8]= {0};
    unsigned char b_block_len[4]= {0};

    FILE *output_file=0;
    int exit_loop=0;
    int num_chunks=0;
    int chunk_len =0;
    int ret_val = EXIT_FAILURE;

    memcpy(b_file_nonce, b_file_nonce_prefix, NONCE_PREFIX_LEN);

    while (!exit_loop) {

        fread(&b_block_len, 1, sizeof(b_block_len), input_file);
        if (feof(input_file) || ferror(input_file)) {
            return EXIT_FAILURE;
        }

        chunk_len = array_to_number(b_block_len, 4) +MAC_LEN;
        uint8_t* b_chunk = (uint8_t*)malloc(chunk_len);
        uint8_t* b_decrypt_block= (uint8_t*)malloc(chunk_len);

        fread(b_chunk, 1, chunk_len, input_file);
        if (ferror(input_file)) {
            return EXIT_FAILURE;
        }

        number_to_array(b_nonce_cnt, sizeof(b_nonce_cnt), num_chunks++);

		//final chunk
        if (eof_pos   == ftell(input_file)) {
            b_nonce_cnt[7] |= 128;
            exit_loop=1;
            ret_val = EXIT_SUCCESS;
        }
        memcpy(b_file_nonce+NONCE_PREFIX_LEN, b_nonce_cnt, sizeof(b_nonce_cnt));

        int file_dec_retval  = crypto_secretbox_open_easy(b_decrypt_block, b_chunk,
                               chunk_len,b_file_nonce ,
                               (const unsigned char *)b_file_key);

        if (file_dec_retval) {
            exit_loop=1;
            goto free_encode_write_file_error;
        }

        if (num_chunks==1) {

            uint8_t* dest_file  =  (strlen((char*)c_override_out_name)) ? c_override_out_name : b_decrypt_block;

            printf("Writing to file %s...\n", dest_file);
            output_file = fopen((char *)dest_file, "wb");
            if (!output_file) {
                fprintf(stderr, "ERROR: could not write to file %s\n", dest_file);
                exit_loop=1;
                goto free_encode_write_file_error;
            }
        } else {
            if (fwrite(b_decrypt_block, 1, chunk_len-MAC_LEN, output_file) < chunk_len-MAC_LEN) {
                exit_loop=1;
                goto free_encode_write_file_error;
            }
        }
        sodium_memzero(b_decrypt_block, chunk_len);

free_encode_write_file_error:
        free(b_decrypt_block);
        free(b_chunk);
    }

    fclose(output_file);
    return ret_val;
}


int encode_file(FILE* output_file, uint8_t* b_file_nonce_prefix, uint8_t* b_file_key, uint8_t *c_input_file) {
    int ret_val = EXIT_FAILURE;

    FILE *input_file = fopen((char*)c_input_file, "r+b");
    if(input_file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s\n", c_input_file);
        return ret_val;
    }

    unsigned char b_file_nonce[KEY_LEN - 8]= {0};
    memcpy(b_file_nonce, b_file_nonce_prefix, NONCE_PREFIX_LEN);

    unsigned char b_nonce_cnt[8]= {0};
    unsigned char b_block_len[4]= {0};

    int exit_loop=0;
    int num_chunks=0;
    char b_crypt_block[BUF_READ_FILE_LEN] = {0};

    // Encode filename in the first chunk
    char b_read_buffer[BUF_READ_FILE_LEN] = {0};
    char *sep_pos = strrchr((const char*)c_input_file, '/'); //drop path

    strncpy(b_read_buffer, (sep_pos) ? (const char*)sep_pos+1 : (const char*)c_input_file, BUF_PATH_LEN-1 );
    crypto_secretbox_easy((unsigned char*)b_crypt_block, (unsigned char*)b_read_buffer,
                          BUF_PATH_LEN, b_file_nonce, b_file_key);

    //dump (" CRYPT ", b_crypt_block, BUF_PATH_LEN + MAC_LEN + 1);

    number_to_array2(b_block_len, sizeof(b_block_len), BUF_PATH_LEN  );

    fwrite(b_block_len, 1, sizeof(b_block_len), output_file);
    fwrite(b_crypt_block, 1, BUF_PATH_LEN + MAC_LEN, output_file);

    // Encode the file
    while (!exit_loop) {
        number_to_array(b_nonce_cnt, sizeof(b_nonce_cnt), ++num_chunks);
        size_t num_read = fread(&b_read_buffer, 1, sizeof(b_read_buffer), input_file);
        if ( ferror(input_file)) {
            fprintf(stderr, "ERROR: could not read file %s\n", c_input_file);
            exit_loop=1;
        }

        if (feof(input_file)) {
            exit_loop = 1;
            b_nonce_cnt[7] |= 128;
            ret_val = EXIT_SUCCESS;
        }

        memcpy(b_file_nonce+NONCE_PREFIX_LEN, b_nonce_cnt, sizeof(b_nonce_cnt));
        crypto_secretbox_easy((unsigned char*)b_crypt_block, (unsigned char*)b_read_buffer, num_read, b_file_nonce, b_file_key);

        number_to_array2(b_block_len, sizeof(b_block_len), num_read  );
        //dump ("file b_block_len ", b_block_len,4);

        fwrite(b_block_len, 1, sizeof(b_block_len), output_file);
        fwrite(b_crypt_block, 1, num_read + MAC_LEN, output_file);

        if ( ferror(output_file)) {
            fprintf(stderr, "ERROR: could not write output file\n");
            exit_loop=1;
        }

    }

    fclose(input_file);
    return ret_val;
}

int minilock_encode(uint8_t* c_filename, uint8_t* c_sender_id, uint8_t* b_my_sk, uint8_t* b_my_pk, char**c_rcpt_list, int num_rcpts, uint8_t *c_override_out_name) {

    int ret_val = EXIT_FAILURE;

    if(num_rcpts==0) {
        fprintf(stderr, "ERROR: no recipients defined\n");
        return ret_val;
    }

    char c_out_file[BUF_PATH_LEN] = {0};


    if ( strlen((char*)c_override_out_name) ) {
        snprintf(c_out_file, sizeof(c_out_file)-1, "%s", c_override_out_name);
    } else {
        snprintf(c_out_file, sizeof(c_out_file)-1, "%s.minilock", c_filename);
    }

    FILE *output_file = fopen((char*)c_out_file, "w+b");
    if(output_file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s\n", c_out_file);
        return ret_val;
    }

    //Reserve 4 bytes for the JSON header length
    uint8_t b_header[12] = {'m','i','n','i','L','o','c','k', 0, 0, 0, 0};
    fwrite(b_header, 1, sizeof(b_header), output_file);
    fwrite("{\"version\":1,", 1, 13, output_file);

    uint8_t  b_ephemeral_rnd[KEY_LEN]= {0};
    uint8_t  b_ephemeral_pk[KEY_LEN]= {0};
    uint8_t  b_file_key_rnd[KEY_LEN]= {0};
    uint8_t  b_file_nonce_rnd[KEY_LEN - 16]= {0};
    uint8_t  b_sending_nonce_rnd[KEY_LEN - 8]= {0};

    uint8_t  *c_ephemeral = 0;
    uint8_t  *c_file_key = 0;
    uint8_t  *c_file_nonce = 0;
    uint8_t  *c_sending_nonce = 0;
    uint8_t  *c_file_hash = 0;
    uint8_t  *c_file_info_crypted=0;
    uint8_t  *c_decrypt_item_crypted=0;

    char     c_ephemeral_json[128] = {0};
    char     c_file_info_json[BUF_PATH_LEN] = {0};
    char     c_decrypt_info_item_json[1024] = {0};
    char     c_decrypt_info_array_item_json[1024] = {0};

    int i=0;

    randombytes_buf(b_ephemeral_rnd, sizeof(b_ephemeral_rnd));
    randombytes_buf(b_file_key_rnd, sizeof(b_file_key_rnd));
    randombytes_buf(b_file_nonce_rnd, sizeof(b_file_nonce_rnd));

    c_file_key  = base64_encode((const char *)b_file_key_rnd, sizeof (b_file_key_rnd));
    c_file_nonce  = base64_encode((const char *)b_file_nonce_rnd, sizeof (b_file_nonce_rnd));

    crypto_scalarmult_base(b_ephemeral_pk, b_ephemeral_rnd);
    c_ephemeral  = base64_encode((const char *)b_ephemeral_pk, sizeof (b_ephemeral_pk));

    snprintf(c_ephemeral_json, sizeof(c_ephemeral_json)-1, "\"ephemeral\":\"%s\",", c_ephemeral);
    fwrite(c_ephemeral_json, 1, strlen(c_ephemeral_json), output_file);

    fwrite("\"decryptInfo\":{", 1, 15, output_file);

    long decrypt_info_block_start = ftell(output_file);

    //Reserve  bytes for the decryptInfo items
    for (i=0; i<num_rcpts*BUF_DECRYPTINFO_ITEM_LEN + 2; i++) {
        fwrite("\x20", 1, 1, output_file);
    }

    fwrite("}}", 1, 2 , output_file);

    long crypt_block_start = ftell(output_file);
    unsigned char b_json_header_len[4]= {0};
    // - magic len + len bytes + bin suffix after json header
    number_to_array2(b_json_header_len, sizeof(b_json_header_len), crypt_block_start - 12);
    fseek(output_file, 8, SEEK_SET);
    fwrite(b_json_header_len, 1, sizeof(b_json_header_len) , output_file);
    fseek(output_file, crypt_block_start, SEEK_SET);

    if (encode_file(output_file, b_file_nonce_rnd, b_file_key_rnd, c_filename))
        goto free_decode_res;

    sodium_memzero(b_file_key_rnd, sizeof (b_file_key_rnd));

    fseek(output_file, crypt_block_start, SEEK_SET);

    unsigned char b_hash[KEY_LEN] = {0};

    printf("Calculating file hash...\n");

    if( blake2s_stream( output_file, b_hash ) < 0 ) {
        goto free_decode_res;
    }

    c_file_hash  = base64_encode((const char *)b_hash, sizeof (b_hash));
    snprintf(c_file_info_json, sizeof(c_file_info_json)-1, 
	     "{\"fileKey\":\"%s\",\"fileNonce\":\"%s\",\"fileHash\":\"%s\"}", c_file_key, c_file_nonce, c_file_hash);
    sodium_memzero(c_file_key, strlen ((char*)c_file_key));

    int file_info_len  = strlen(c_file_info_json);
    uint8_t b_rcpt_list_pk[KEY_LEN + 1]= {0};
    char b_crypt_block[1024] = {0};
    int exit_loop_on_error=0;
    for (i=0; i<num_rcpts; i++) {

        randombytes_buf(b_sending_nonce_rnd, sizeof(b_sending_nonce_rnd));
        c_sending_nonce  = base64_encode((const char *)b_sending_nonce_rnd, sizeof (b_sending_nonce_rnd));

        base58_decode(b_rcpt_list_pk, (unsigned char*)c_rcpt_list[i]);
        //  dump ("rcpt public ", b_rcpt_list_pk, 33);
        b_rcpt_list_pk[KEY_LEN]=0;

        if (crypto_box_easy((unsigned char*)b_crypt_block, (unsigned char*)c_file_info_json, 
			file_info_len, b_sending_nonce_rnd, b_rcpt_list_pk, b_my_sk)) {
	    exit_loop_on_error=1;
            goto free_encode_loop_on_failure;
        }

        /////  dump ("fileinfo CRYPT ", b_crypt_block, file_info_len + 16 + 1);
        c_file_info_crypted  = base64_encode((const char *)b_crypt_block, file_info_len +16);

        snprintf(c_decrypt_info_item_json, sizeof(c_decrypt_info_item_json)-1, 
		 "{\"senderID\":\"%s\",\"recipientID\":\"%s\",\"fileInfo\":\"%s\"}", 
		 c_sender_id, c_rcpt_list[i], c_file_info_crypted);
        int decrypt_info_len  = strlen(c_decrypt_info_item_json);

        //crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, bob_publickey, alice_secretkey);
        if (crypto_box_easy((unsigned char*)b_crypt_block, (unsigned char*)c_decrypt_info_item_json, 
			decrypt_info_len, b_sending_nonce_rnd, b_rcpt_list_pk, b_ephemeral_rnd)) {
			exit_loop_on_error=1;
            goto free_encode_loop_on_failure;
        }
        //  dump ("decrypt_info_ CRYPT ", b_crypt_block, decrypt_info_len + 16 + 1);
        c_decrypt_item_crypted  = base64_encode((const char *)b_crypt_block, decrypt_info_len +16);

        snprintf(c_decrypt_info_array_item_json, sizeof(c_decrypt_info_array_item_json)-1, 
		 "\"%s\":\"%s\"%c", c_sending_nonce, c_decrypt_item_crypted,  (num_rcpts >1 && i<num_rcpts-1) ? ',':'\x20' );

        int decrypt_info_array_item_len  = strlen(c_decrypt_info_array_item_json);

        if (decrypt_info_array_item_len<500) {
			exit_loop_on_error=1;
            goto free_encode_loop_on_failure;
        }

        fseek(output_file, decrypt_info_block_start + i* BUF_DECRYPTINFO_ITEM_LEN, SEEK_SET);

        fwrite(c_decrypt_info_array_item_json, 1, decrypt_info_array_item_len , output_file);

        if ( ferror(output_file)) {
            fprintf(stderr, "ERROR: could not write output file\n");
        } else {
            if (i==num_rcpts-1) ret_val = EXIT_SUCCESS;
        }

free_encode_loop_on_failure:
        free(c_file_info_crypted);
        c_file_info_crypted=0;
        free(c_decrypt_item_crypted);
        c_decrypt_item_crypted=0;
        free (c_sending_nonce);
        c_sending_nonce=0;
	if (exit_loop_on_error) break;
    }

free_decode_res:
    free (c_ephemeral);
    free (c_file_key);
    free (c_file_nonce);
    free (c_file_hash);
    fclose(output_file);
    return ret_val;
}


int minilock_decode(uint8_t* c_filename, uint8_t* b_my_sk, uint8_t* b_my_pk, uint8_t *c_override_out_name) {

    int ret_val = EXIT_FAILURE;

    uint8_t *b_ephemeral=0;
    uint8_t *b_nonce  = 0;
    uint8_t *b_decrypt_info  = 0;

    uint8_t *b_file_key=0;
    uint8_t *b_file_nonce=0;
    uint8_t *b_file_hash=0;

    uint8_t* b_sender_id = 0;
    uint8_t* b_recipient_id = 0;
    uint8_t *b_file_info=0;

    char    *c_json_buffer = 0;

    int b64_fileinfo_cnt, b58_sender_cnt, b58_rcpt_cnt;
    int b64_cnt_key, b64_cnt_nonce, b64_cnt_hash ;

    json_value * json_header = 0;
    json_value * json_file_info =0;
    json_value * json_file_desc = 0;

    FILE *input_file = fopen((char*)c_filename, "r+b");
    if(input_file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s\n", c_filename);
        return ret_val;
    }

    uint8_t b_header[12] = {0};
    fread(&b_header, 1, sizeof(b_header), input_file);
    if (feof(input_file) || ferror(input_file)) {
        fprintf(stderr, "ERROR: could not read file %s\n", c_filename);
        goto free_decode_res;
    }

    if (strncmp((const char *)b_header, "miniLock", 8)) {
        fprintf(stderr, "ERROR: invalid file format\n");
        goto free_decode_res;
    }

    unsigned int json_header_len = array_to_number(b_header + 8, 4);

    c_json_buffer = malloc(json_header_len);

    if (fread(c_json_buffer, 1, json_header_len, input_file) < json_header_len) {
        goto free_decode_res;
    }

    //printf("c_json_buffer: %s", c_json_buffer);

    json_header = json_parse (c_json_buffer, json_header_len );

    if (!json_header || json_header->type!=json_object) {
        goto free_decode_res;
    }

    int b64_cnt, b_64_epem_cnt;


    if (get_json_integer(json_header, "version")!=1) {
        printf("WARNING: minilock file version mismatch\n");
    }

    b_ephemeral=get_json_b64_string(json_header, "ephemeral", &b_64_epem_cnt);

    if (!b_ephemeral || b_64_epem_cnt != KEY_LEN) {
        goto free_decode_res;
    }

    //dump("ephemeral", b_ephemeral, 32);

    json_value* json_decrypt_info = get_json_value (json_header, "decryptInfo");
    if (!json_decrypt_info) {
        goto free_decode_res;
    }

    for (unsigned int i = 0; i < json_decrypt_info->u.object.length; i++) {

        b_nonce  =        base64_decode(json_decrypt_info->u.object.values [i].name, &b64_cnt);
        b_decrypt_info  = base64_decode(json_decrypt_info->u.object.values [i].value->u.string.ptr, &b64_cnt);
        char c_decoded_file_desc[512] = {0};

        //crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce alice_publickey, bob_secretkey)
        int open_retval =crypto_box_open_easy(( unsigned char *)c_decoded_file_desc,
                                              (const unsigned char *)b_decrypt_info, b64_cnt,
                                              (const unsigned char *)b_nonce, b_ephemeral, b_my_sk);

        if (open_retval) {
            free (b_nonce);
            b_nonce=0;
            free (b_decrypt_info);
            b_decrypt_info=0;
            continue;
        }

        //  printf("\nVAL crypto_box_open_easy  %d %s\n", open_retval, c_decoded_file_desc);

        json_file_desc = json_parse (c_decoded_file_desc, strlen(c_decoded_file_desc) );

        sodium_memzero(c_decoded_file_desc, sizeof (c_decoded_file_desc));

        if (!json_file_desc || json_file_desc->type!=json_object) {
            goto exit_decode_loop_on_failure;
        }

        uint8_t c_decoded_file_path[BUF_PATH_LEN] = {0};
        b_sender_id = get_json_b58_string(json_file_desc, "senderID", &b58_sender_cnt);
        b_recipient_id = get_json_b58_string(json_file_desc, "recipientID", &b58_rcpt_cnt);
        b_file_info=get_json_b64_string(json_file_desc, "fileInfo", &b64_fileinfo_cnt);

        if (!b_file_info || !b_sender_id || !b_recipient_id || b58_sender_cnt!=KEY_LEN+1 || b58_rcpt_cnt!=KEY_LEN+1 ) {
            goto exit_decode_loop_on_failure;
        }

        uint8_t b_cs[1];
        blake_2s_array(b_recipient_id, KEY_LEN , b_cs, sizeof(b_cs));

        if (b_cs[0]!=b_recipient_id[KEY_LEN]) {
            goto exit_decode_loop_on_failure;
        }
        if (memcmp(b_my_pk, b_recipient_id, KEY_LEN)) {
            goto exit_decode_loop_on_failure;
        }
        blake_2s_array(b_sender_id, KEY_LEN , b_cs, sizeof(b_cs));

        if (b_cs[0]!=b_sender_id[KEY_LEN]) {
            goto exit_decode_loop_on_failure;
        }

        int open_fi_retval =crypto_box_open_easy((unsigned char *)c_decoded_file_path,
                            (const unsigned char *)b_file_info, b64_fileinfo_cnt,
                            (const unsigned char *)b_nonce,
                            b_sender_id, b_my_sk);
        // printf("\nVAL crypto_box_open_easy  %d %s\n", open_fi_retval, c_decoded_file_path);

        if (open_fi_retval) {
            goto exit_decode_loop_on_failure;
        }

        json_file_info = json_parse ((const char *)c_decoded_file_path, strlen((const char*)c_decoded_file_path) );

        sodium_memzero(c_decoded_file_path, sizeof (c_decoded_file_path));

        if (!json_file_info || json_file_info->type!=json_object) {
            goto exit_decode_loop_on_failure;
        }

        b_file_key=get_json_b64_string(json_file_info, "fileKey", &b64_cnt_key);
        b_file_nonce=get_json_b64_string(json_file_info, "fileNonce", &b64_cnt_nonce);
        b_file_hash=get_json_b64_string(json_file_info, "fileHash", &b64_cnt_hash);

        if (b64_cnt_key != KEY_LEN || b64_cnt_nonce != NONCE_PREFIX_LEN ||  b64_cnt_hash != KEY_LEN) {
            goto exit_decode_loop_on_failure;
        }
        if (!b_file_key || !b_file_nonce || !b_file_hash) {
            goto exit_decode_loop_on_failure;
        }

        long crypt_block_start = ftell(input_file);

        printf("Calculating file hash...\n");

        unsigned char hash[KEY_LEN] = {0};
        if( blake2s_stream( input_file, hash ) < 0 ) {
            goto exit_decode_loop_on_failure;
        } else if (memcmp(hash, b_file_hash, KEY_LEN)) {
            goto exit_decode_loop_on_failure;
        }

        fseek(input_file, 0, SEEK_END);
        long eof_pos   = ftell(input_file);
        fseek(input_file, crypt_block_start, SEEK_SET);

        if (decode_file(input_file, eof_pos, b_file_nonce, b_file_key, c_override_out_name)) {
            goto exit_decode_loop_on_failure;
        }
	sodium_memzero(b_file_key, b64_cnt_key);

        ret_val = EXIT_SUCCESS;

exit_decode_loop_on_failure:
        free (b_file_key);
        free (b_file_nonce);
        free (b_file_hash);

        free(b_file_info);
        free(b_sender_id);
        free(b_recipient_id);
        json_value_free (json_file_desc);
        json_value_free (json_file_info);

        goto free_decode_res;

    } // loop decryptInfo

free_decode_res:
    free(b_nonce);
    free(b_decrypt_info);
    free(b_ephemeral);
    free(c_json_buffer);
    json_value_free (json_header);
    fclose(input_file);

    return ret_val;
}

void prompt_user(const char* prompt_txt, uint8_t* input, int max_len, int is_secret){

	if (is_secret){
		// Catch the most popular signals.
	    if((long) signal(SIGINT,sigcatch) < 0) {
	        perror("signal");
	    }
	    if((long)signal(SIGQUIT,sigcatch) < 0) {
	        perror("signal");
	    }
	    if((long) signal(SIGTERM,sigcatch) < 0) {
	        perror("signal");
	    }
	    // Set raw mode on stdin.
	    if(ttyraw(0) < 0) {
	        fprintf(stderr,"ERROR Can't go to raw mode.\n");
	    }
	}
    printf("%s", prompt_txt);
    int pp_idx=0;
    uint8_t key=0;
    while( (read(0, &key, 1)) == 1 && pp_idx < max_len-1) {
		key &= 255;
        if( (is_secret && (key == 0xd || key==0x03)) || (!is_secret && key==0x0a) ) /* ASCII RETURN / CTRL+C */
            break;
        input[pp_idx++] = key;
    }

    if (is_secret){
		ttyreset(0);
    }
}

/******************************************************************************/

void print_help() {
	printf("USAGE: mlock [OPTION]...\n");
	printf("mlock reads and writes encryped miniLock files (https://minilock.io/)\n\n");
	printf("Available options:\n\n");
	printf("  -E, --encrypt <file>  Encrypt the given file (see -r)\n");
	printf("  -D, --decrypt <file>  Decrypt the given miniLock-file\n");
	printf("  -o, --output <file>   Override the target file name (assumes -D or -E)\n");
	printf("  -m, --mail <string>   Mail address (salt)\n");
	printf("  -r, --rcpt <string>   Recipient's miniLock ID (may be repeated up to 50x, assumes -E)\n");
	printf("  -x, --exclude-me      Exlude own miniLock ID from recipient list (assumes -E)\n");
	printf("  -q, --quiet           Reserved\n");
	printf("  -h, --help            Print this help screen\n");
	printf("  -v, --version         Print version information\n\n");
	printf("If neither -E nor -D is given, mlock exit_loops after showing your miniLock ID.\n");
}

void print_version(int show_license_info) {
	printf("mlock version " VERSION " Copyright 2014 Andre Simon\n");

	if (show_license_info){
	    printf("This program comes with ABSOLUTELY NO WARRANTY\n");
	    printf("This is free software, and you are welcome to redistribute it\n");
	    printf("under certain conditions listed in COPYING.\n\n");
	}
}


int check_password(const char *c_passphrase){

  size_t len  = strlen(c_passphrase);
  
  if (len<40) return 0;
  
  const char * s  = c_passphrase;
  uint8_t i;
  for (i=0; s[i]; s[i]==' ' ? i++ : *s++);
  return i > 3;
}

int main(int argc, char **argv) {

    if (argc == 1) {
        printf("USAGE: mlock [OPTIONS]\n");
        return EXIT_FAILURE;
    }
    uint8_t c_user_passphrase[256] = {0};
    uint8_t c_user_salt[256]  = {0};
    uint8_t c_input_file[BUF_PATH_LEN]  = {0};
    uint8_t c_output_file[BUF_PATH_LEN]  = {0};
    int do_enc=0, do_dec=0;
    int c;

    int exclude_me =0;
	int ret_val = EXIT_FAILURE;

    //list of minilock IDs which can decrypt the file
    char* c_rcpt_list[51]= {0};
    unsigned int num_rcpts=0;

    uint8_t b_cs[1];
    uint8_t b_rcpt_pk[KEY_LEN + 1]= {0};

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"encrypt",  required_argument, 0,  'E' },
            {"decrypt", required_argument, 0,  'D' },
            {"output",  required_argument, 0,  'o' },
            {"quiet",   no_argument,       0,  'q' },
            {"version", no_argument,       0,  'v' },
            {"help", no_argument,          0,  'h' },
            {"exclude-me", no_argument,    0,  'x' },
            {"mail",    required_argument, 0,  'm'},
            {"rcpt",    required_argument, 0,  'r' },
            {0,         0,                 0,  0 }
        };

        c = getopt_long(argc, argv, "E:D:o:qvhm:r:x",
                        long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {

        case 'm':
            snprintf((char *)c_user_salt, sizeof(c_user_salt)-1, "%s", optarg);
            break;

        case 'o':
            snprintf((char *)c_output_file, sizeof(c_output_file)-1, "%s", optarg);
            break;

        case 'v':
            print_version(0);
            return EXIT_SUCCESS;

        case 'h':
            print_help();
            return EXIT_SUCCESS;

        case 'D':
        case 'E':
            do_dec=c=='D';
            do_enc=!do_dec;
            snprintf((char *)c_input_file, sizeof(c_input_file)-1, "%s",optarg);
            break;

        case 'r':
	    if (num_rcpts+1== sizeof(c_rcpt_list)) break;
            base58_decode(b_rcpt_pk, (const unsigned char*)optarg);
            blake_2s_array(b_rcpt_pk, KEY_LEN , b_cs, sizeof(b_cs));
            if (b_cs[0]!=b_rcpt_pk[KEY_LEN]) {
                fprintf(stderr, "ERROR: invalid Minilock ID: %s\n", optarg);
                goto main_exit_on_failure;
            }
            c_rcpt_list[num_rcpts] = (char*)malloc(strlen(optarg)+1);
            snprintf(c_rcpt_list[num_rcpts], 50, "%s",optarg);
            num_rcpts++;
            break;
        case 'x':
            exclude_me = 1;
            break;
        case  '?':
            goto main_exit_on_failure;
        default:
            break;
        }
    }

	print_version(1);
	if(!strlen((const char*)c_user_salt)){
		prompt_user("Please enter your mail address:\n", c_user_salt, sizeof(c_user_salt), 0);
	}
	prompt_user("Please enter your secret passphrase:\r\n", c_user_passphrase, sizeof(c_user_passphrase), 1);

	
    if (!check_password( (const char*) c_user_passphrase)){
        fprintf(stderr, "ERROR: the passphrase must consist of several random words\n");
        goto main_exit_on_failure;
    }
   
    printf("Unlocking...\n");

    uint8_t b_passphrase_blake2[KEY_LEN] = {0};
    uint8_t b_my_sk[KEY_LEN] = {0};

    blake_2s_array(c_user_passphrase, strlen((char *)c_user_passphrase),
                   b_passphrase_blake2, KEY_LEN);

    sodium_memzero(c_user_passphrase, strlen((char *)c_user_passphrase));
    int scrypt_retval= crypto_scrypt(b_passphrase_blake2, KEY_LEN,
                                     (const uint8_t *)c_user_salt, strlen((char *)c_user_salt),
                                     131072, 8, 1,
                                     b_my_sk, sizeof (b_my_sk));
    if (scrypt_retval) {
        fprintf(stderr, "ERROR: key derivation failed\n");
        goto main_exit_on_failure;
    }

    uint8_t b_my_pk[KEY_LEN + 1]= {0};
    uint8_t c_minilock_id[KEY_LEN * 2]= {0};
    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof(b_cs));
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    printf("Your miniLock-ID: %s\n", c_minilock_id);

    if (!exclude_me) {
        c_rcpt_list[num_rcpts] = malloc(strlen((char*)c_minilock_id)+1);
        sprintf(c_rcpt_list[num_rcpts], "%s", (char*)c_minilock_id);
        num_rcpts++;
    }

    if (do_dec || do_enc) {
        printf("%scrypting file %s...\n", do_enc ? "En" : "De", c_input_file);

        if (do_dec && minilock_decode(c_input_file, b_my_sk, b_my_pk, c_output_file))
            fprintf(stderr, "ERROR: file decryption failed: %s\n", c_input_file);
        else if (do_enc && minilock_encode(c_input_file, c_minilock_id, b_my_sk, 
					  b_my_pk, c_rcpt_list, num_rcpts, c_output_file))
            fprintf(stderr, "ERROR: file encryption failed: %s\n", c_input_file);

        sodium_memzero(b_my_sk, sizeof (b_my_sk));
        printf("Task completed.\n");
    }
    ret_val = EXIT_SUCCESS;

main_exit_on_failure:
    while (num_rcpts--) {
       free(c_rcpt_list[num_rcpts]);
    }
    return ret_val;
}

/*TODO Encryption errors

Error 1: General encryption error
Decryption errors

Error 2: General decryption error
Error 3: Could not parse header
Error 4: Invalid header version
Error 5: Could not validate sender ID
Error 6: File is not encrypted for this recipient
Error 7: Could not validate ciphertext hash
*/
