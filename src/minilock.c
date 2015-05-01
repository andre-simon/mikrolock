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

/*
Die Nachbarskinder

Wer andern gar zu wenig traut,
Hat Angst an allen Ecken;
Wer gar zu viel auf andre baut,
Erwacht mit Schrecken.

Es trennt sie nur ein leichter Zaun,
Die beiden Sorgengruender;
Zu wenig und zu viel Vertraun
Sind Nachbarskinder.

Wilhelm Busch
*/

#include "minilock.h"

#include <string.h>
#include <stdio.h>

#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_box.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>

#include "json/json.h"

#ifndef AS_SODIUM_MEMZERO
  #error "JSON lib needs to be patched to safely overwrite released memory"
#endif

#include "libb64/b64/cencode.h"
#include "libb64/b64/cdecode.h"
#include "blake2/blake2.h"
#include "b58/base58.h"
#include "utils.h"

error_code decode_file(FILE* input_file, off_t crypt_block_start, off_t eof_pos, uint8_t* b_file_nonce_prefix,
                uint8_t* b_file_key, struct output_options *out_opts) {

    unsigned char b_file_nonce[KEY_LEN-8]= {0};
    unsigned char b_nonce_cnt[8]= {0};
    unsigned char b_block_len[4]= {0};

    FILE *output_file=0;
    int exit_loop=0;
    int num_chunks=0;
    int chunk_len =0;
    error_code ret_val = err_failed;
    off_t current_pos=crypt_block_start;
    memcpy(b_file_nonce, b_file_nonce_prefix, NONCE_PREFIX_LEN);
    while (!exit_loop) {

        fread(&b_block_len, 1, sizeof b_block_len, input_file);
        if (feof(input_file) || ferror(input_file)) {
            return err_file_read;
        }

        chunk_len = array_to_number(b_block_len, 4) +MAC_LEN;
        
        uint8_t* b_chunk = (uint8_t*)malloc(chunk_len);
        uint8_t* b_decrypt_block= (uint8_t*)malloc(chunk_len);

        fread(b_chunk, 1, chunk_len, input_file);
        if (ferror(input_file)) {
            return err_file_read;
        }

        current_pos += (chunk_len + 4);
        number_to_array(b_nonce_cnt, sizeof b_nonce_cnt, num_chunks++);

	//final chunk
	if (eof_pos   == current_pos) {
            b_nonce_cnt[7] |= 128;
            exit_loop=1;
            ret_val = err_ok;
        }
        memcpy(b_file_nonce+NONCE_PREFIX_LEN, b_nonce_cnt, sizeof b_nonce_cnt);

        int file_err_retval  = crypto_secretbox_open_easy(b_decrypt_block, b_chunk,
                               chunk_len,b_file_nonce ,
                               (const unsigned char *)b_file_key);

        if (file_err_retval) {
            exit_loop=1;
            ret_val = err_open;
            goto free_encode_write_file_error;
        }

        if (num_chunks==1) {
            
            if (strlen((char*)out_opts->c_override_out_name)){
                if (out_opts->override_out_name_as_dir){
                   snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s%s", out_opts->c_override_out_name, b_decrypt_block);
                } else {
                    snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s", out_opts->c_override_out_name);
                }
            } else {
                snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s", b_decrypt_block);
            }

            if (!out_opts->silent_mode)
                printf("Writing to file %s...\n", out_opts->c_final_out_name);
            
            output_file = fopen((char *)out_opts->c_final_out_name, "wb");
            if (!output_file) {
                exit_loop=1;
                ret_val = err_file_write;
                goto free_encode_write_file_error;
            }
        } else {
            if (fwrite(b_decrypt_block, 1, chunk_len-MAC_LEN, output_file) < chunk_len-MAC_LEN) {
                exit_loop=1;
                ret_val = err_file_write;
                goto free_encode_write_file_error;
            }

            out_opts->crypto_progress = current_pos*1.0 / eof_pos * 100;
            if (!out_opts->silent_mode) {
                printf("\rProgress %3.0f%%", out_opts->crypto_progress);
                fflush(stdout);
            }
        }

free_encode_write_file_error:
        sodium_memzero(b_decrypt_block, chunk_len);
        free(b_decrypt_block);
        free(b_chunk);
    }
    

    if (!out_opts->silent_mode) printf("\n");

    if (output_file) fclose(output_file);
    return ret_val;
}


error_code encode_file(FILE* output_file, uint8_t* b_file_nonce_prefix, uint8_t* b_file_key, uint8_t *c_input_file, struct output_options *out_opts) {
    error_code ret_val = err_failed;

    FILE *input_file = fopen((char*)c_input_file, "r");
    if(input_file == NULL) {
        return err_file_read;
    }
    
    off_t current_pos=0;
    off_t eof_pos=0;
     
    fseeko(input_file, 0, SEEK_END); 
    eof_pos   = ftello(input_file);
    fseeko(input_file, 0, SEEK_SET);
    
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

    number_to_array2(b_block_len, sizeof b_block_len, BUF_PATH_LEN  );

    fwrite(b_block_len, 1, sizeof b_block_len, output_file);
    fwrite(b_crypt_block, 1, BUF_PATH_LEN + MAC_LEN, output_file);

    // Encode the file
    while (!exit_loop) {
        number_to_array(b_nonce_cnt, sizeof b_nonce_cnt, ++num_chunks);
        off_t num_read = fread(&b_read_buffer, 1, sizeof b_read_buffer, input_file);
        if ( ferror(input_file)) {
	    ret_val = err_file_read;
	    break;
        }

        if (feof(input_file)) {
            exit_loop = 1;
            b_nonce_cnt[7] |= 128;
            ret_val = err_ok;
        }
        
        current_pos += num_read;

        out_opts->crypto_progress = current_pos*1.0 / eof_pos * 100;
        if (!out_opts->silent_mode) {
            printf("\rProgress %3.0f%%", out_opts->crypto_progress);
            fflush(stdout);
        }

        memcpy(b_file_nonce+NONCE_PREFIX_LEN, b_nonce_cnt, sizeof b_nonce_cnt);
        crypto_secretbox_easy((unsigned char*)b_crypt_block, (unsigned char*)b_read_buffer, num_read, b_file_nonce, b_file_key);

        number_to_array2(b_block_len, sizeof b_block_len, num_read);

        fwrite(b_block_len, 1, sizeof b_block_len, output_file);
        fwrite(b_crypt_block, 1, num_read + MAC_LEN, output_file);

        if ( ferror(output_file)) {
           // fprintf(stderr, "ERROR: could not write output file\n"); // wenn ausserhalb kann name ausgegeben werden
	    ret_val = err_file_write;
	    break;
        }

    }

    if (!out_opts->silent_mode) printf("\n");

    fclose(input_file);
    return ret_val;
}

error_code minilock_encode(uint8_t* c_filename, uint8_t* c_sender_id, uint8_t* b_my_sk, char**c_rcpt_list, int num_rcpts, struct output_options * out_opts) {

    int ret_val = err_failed;

    if(num_rcpts==0) {
        return err_no_rcpt;
    }

    if ( strlen((char*)out_opts->c_override_out_name) ) {
        if (out_opts->override_out_name_as_dir){
            char* delim=strrchr((char*)c_filename, '/');
            char *fname= delim ? delim+1 : (char*)c_filename;
            snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s%s.minilock", out_opts->c_override_out_name, fname);
        }else {
            snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s", out_opts->c_override_out_name);
        }

    } else {
        snprintf((char*)out_opts->c_final_out_name,  sizeof out_opts->c_final_out_name-1, "%s.minilock", c_filename);
    }

    FILE *output_file = fopen((char*)out_opts->c_final_out_name, "w+b");
    if(output_file == NULL) {
        return err_file_write;
    }

    //Reserve 4 bytes for the JSON header length
    uint8_t b_header[12] = {'m','i','n','i','L','o','c','k', 0, 0, 0, 0};
    fwrite(b_header, 1, sizeof b_header, output_file);
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

    randombytes_buf(b_ephemeral_rnd, sizeof b_ephemeral_rnd);
    randombytes_buf(b_file_key_rnd, sizeof b_file_key_rnd);
    randombytes_buf(b_file_nonce_rnd, sizeof b_file_nonce_rnd);

    c_file_key  = base64_encode((const char *)b_file_key_rnd, sizeof b_file_key_rnd);
    c_file_nonce  = base64_encode((const char *)b_file_nonce_rnd, sizeof b_file_nonce_rnd);

    crypto_scalarmult_base(b_ephemeral_pk, b_ephemeral_rnd);
    c_ephemeral  = base64_encode((const char *)b_ephemeral_pk, sizeof b_ephemeral_pk);

    snprintf(c_ephemeral_json, sizeof c_ephemeral_json-1, "\"ephemeral\":\"%s\",", c_ephemeral);
    fwrite(c_ephemeral_json, 1, strlen(c_ephemeral_json), output_file);

    fwrite("\"decryptInfo\":{", 1, 15, output_file);

    off_t decrypt_info_block_start = ftello(output_file);

    //Reserve  bytes for the decryptInfo items
    for (i=0; i<num_rcpts*BUF_DECRYPTINFO_ITEM_LEN + 2; i++) {
        fwrite("\x20", 1, 1, output_file);
    }

    fwrite("}}", 1, 2 , output_file);

    off_t crypt_block_start = ftello(output_file);
    unsigned char b_json_header_len[4]= {0};
    // - magic len + len bytes + bin suffix after json header
    number_to_array2(b_json_header_len, sizeof b_json_header_len, crypt_block_start - 12);
    fseeko(output_file, 8, SEEK_SET);
    fwrite(b_json_header_len, 1, sizeof b_json_header_len, output_file);
    fseeko(output_file, crypt_block_start, SEEK_SET);

    error_code file_err_err = encode_file(output_file, b_file_nonce_rnd, b_file_key_rnd, c_filename, out_opts);
    if (file_err_err){
        ret_val = file_err_err;
        goto free_encode_res;
    }
    sodium_memzero(b_file_key_rnd, sizeof b_file_key_rnd);

    fseeko(output_file, crypt_block_start, SEEK_SET);

    unsigned char b_hash[KEY_LEN] = {0};
    
    if( blake2s_stream( output_file, b_hash , out_opts) < 0 ) {
        ret_val = err_hash;
        goto free_encode_res;
    }

    c_file_hash  = base64_encode((const char *)b_hash, sizeof b_hash);
    snprintf(c_file_info_json, sizeof c_file_info_json-1, 
	     "{\"fileKey\":\"%s\",\"fileNonce\":\"%s\",\"fileHash\":\"%s\"}", c_file_key, c_file_nonce, c_file_hash);
    sodium_memzero(c_file_key, strlen ((char*)c_file_key));

    int file_info_len  = strlen(c_file_info_json);
    uint8_t b_rcpt_list_pk[KEY_LEN + 1]= {0};
    char b_crypt_block[1024] = {0};
    int exit_loop_on_error=0;
    for (i=0; i<num_rcpts; i++) {

        randombytes_buf(b_sending_nonce_rnd, sizeof b_sending_nonce_rnd);
        c_sending_nonce  = base64_encode((const char *)b_sending_nonce_rnd, sizeof b_sending_nonce_rnd);

        base58_decode(b_rcpt_list_pk, (unsigned char*)c_rcpt_list[i]);
        b_rcpt_list_pk[KEY_LEN]=0;

        if (crypto_box_easy((unsigned char*)b_crypt_block, (unsigned char*)c_file_info_json, 
			file_info_len, b_sending_nonce_rnd, b_rcpt_list_pk, b_my_sk)) {
	    exit_loop_on_error=1;
	    ret_val = err_box;
            goto free_encode_loop_on_failure;
        }

        c_file_info_crypted  = base64_encode((const char *)b_crypt_block, file_info_len +16);

        snprintf(c_decrypt_info_item_json, sizeof c_decrypt_info_item_json-1, 
		 "{\"senderID\":\"%s\",\"recipientID\":\"%s\",\"fileInfo\":\"%s\"}", 
		 c_sender_id, c_rcpt_list[i], c_file_info_crypted);
        int decrypt_info_len  = strlen(c_decrypt_info_item_json);

        //crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, bob_publickey, alice_secretkey);
        if (crypto_box_easy((unsigned char*)b_crypt_block, (unsigned char*)c_decrypt_info_item_json, 
			decrypt_info_len, b_sending_nonce_rnd, b_rcpt_list_pk, b_ephemeral_rnd)) {
	    exit_loop_on_error=1;
	    ret_val = err_box;
            goto free_encode_loop_on_failure;
        }

        c_decrypt_item_crypted  = base64_encode((const char *)b_crypt_block, decrypt_info_len +16);

        snprintf(c_decrypt_info_array_item_json, sizeof c_decrypt_info_array_item_json-1, 
		 "\"%s\":\"%s\"%c", c_sending_nonce, c_decrypt_item_crypted,  (num_rcpts >1 && i<num_rcpts-1) ? ',':'\x20' );

        int decrypt_info_array_item_len  = strlen(c_decrypt_info_array_item_json);

        if (decrypt_info_array_item_len<500) {
	    exit_loop_on_error=1;
	    ret_val = err_format;
            goto free_encode_loop_on_failure;
        }

        fseeko(output_file, decrypt_info_block_start + i* BUF_DECRYPTINFO_ITEM_LEN, SEEK_SET);

        fwrite(c_decrypt_info_array_item_json, 1, decrypt_info_array_item_len , output_file);

        if ( ferror(output_file)) {
	    ret_val = err_file_write;
	    exit_loop_on_error=1;
        } else {
            if (i==num_rcpts-1) ret_val = err_ok;
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

free_encode_res:
    free (c_ephemeral);
    free (c_file_key);
    free (c_file_nonce);
    free (c_file_hash);
    fclose(output_file);
    return ret_val;
}


error_code minilock_decode(uint8_t* c_filename, uint8_t* b_my_sk, uint8_t* b_my_pk, struct output_options* out_opts) {

    error_code ret_val = err_not_allowed;

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

    FILE *input_file = fopen((char*)c_filename, "r");
    if(input_file == NULL) {
        return err_file_open;
    }

    uint8_t b_header[12] = {0};
    fread(&b_header, 1, sizeof b_header, input_file);
    if (feof(input_file) || ferror(input_file)) {
	ret_val = err_file_read;
        goto free_decode_res;
    }

    if (strncmp((const char *)b_header, "miniLock", 8)) {
	ret_val = err_format;
        goto free_decode_res;
    }

    unsigned int json_header_len = array_to_number(b_header + 8, 4);

    c_json_buffer = malloc(json_header_len);

    if (fread(c_json_buffer, 1, json_header_len, input_file) < json_header_len) {
        ret_val = err_format;
        goto free_decode_res;
    }

    json_header = json_parse (c_json_buffer, json_header_len );

    if (!json_header || json_header->type!=json_object) {
        ret_val = err_format;
        goto free_decode_res;
    }

    int b64_cnt, b_ephemeral_cnt;

    if (get_json_integer(json_header, "version")!=1) {
        printf("WARNING: minilock file version mismatch\n");
    }

    b_ephemeral=get_json_b64_string(json_header, "ephemeral", &b_ephemeral_cnt);

    if (!b_ephemeral || b_ephemeral_cnt != KEY_LEN) {
         ret_val = err_format;
        goto free_decode_res;
    }

    json_value* json_decrypt_info = get_json_value (json_header, "decryptInfo");
    if (!json_decrypt_info) {
        ret_val = err_format;
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

        json_file_desc = json_parse (c_decoded_file_desc, strlen(c_decoded_file_desc) );

        sodium_memzero(c_decoded_file_desc, sizeof c_decoded_file_desc);

        if (!json_file_desc || json_file_desc->type!=json_object) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }

        uint8_t c_decoded_file_path[BUF_PATH_LEN] = {0};
        b_sender_id = get_json_b58_string(json_file_desc, "senderID", &b58_sender_cnt);
        b_recipient_id = get_json_b58_string(json_file_desc, "recipientID", &b58_rcpt_cnt);
        b_file_info=get_json_b64_string(json_file_desc, "fileInfo", &b64_fileinfo_cnt);

        if (!b_file_info || !b_sender_id || !b_recipient_id || b58_sender_cnt!=KEY_LEN+1 || b58_rcpt_cnt!=KEY_LEN+1 ) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }

        uint8_t b_cs[1];
        blake_2s_array(b_recipient_id, KEY_LEN , b_cs, sizeof b_cs);

        if (b_cs[0]!=b_recipient_id[KEY_LEN]) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }
        if (memcmp(b_my_pk, b_recipient_id, KEY_LEN)) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }
        blake_2s_array(b_sender_id, KEY_LEN , b_cs, sizeof b_cs);

        if (b_cs[0]!=b_sender_id[KEY_LEN]) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }

        int open_fi_retval =crypto_box_open_easy((unsigned char *)c_decoded_file_path,
                            (const unsigned char *)b_file_info, b64_fileinfo_cnt,
                            (const unsigned char *)b_nonce,
                            b_sender_id, b_my_sk);

        if (open_fi_retval) {
            ret_val = err_open;
            goto exit_decode_loop_on_failure;
        }

        json_file_info = json_parse ((const char *)c_decoded_file_path, strlen((const char*)c_decoded_file_path) );

        sodium_memzero(c_decoded_file_path, sizeof c_decoded_file_path);

        if (!json_file_info || json_file_info->type!=json_object) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }

        b_file_key=get_json_b64_string(json_file_info, "fileKey", &b64_cnt_key);
        b_file_nonce=get_json_b64_string(json_file_info, "fileNonce", &b64_cnt_nonce);
        b_file_hash=get_json_b64_string(json_file_info, "fileHash", &b64_cnt_hash);

        if (b64_cnt_key != KEY_LEN || b64_cnt_nonce != NONCE_PREFIX_LEN ||  b64_cnt_hash != KEY_LEN) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }
        if (!b_file_key || !b_file_nonce || !b_file_hash) {
            ret_val = err_format;
            goto exit_decode_loop_on_failure;
        }

        off_t crypt_block_start = ftello(input_file);
        
        unsigned char hash[KEY_LEN] = {0};

        if( blake2s_stream( input_file, hash, out_opts ) < 0 ) {
            ret_val = err_hash;
            goto exit_decode_loop_on_failure;
        } else if (memcmp(hash, b_file_hash, KEY_LEN)) {
            ret_val = err_hash;
            goto exit_decode_loop_on_failure;
        }
        
        // calculating hash moves fp to the end
        off_t eof_pos   = ftello(input_file);
        fseeko(input_file, crypt_block_start, SEEK_SET);
        error_code file_err_err = decode_file(input_file, crypt_block_start, eof_pos, b_file_nonce, b_file_key, out_opts);
        if (file_err_err) {
            ret_val = file_err_err;
            goto exit_decode_loop_on_failure;
        }
        ret_val = err_ok;

exit_decode_loop_on_failure:
	sodium_memzero(b_file_key, b64_cnt_key);
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
