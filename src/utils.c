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

#include "utils.h"

struct termios oldtermios;

int ttyraw(int fd) {

    struct termios newtermios;
    if(tcgetattr(fd, &oldtermios) < 0)
        return(-1);
    newtermios = oldtermios;

    newtermios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

    newtermios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    newtermios.c_cflag &= ~(CSIZE | PARENB);

    newtermios.c_cflag |= CS8;
    /* Set 8 bits per character. */

    newtermios.c_oflag &= ~(OPOST);
    /* This includes things like expanding tabs to spaces. */

    newtermios.c_cc[VMIN] = 1;
    newtermios.c_cc[VTIME] = 0;

    /* You tell me why TCSAFLUSH. */
    if(tcsetattr(fd, TCSAFLUSH, &newtermios) < 0)
        return(-1);
    return(0);
}


int ttyreset(int fd) {
    if(tcsetattr(fd, TCSAFLUSH, &oldtermios) < 0)
        return(-1);

    return(0);
}

void sigcatch(int sig) {
    ttyreset(0);
    exit(0);
}

int array_to_number(uint8_t* array, int size) {
    int n=0;
    int i;
    for (i = size-1;  i>=0; i--) {
        n += array[i]&0xff;
        if (i > 0) {
            n = n << 8;
        }
    }
    return n;
}

void number_to_array(uint8_t* array, int size, int num ) {

    int i;
    for (i=0; i<size; i++) {
        array[i] = num ;
        num <<=8;
    }
}

void number_to_array2(uint8_t* array, int size, int num ) {

    int i;
    for (i=0; i<size; i++) {
        array[i] = num ;
        num >>=8;
    }
}

uint8_t* base64_encode(const char* b_input, int in_len) {
    /* set up a destination buffer large enough to hold the encoded data */
    uint8_t* output = (uint8_t*)malloc(in_len*2);
    /* keep track of our encoded position */
    uint8_t* c = output;
    /* store the number of bytes encoded by a single call */
    int cnt = 0;
    /* we need an encoder state */
    base64_encodestate s;

    /*---------- START ENCODING ----------*/
    /* initialise the encoder state */
    base64_init_encodestate(&s);
    /* gather data from the input and send it to the output */
    cnt = base64_encode_block(b_input, in_len, (char*)c, &s);
    c += cnt;
    /* since we have encoded the entire input string, we know that
       there is no more input data; finalise the encoding */
    cnt = base64_encode_blockend((char*)c, &s);
    c += cnt;
    /*---------- STOP ENCODING  ----------*/

    /* we want to print the encoded data, so null-terminate it: */
    *c = 0;

    return output;
}


uint8_t* base64_decode(const char *c_input, int* cnt) {
    int in_len   = strlen(c_input);
    uint8_t* output = (uint8_t*)malloc(in_len);
    uint8_t* c = output;
    *cnt = 0;
    base64_decodestate s;
    base64_init_decodestate(&s);
    *cnt = base64_decode_block(c_input, in_len, (char*)c, &s);
    c += *cnt;
    *c = 0;
    return output;
}

void dump(const char *what, uint8_t *s, int len) {
    printf("\n%s: ", what);
    for (int i=0; i<len; i++)
        printf("%02X ", (int)s[i]);
    printf("\n");
}

int blake2s_stream( FILE *stream, void *resstream ) {
    int ret = -1;
    size_t sum, n;
    blake2s_state S[1];
    static const size_t buffer_length = 1048576;
    uint8_t *buffer = ( uint8_t * )malloc( buffer_length );

    if( !buffer ) return -1;

    blake2s_init( S, KEY_LEN );

    while( 1 ) {
        sum = 0;

        while( 1 ) {
            n = fread( buffer + sum, 1, buffer_length - sum, stream );
            sum += n;

            if( buffer_length == sum )
                break;

            if( 0 == n ) {
                if( ferror( stream ) )
                    goto cleanup_buffer;

                goto final_process;
            }

            if( feof( stream ) )
                goto final_process;
        }

        blake2s_update( S, buffer, buffer_length );
    }

final_process:
    ;

    if( sum > 0 ) blake2s_update( S, buffer, sum );

    blake2s_final( S, resstream, KEY_LEN );
    ret = 0;
cleanup_buffer:
    free( buffer );
    return ret;
}

void blake_2s_array(uint8_t *b_in, int in_len, uint8_t *b_out, int out_len) {
    blake2s_state S[1];
    blake2s_init(S, out_len);
    blake2s_update(S, (const uint8_t *)b_in, in_len );
    blake2s_final(S, b_out, out_len );
}

uint8_t* get_json_b64_string(json_value *json_file_info, const char *c_node_wanted, int *b64_cnt) {
    const char *c_node_name;
    json_type node_type;
    for (unsigned int i = 0; i < json_file_info->u.object.length; i++) {
        c_node_name = json_file_info->u.object.values[i].name;
        node_type = json_file_info->u.object.values[i].value->type;
//     printf("\njson_file_info obj name %s -> %d\n", c_node_name, node_type);

        if (node_type == json_string && !strncmp((const char *)c_node_name, c_node_wanted, strlen(c_node_wanted))) {
            return base64_decode(json_file_info->u.object.values[i].value->u.string.ptr, b64_cnt);
        }
    }
    return NULL;
}

uint8_t* get_json_b58_string(json_value *json_file_info, const char *c_node_wanted, int *b58_cnt) {
    const char *c_node_name;
    json_type node_type;
    for (unsigned int i = 0; i < json_file_info->u.object.length; i++) {
        c_node_name = json_file_info->u.object.values[i].name;
        node_type = json_file_info->u.object.values[i].value->type;
        if (node_type == json_string && !strncmp((const char *)c_node_name, c_node_wanted, strlen(c_node_wanted))) {
            char* c_val   = json_file_info->u.object.values[i].value->u.string.ptr;
            int in_len   = strlen(c_val);
            /* set up a destination buffer large enough to hold the encoded data */
            uint8_t* output = (uint8_t*)malloc(in_len);

            *b58_cnt = base58_decode((unsigned char *)output , (const unsigned char*)c_val);
            return output;
        }
    }
    return NULL;
}

int get_json_integer(json_value *json_file_info, const char *c_node_wanted) {
    const char *c_node_name;
    json_type node_type;
    for (unsigned int i = 0; i < json_file_info->u.object.length; i++) {
        c_node_name = json_file_info->u.object.values[i].name;
        node_type = json_file_info->u.object.values[i].value->type;
        if (node_type == json_integer && !strncmp((const char *)c_node_name, c_node_wanted, strlen(c_node_wanted))) {
            return json_file_info->u.object.values[i].value->u.integer;
        }
    }
    return 0;
}

json_value* get_json_value (json_value *json_file_info, const char *c_node_wanted) {
    const char *c_node_name;
    json_type node_type;

    for (unsigned int i = 0; i < json_file_info->u.object.length; i++) {
        c_node_name = json_file_info->u.object.values[i].name;
        node_type = json_file_info->u.object.values[i].value->type;

        if (node_type == json_object && !strncmp((const char *)c_node_name, c_node_wanted, strlen(c_node_wanted))) {
            return json_file_info->u.object.values[i].value;
        }
    }
    return NULL;
}
