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
#include <stdio.h>

#include <sodium/crypto_pwhash_scryptsalsa208sha256.h>
#include "pinentry/pinentry.h"

#include "utils.h"
#include "minilock.h"

// sadasfsa fff as fasf assffasf saf as fsa fas

extern int silent_mode;

void prompt_tty(const char* prompt_txt, uint8_t* input, int max_len, int is_secret){

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

int check_password(const char *c_passphrase){

  size_t len  = strlen(c_passphrase);
  
  if (len<40) return 0;
  
  const char * s  = c_passphrase;
  uint8_t i;
  for (i=0; s[i]; s[i]==' ' ? i++ : *s++);
  return i > 3;
}


/******************************************************************************/

void print_help() {
	printf("USAGE: mlock [OPTION]...\n");
	printf("mlock reads and writes encrypted miniLock files (https://minilock.io/)\n\n");
	printf("Available options:\n\n");
	printf("  -E, --encrypt <file>  Encrypt the given file (see -r)\n");
	printf("  -D, --decrypt <file>  Decrypt the given miniLock file\n");
	printf("  -o, --output <file>   Override the target file name (assumes -D or -E)\n");
	printf("  -m, --mail <string>   Mail address (salt)\n");
	printf("  -r, --rcpt <string>   Recipient's miniLock ID (may be repeated up to 50x, assumes -E)\n");
	printf("  -x, --exclude-me      Exlude own miniLock ID from recipient list (assumes -E)\n");
	printf("  -p, --pinentry        Use pinentry program to ask for the passphrase\n");
	printf("  -q, --quiet           Do not print progress information\n");
	printf("  -h, --help            Print this help screen\n");
	printf("  -v, --version         Print version information\n\n");
	printf("If neither -E nor -D is given, mlock exits after showing your miniLock ID.\n");
}

void print_version(int show_license_info) {
        printf("mlock version " VERSION " Copyright 2014, 2015 Andre Simon\n");

	if (show_license_info){
	    printf("This program comes with ABSOLUTELY NO WARRANTY\n");
	    printf("This is free software, and you are welcome to redistribute it\n");
	    printf("under certain conditions listed in COPYING.\n\n");
	}
}

int main(int argc, char **argv) {

    if (argc == 1) {
        printf("USAGE: mlock [OPTIONS]\n");
        return EXIT_FAILURE;
    }
    uint8_t c_user_passphrase[256] = {0};
    uint8_t c_user_salt[256]  = {0};
    uint8_t c_input_file[BUF_PATH_LEN]  = {0};
    uint8_t c_override_out_name[BUF_PATH_LEN]  = {0};
    uint8_t c_final_out_name[BUF_PATH_LEN]  = {0};
    
    int do_enc=0, do_dec=0;
    int use_pinentry=0;
    
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
            {"encrypt", required_argument, 0, 'E' },
            {"decrypt", required_argument, 0, 'D' },
            {"output",  required_argument, 0, 'o' },
            {"quiet",   no_argument,       0, 'q' },
            {"version", no_argument,       0, 'v' },
            {"help", no_argument,          0, 'h' },
            {"exclude-me", no_argument,    0, 'x' },
	    {"pinentry", no_argument,      0, 'p' },
            {"mail",    required_argument, 0, 'm' },
            {"rcpt",    required_argument, 0, 'r' },
            {0,         0,                 0, 0 }
        };

        c = getopt_long(argc, argv, "E:D:o:qvhm:r:xp",
                        long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {

        case 'm':
            snprintf((char *)c_user_salt, sizeof c_user_salt-1, "%s", optarg);
            break;

        case 'o':
            snprintf((char *)c_override_out_name, sizeof c_override_out_name-1, "%s", optarg);
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
            snprintf((char *)c_input_file, sizeof c_input_file-1, "%s",optarg);
            break;

        case 'r':
	    if (num_rcpts+1== sizeof c_rcpt_list) break;
	    
	    if (strlen(optarg)>46) {
                fprintf(stderr, "ERROR: invalid Minilock ID: %s\n", optarg);
                goto main_exit_on_failure;
            }
            base58_decode(b_rcpt_pk, (const unsigned char*)optarg);
            blake_2s_array(b_rcpt_pk, KEY_LEN , b_cs, sizeof b_cs);
            if (b_cs[0]!=b_rcpt_pk[KEY_LEN]) {
                fprintf(stderr, "ERROR: invalid Minilock ID: %s\n", optarg);
                goto main_exit_on_failure;
            }
            c_rcpt_list[num_rcpts] = (char*)malloc(strlen(optarg)+1);
            snprintf(c_rcpt_list[num_rcpts], strlen(optarg)+1, "%s",optarg);
            num_rcpts++;
            break;
        case 'x':
            exclude_me = 1;
            break;
	case 'p':
            use_pinentry = 1;
            break;
	case 'q':
            silent_mode = 1;
            break;
        case  '?':
            goto main_exit_on_failure;
        default:
            break;
        }
    }

    print_version(1);
    if(!strlen((const char*)c_user_salt)){
	prompt_tty("Please enter your mail address:\n", c_user_salt, sizeof c_user_salt, 0);
    }
    
    if (!use_pinentry ||  prompt_pinentry((const char*)c_user_salt, c_user_passphrase, sizeof c_user_passphrase)<0){
      prompt_tty("Please enter your secret passphrase:\r\n", c_user_passphrase, sizeof c_user_passphrase, 1);
    }
    
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

    int scrypt_retval= crypto_pwhash_scryptsalsa208sha256_ll(b_passphrase_blake2, KEY_LEN,
                                     (const uint8_t *)c_user_salt, strlen((char *)c_user_salt),
                                     131072, 8, 1,
                                     b_my_sk, sizeof b_my_sk);

    if (scrypt_retval) {
        fprintf(stderr, "ERROR: key derivation failed\n");
        goto main_exit_on_failure;
    }

    uint8_t b_my_pk[KEY_LEN + 1]= {0};
    uint8_t c_minilock_id[KEY_LEN * 2]= {0};
    crypto_scalarmult_base(b_my_pk, b_my_sk);

    blake_2s_array(b_my_pk, KEY_LEN , b_cs, sizeof b_cs);
    b_my_pk[KEY_LEN] = b_cs[0];

    base58_encode((unsigned char *)c_minilock_id, b_my_pk, KEY_LEN + 1);

    printf("Your miniLock-ID: %s\n", c_minilock_id);

    if (do_dec || do_enc) {
      
        printf("%scrypting file %s...\n", do_enc ? "En" : "De", c_input_file);

	if (do_enc && !exclude_me) {
	  c_rcpt_list[num_rcpts] = malloc(strlen((char*)c_minilock_id)+1);
	  sprintf(c_rcpt_list[num_rcpts], "%s", (char*)c_minilock_id);
	  num_rcpts++;
	}

	if (do_dec || do_enc){
	  error_code err_code;
	  if (do_dec) 
            err_code = minilock_decode(c_input_file, b_my_sk, b_my_pk, c_override_out_name, c_final_out_name, sizeof c_final_out_name, 0);
	  else
            err_code = minilock_encode(c_input_file, c_minilock_id, b_my_sk, c_rcpt_list, num_rcpts, c_override_out_name, c_final_out_name, sizeof c_final_out_name, 0);
	  
	  
	  switch (err_code){
	    case err_ok:
	      break;
	    case  err_file_write:
	      fprintf(stderr, "ERROR: could not write to file %s\n", c_final_out_name);
	      break;
	    case err_file_open:
	      fprintf(stderr, "ERROR: could not open file %s\n", do_dec ? c_input_file : c_final_out_name);
	      break;
	    case err_file_read:  
	      fprintf(stderr, "ERROR: could not read file %s\n", do_dec ? c_input_file :c_final_out_name);
	      break;
	    case err_format:
	      fprintf(stderr, "ERROR: invalid file format of %s\n", c_input_file);
	      break;
	    case err_no_rcpt:
	      fprintf(stderr, "ERROR: no recipients defined\n");
	      break;
	    case  err_failed:
	     fprintf(stderr, "ERROR: undefined error\n");
	      break;
	    case err_open:
	     fprintf(stderr, "ERROR: could not decrypt data\n");
	      break;
	    case err_box:
	      fprintf(stderr, "ERROR: could not crypt data\n");
	      break;
	    case err_hash:
	      fprintf(stderr, "ERROR: could not hash data\n");
	      break;
	  }
	}
	
        sodium_memzero(b_my_sk, sizeof b_my_sk);
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

https://www.securecoding.cert.org/confluence/display/seccode/FIO19-C.+Do+not+use+fseeko()+and+ftello()+to+compute+the+size+of+a+regular+file
https://www.securecoding.cert.org/confluence/display/seccode/FIO03-C.+Do+not+make+assumptions+about+fopen%28%29+and+file+creation
*/
