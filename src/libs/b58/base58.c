/**
 * @file ipomoea/base58.cpp  
 * @author Per Löwgren
 * @date Modified: 2013-12-29
 * @date Created: 2013-12-27
 * 
 * See the file COPYING for licensing details
 */ 

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <b58/base58.h>

#define __ -1

static const char base58_code[]="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int base58_index[256] = {
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __, 0, 1, 2,  3, 4, 5, 6,  7, 8,__,__, __,__,__,__, // '0'-'9'
    __, 9,10,11, 12,13,14,15, 16,__,17,18, 19,20,21,__, // 'A'-'O'
    22,23,24,25, 26,27,28,29, 30,31,32,__, __,__,__,__, // 'P'-'Z'
    __,33,34,35, 36,37,38,39, 40,41,42,43, __,44,45,46, // 'a'-'o'
    47,48,49,50, 51,52,53,54, 55,56,57,__, __,__,__,__, // 'p'-'z'
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
    __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,
};


static char *copy_of_range(const char *src,size_t from,size_t to) {
	char *dst = (char *)malloc((to-from)+1);
	memcpy(dst,&src[from],to-from);
	dst[to-from] = '\0';
	return dst;
}

static char divmod58(char number[],int start,int len) {
	int i;
	uint32_t digit256,temp,remainder = 0;
	for(i=start; i<len; i++) {
		digit256 = (uint32_t)(number[i]&0xFF);
		temp = remainder*256+digit256;
		number[i] = (char)(temp/58);
		remainder = temp % 58;
	}
	return (char)remainder;
}

static char divmod256(char number58[],int start,int len) {
	int i;
	uint32_t digit58,temp,remainder = 0;
	for(i=start; i<len; i++) {
		digit58 = (uint32_t)(number58[i]&0xFF);
		temp = remainder*58+digit58;
		number58[i] = (char)(temp/256);
		remainder = temp % 256;
	}
	return (char)remainder;
}

size_t base58_encoded_size(size_t len) {
	return ((len+4)/5)*7;
}

size_t base58_decoded_size(size_t len) {
	return (len/4)*3;
}

void base58_encode(unsigned char *dst,const unsigned char *src,size_t len) {
	*dst = '\0';
	if(len>0) {
		int tlen= len*2,j = tlen,zc = 0,start,mod;
		char *copy = copy_of_range((char*)src,0,len);
		char temp[tlen];

		while((size_t)zc<len && copy[zc]=='\0') ++zc;

		start = zc;
		while((size_t)start<len) {
			mod = divmod58(copy,start,len);
			if(copy[start]==0) ++start;
			temp[--j] = base58_code[mod];
		}

		while(j<tlen && temp[j]==base58_code[0]) ++j;

		while(--zc>=0) temp[--j] = base58_code[0];

		free(copy);
		memcpy(dst,&temp[j],tlen-j);
		dst[tlen-j] = '\0';
	}
}

int base58_decode(unsigned char *dst,const unsigned char *src) {
	int len = strlen((char*)src);
	*dst = '\0';
	if(len>0) {
		int i,j = len,c,digit58,zc = 0,start,mod;
		char input58[len];
		char temp[len];

		for(i=0; i<len; ++i) {
			c = src[i];
			digit58 = -1;
			if(c>=0 && c<128) digit58 = base58_index[c];
			if(digit58<0) {
				fprintf(stderr,"Illegal character '%c' at %d.\n",(char)c,i);
				return -1;
			}
			input58[i] = (char)digit58;
		}

		while(zc<len && input58[zc]==0) ++zc;
		start = zc;
		while(start<len) {
			mod = divmod256(input58,start,len);
			if(input58[start]==0) ++start;
			temp[--j] = mod;
		}

		while(j<len && temp[j]==0) ++j;

		memcpy(dst,&temp[j-zc],len-(j-zc));
		dst[len-(j-zc)] = '\0';
		return len-(j-zc);
	}
	return 0;
}
