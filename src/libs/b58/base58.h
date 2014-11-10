#ifndef _IPOMOEA_BASE58_H
#define _IPOMOEA_BASE58_H

/**
 * @file ipomoea/base58.h  
 * @author Per Löwgren
 * @date Modified: 2013-12-29
 * @date Created: 2013-12-27
 * 
 * See the file COPYING for licensing details
 */ 

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

/** Calculation is approximate, slightly larger than actual encoded size to account for margin. */
size_t base58_encoded_size(size_t len);
/** Calculation is approximate, slightly larger than actual decoded size to account for margin. */
size_t base58_decoded_size(size_t len);

void base58_encode(unsigned char *dst,const unsigned char *src,size_t len);
int base58_decode(unsigned char *dst,const unsigned char *src);


#ifdef __cplusplus
}
#endif

#endif /* _IPOMOEA_BASE58_H */