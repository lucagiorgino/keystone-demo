#ifndef _EH_SHARED_H_
#define _EH_SHARED_H_

#include <malloc.h>

#define FILE_CLIENT_KEYS_SIGNATURE 1
#define FILE_CLIENT_VC_SIGNATURE 2

/* *
 * This file is shared between
 * the enclave and the untrusted host
 * */

typedef struct stored_data_t{
  unsigned short file_type;
  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
  size_t c_len; // content len 
  unsigned char content[]; // Flexible member
} stored_data_t;

#endif /* _EH_SHARED_H_ */
