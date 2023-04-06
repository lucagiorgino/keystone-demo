#ifndef _REQUEST_MSG_H_
#define _REQUEST_MSG_H_

#define SERVICE_GEN_KEYS 1
#define SERVICE_STORE_VC 2
#define SERVICE_GET_VP 3
#define MSG_EXIT 4

#define SECRET_LEN 64

#include "malloc.h"

/* *
 * This file is shared between
 * the client and the enclave
 * */

typedef struct request_message_t {
  unsigned short request_type;
  unsigned char secret[SECRET_LEN];
  size_t len;
  unsigned char payload[]; // Flexible member
} request_message_t;

typedef struct response_message_t {
  unsigned short response_type;
  size_t len;
  unsigned char payload[]; // Flexible member
} response_message_t;

#endif /* _REQUEST_MSG_H_ */
