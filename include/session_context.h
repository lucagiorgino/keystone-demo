#ifndef _STUB_CERTIFICATE_H_
#define _STUB_CERTIFICATE_H_

#include "sodium.h"

#define CHALLENGE_SIZE 64
#define SIGNATURE_SIZE 64
#define PUBLIC_KEY_SIZE 32
#define SESSION_CTX_SIZE  PUBLIC_KEY_SIZE+CHALLENGE_SIZE+SIGNATURE_SIZE+PUBLIC_KEY_SIZE+SIGNATURE_SIZE

#include "common/sha3.h"
#include "ed25519/ed25519.h"

struct session_context_t {
  unsigned char  dh_public_key[PUBLIC_KEY_SIZE];
  unsigned char  challenge[CHALLENGE_SIZE];
  unsigned char  data_signature[SIGNATURE_SIZE];
  // stub_cert
  unsigned char  client_public_key[PUBLIC_KEY_SIZE];
  unsigned char  root_signature_of_client_pk[SIGNATURE_SIZE];
};

void session_context_from_buffer(struct session_context_t* session_context, unsigned char* buffer);
int session_context_verify(struct session_context_t session_context, unsigned char* challange, const unsigned char* root_public_key);
 

#endif /* _STUB_CERTIFICATE_H_ */
