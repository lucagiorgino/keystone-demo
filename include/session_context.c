#include "session_context.h"
#include <string.h>
#include <stdio.h>

void session_context_from_buffer(struct session_context_t* session_context, unsigned char* buffer){
    memcpy(session_context->dh_public_key,                  buffer,PUBLIC_KEY_SIZE);
    memcpy(session_context->challenge,                      buffer+PUBLIC_KEY_SIZE,CHALLENGE_SIZE);
    memcpy(session_context->data_signature,                 buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE,crypto_sign_BYTES);
    memcpy(session_context->client_public_key,              buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE+crypto_sign_BYTES,PUBLIC_KEY_SIZE);
    memcpy(session_context->root_signature_of_client_pk,    buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE+crypto_sign_BYTES+PUBLIC_KEY_SIZE,crypto_sign_BYTES);
}

int session_context_verify(struct session_context_t session_context, unsigned char* challange, const unsigned char* root_public_key) {
    int data_signature_valid = 0;
    int cert_signature_valid = 0;
    int equal_challange = 0;
    /* verify DH public key */

    unsigned char data_buffer[PUBLIC_KEY_SIZE+CHALLENGE_SIZE];

    memcpy(data_buffer, session_context.dh_public_key, PUBLIC_KEY_SIZE);
    memcpy(data_buffer+PUBLIC_KEY_SIZE, session_context.challenge, CHALLENGE_SIZE);

    data_signature_valid = crypto_sign_verify_detached(session_context.data_signature, data_buffer, PUBLIC_KEY_SIZE+CHALLENGE_SIZE, session_context.client_public_key);

    cert_signature_valid = crypto_sign_verify_detached(session_context.root_signature_of_client_pk, session_context.client_public_key, PUBLIC_KEY_SIZE, root_public_key);
    
    //memcmp return 0 if the contents of both memory blocks are equal
    equal_challange = !memcmp(challange, session_context.challenge, CHALLENGE_SIZE);

    return equal_challange && !cert_signature_valid && !data_signature_valid; 
}