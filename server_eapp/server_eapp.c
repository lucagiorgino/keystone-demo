#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"
#include "calculator.h"
#include "sodium.h"
#include "hacks.h"
#include "channel.h"
/* DEMO CHANGES INCLUDE */
#include "services.h"
#include "session_context.h"
#include "test_client_key.h"
/* END DEMO CHANGES */

#define CHALLENGE_SIZE 64
#define MAX_REPORT_SIZE 2048 // TODO sizeof report

/* DEMO CHANGES */
void validate_session_context(void* buffer, unsigned char* challange){

  struct session_context_t session_context;
  session_context_from_buffer(&session_context,(unsigned char*) buffer);
  if (session_context_verify(session_context, challange, _root_public_key)) {
    ocall_print_buffer("Stub certificate signature is valid\n");
  } else {
    ocall_print_buffer("Stub certificate signature is NOT valid\n");
    // TODO: loop?
    EAPP_RETURN(-1);
  }

  // extract dh_public_key and client_pk from session_context
  memcpy(dh_client_pk, session_context.dh_public_key, crypto_kx_PUBLICKEYBYTES);
  memcpy(client_pk, session_context.client_public_key, crypto_kx_PUBLICKEYBYTES);
}
/* END DEMO CHANGES */

void attest_and_establish_channel() {
  /* DEMO CHANGES */
  // TODO sizeof report
  char buffer[MAX_REPORT_SIZE];
  
  unsigned char data_buffer[crypto_kx_PUBLICKEYBYTES+CHALLENGE_SIZE];
  unsigned char challenge[CHALLENGE_SIZE];
  randombytes_buf(challenge, CHALLENGE_SIZE);
  memcpy(data_buffer, dh_server_pk,crypto_kx_PUBLICKEYBYTES);
  memcpy(data_buffer+crypto_kx_PUBLICKEYBYTES,challenge,CHALLENGE_SIZE);

  attest_enclave((void*) buffer, data_buffer, crypto_kx_PUBLICKEYBYTES+CHALLENGE_SIZE);
  ocall_send_report(buffer, MAX_REPORT_SIZE);

  unsigned char session_ctx_buffer[SESSION_CTX_SIZE];
  // TODO: understand why it is necessary to break the message
  ocall_wait_for_client_session_ctx(session_ctx_buffer, 128);
  ocall_wait_for_client_session_ctx(session_ctx_buffer+128, 128);
  validate_session_context(session_ctx_buffer, challenge);

  /* END DEMO CHANGES */

  channel_establish();
}

void handle_requests(){

  struct edge_data msg;

  while(1){
    ocall_wait_for_request(&msg);
    request_message_t* request = malloc(msg.size);
    response_message_t* response; size_t r_size;
    size_t wordmsg_len;

    if(request == NULL){
      ocall_print_buffer("Message too large to store, ignoring\n");
      continue;
    }

    copy_from_shared(request, msg.offset, msg.size);
    if(channel_recv((unsigned char*)request, msg.size, &wordmsg_len) != 0){
      free(request); 
      continue;
    }

    switch (request->request_type) {

      case MSG_EXIT:
        ocall_print_buffer("Received exit, exiting\n");
        EAPP_RETURN(0);
      break;

      default:
        response = process_request(request, &r_size);
      break;
    }

    if (response == NULL) {
      ocall_print_buffer("Response handling error\n");
      EAPP_RETURN(0);
    }

    // Done with the message, free it
    free(request);  

    size_t boxed_size = channel_get_send_size(r_size);
    unsigned char* boxed_buffer = (unsigned char*) malloc(boxed_size);

    if(boxed_buffer == NULL){
      ocall_print_buffer("Reply too large to allocate, no reply sent\n");
      EAPP_RETURN(-1);
    }
    printf("boxed_size: %ld\n\n",boxed_size);
    channel_send((unsigned char*) response, r_size, boxed_buffer);
    ocall_send_reply(boxed_buffer, boxed_size);

    free(boxed_buffer);
    free(response);

  }

}

// void EAPP_ENTRY eapp_entry(){
int main() {

  setvbuf(stdout, 0, _IONBF, 0);
  edge_init();
  magic_random_init();
  channel_init();

  attest_and_establish_channel();

  handle_requests();

  EAPP_RETURN(0);
}