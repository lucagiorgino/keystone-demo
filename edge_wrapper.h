#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include <edge_call.h>
#include "keystone.h"

#define crypto_kx_PUBLICKEYBYTES 32
/* DEMO CHANGES */
#define _SESSION_CTX_SIZE 128
/* END DEMO CHANGES */
typedef struct encl_message_t {
  void* host_ptr;
  size_t len;
} encl_message_t;

int edge_init(Keystone::Enclave* enclave);

void print_buffer_wrapper(void* buffer);
unsigned long print_buffer(char* str);

void print_value_wrapper(void* buffer);
void print_value(unsigned long val);

void send_report_wrapper(void* buffer);
void send_report(void* shared_buffer, size_t len);

void wait_for_message_wrapper(void* buffer);
encl_message_t wait_for_message();

void send_reply_wrapper(void* buffer);
void send_reply(void* message, size_t len);

void wait_for_client_pubkey_wrapper(void* buffer);
void* wait_for_client_pubkey();

/* DEMO CHANGES */
void wait_for_client_session_ctx_wrapper(void* buffer);
void save_sealed_data_wrapper(void* buffer);
void save_sealed_data(void* data, size_t len);
void retrieve_sealed_data_wrapper(void* buffer);
encl_message_t retrieve_sealed_data(void* data, size_t len);
/* END DEMO CHANGES */

#endif /* _EDGE_WRAPPER_H_ */
