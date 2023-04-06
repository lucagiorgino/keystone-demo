#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"

void edge_init();

unsigned long ocall_print_buffer(char* data);
void ocall_print_value(unsigned long val);
void ocall_wait_for_request(struct edge_data *msg);
void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len);
void ocall_send_report(char* buffer, size_t len);
void ocall_send_reply(unsigned char* data, size_t len);
/* DEMO CHANGES INCLUDE */
void ocall_wait_for_client_session_ctx(unsigned char* stub_cert_buff, size_t len);
// TODO ocall_save_sealed_data(char* filename, unsigned char* buffer, unsigned_char* len)
void ocall_save_sealed_data(unsigned char* buffer, size_t len);
void ocall_retrieve_sealed_data(unsigned char* buffer, size_t len, struct edge_data *msg);
/* END DEMO CHANGES */
#endif /* _EDGE_WRAPPER_H_ */
