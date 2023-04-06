#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "edge_wrapper.h"
#include "edge_defines.h"

void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
}

void ocall_print_value(unsigned long val){

  unsigned long val_ = val;
  ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

  return;
}

void ocall_send_report(char* buffer, size_t len){

  ocall(OCALL_SEND_REPORT, buffer, len, 0, 0);

  return;  
}

unsigned long ocall_print_buffer(char* data){

  unsigned long retval;
  ocall(OCALL_PRINT_BUFFER, data, strlen(data)+1, &retval ,sizeof(unsigned long));

  return retval;
}

void ocall_wait_for_request(struct edge_data *msg){

  ocall(OCALL_WAIT_FOR_REQUEST, NULL, 0, msg, sizeof(struct edge_data));
}

void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len){
  ocall(OCALL_WAIT_FOR_CLIENT_PUBKEY, NULL, 0, pk, len);
  return;
}

void ocall_send_reply(unsigned char* data, size_t len){
  ocall(OCALL_SEND_REPLY, data, len, 0, 0);
  return;
}

/* DEMO CHANGES INCLUDE */
void ocall_wait_for_client_session_ctx(unsigned char* stub_cert_buff, size_t len){
  ocall(OCALL_WAIT_FOR_CLIENT_SESSION_CTX, NULL, 0, stub_cert_buff, len);
  return;
}

// ocall(
//    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
//    size_t return_len);

void ocall_save_sealed_data(unsigned char* buffer, size_t len){
  ocall(OCALL_SAVE_SEALED_DATA, buffer, len, 0, 0);
  return;
}

void ocall_retrieve_sealed_data(unsigned char* buffer, size_t len, struct edge_data *msg){
  ocall(OCALL_RETRIEVE_SEALED_DATA, buffer, len, msg, sizeof(struct edge_data));
  return;
}

/* END DEMO CHANGES */