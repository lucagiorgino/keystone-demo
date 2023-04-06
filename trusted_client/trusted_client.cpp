#include <string.h>
#include "trusted_client.h"
#include "client.h"

#include "test_dev_key.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"
/* DEMO CHANGES */
#include "test_client_key.h"
#include "ed25519/ed25519.h"

#define CHALLENGE_SIZE 64
unsigned char challenge[CHALLENGE_SIZE];
/* END DEMO CHANGES */ 

unsigned char dh_client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char dh_client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char dh_server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

int double_fault;
int channel_ready;

/* DEMO CHANGES */
void dump_buf( char* title, unsigned char *buf, size_t len ) {
    size_t i;

    printf( "%s\n", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );	
}

int gen_session_context(byte* buffer){

  unsigned char data[PUBLIC_KEY_SIZE+CHALLENGE_SIZE];
  unsigned char data_signature[crypto_sign_BYTES];
  
  memcpy(data,dh_client_pk,PUBLIC_KEY_SIZE);
  memcpy(data+PUBLIC_KEY_SIZE,challenge,CHALLENGE_SIZE);
  
  if (crypto_sign_detached(data_signature, NULL, data, PUBLIC_KEY_SIZE+CHALLENGE_SIZE,    _client_secret_key) != 0) {
    printf("[TC] Session context fail signature.\n");
    return 0;
  } 
  
  memcpy(buffer,data,PUBLIC_KEY_SIZE+CHALLENGE_SIZE);
  memcpy(buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE,data_signature,crypto_sign_BYTES);
  memcpy(buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE+crypto_sign_BYTES,_client_public_key,PUBLIC_KEY_SIZE);

  // fixed signature computed by the system administrator
  memcpy(buffer+PUBLIC_KEY_SIZE+CHALLENGE_SIZE+crypto_sign_BYTES+PUBLIC_KEY_SIZE,_signature_of_client_pk,crypto_sign_BYTES);

  return 1;
}
/* END DEMO CHANGES */ 

void trusted_client_exit(){
  if(double_fault || !channel_ready){
    printf("DC: Fatal error, exiting. Remote not cleanly shut down.\n");
    exit(-1);
  }
  else{
    double_fault = 1;
    printf("[TC] Exiting. Attempting clean remote shutdown.\n");
    send_exit_message();
    exit(0);
  }
}

void trusted_client_init(){

  if( sodium_init() != 0){
    printf("[TC] Libsodium init failure\n");
    trusted_client_exit();
  }
  if( crypto_kx_keypair(dh_client_pk,dh_client_sk) != 0){
    printf("[TC] Libsodium keypair gen failure\n");
    trusted_client_exit();
  }

  channel_ready = 0;
}

byte* trusted_client_pubkey(size_t* len){
  *len = crypto_kx_PUBLICKEYBYTES;
  return (byte*)dh_client_pk;
}

void trusted_client_get_report(void* buffer, int ignore_valid){

  Report report;
  report.fromBytes((unsigned char*)buffer);
  report.printPretty();

  if (report.verify(enclave_expected_hash,
  		    sm_expected_hash,
  		    _sanctum_dev_public_key))
  {
    printf("[TC] Attestation signature and enclave hash are valid\n");
  }
  else
  {
    printf("[TC] Attestation report is NOT valid\n");
    if( ignore_valid ){
      printf("[TC] Ignore Validation was set, CONTINUING WITH INVALID REPORT\n");
    }
    else{
      trusted_client_exit();
    }
  }
/* DEMO CHANGES */
  if(report.getDataSize() !=  crypto_kx_PUBLICKEYBYTES+CHALLENGE_SIZE){
    printf("[TC] Bad report data sec size\n");
    trusted_client_exit();
  }

  memcpy(dh_server_pk, report.getDataSection(), crypto_kx_PUBLICKEYBYTES);
  memcpy(challenge, report.getDataSection()+crypto_kx_PUBLICKEYBYTES, CHALLENGE_SIZE);


/* END DEMO CHANGES */

  if(crypto_kx_client_session_keys(rx, tx, dh_client_pk, dh_client_sk, dh_server_pk) != 0) {
    printf("[TC] Bad session keygen\n");
    trusted_client_exit();
  }

  printf("[TC] Session keys established\n");
  channel_ready = 1;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

byte* trusted_client_box(byte* msg, size_t size, size_t* finalsize){
  size_t size_padded = BLOCK_UP(size);
  *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
  byte* buffer = (byte*)malloc(*finalsize);
  if(buffer == NULL){
    printf("[TC] NOMEM for msg\n");
    trusted_client_exit();
  }

  memcpy(buffer, msg, size);

  size_t buf_padded_len;
  if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
    printf("[TC] Unable to pad message, exiting\n");
    trusted_client_exit();
  }

  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0){
    printf("[TC] secretbox failed\n");
    trusted_client_exit();
  }

  return(buffer);
}

size_t trusted_client_unbox(unsigned char* buffer, size_t len){

  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(buffer[clen]);
  if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0){
    printf("[TC] unbox failed\n");
    trusted_client_exit();
  }

  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  size_t unpad_len;
  if( sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0){
    printf("[TC] Invalid message padding, ignoring\n");
    trusted_client_exit();
  }

  return unpad_len;
}

response_message_t* trusted_client_read_reply(unsigned char* data, size_t* len){

  *len = trusted_client_unbox(data, *len);
  // int* replyval = (int*)data;
  // printf("[TC] Enclave said string was %i words long\n",*replyval);
  printf("Size = %d\n", *len);
  response_message_t* response = (response_message_t*) malloc(*len);
  if(response == NULL){
    printf("Unable to allocate\n");
    exit(-1);
  }
  
  response->response_type = *(data+offsetof(response_message_t, response_type));
  response->len = *(data+offsetof(response_message_t, len));
  memcpy(response->payload, data+offsetof(response_message_t, payload), response->len);

  printf("\n\nResponse type: %d\n", response->response_type);
  dump_buf("Response payload: ", response->payload, response->len);
  printf("Response len: %ld\n", response->len);
  return response;
}

void send_exit_message(){

  size_t pt_size;
  request_message_t* pt_msg = generate_exit_message(&pt_size);

  size_t ct_size;
  byte* ct_msg = trusted_client_box((byte*)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);
}

void send_request_message(char* buffer, unsigned char* secret, unsigned short request_type){

  size_t pt_size;
  request_message_t* pt_msg = generate_request_message(buffer, strlen(buffer)+1, &pt_size, secret, request_type);

  size_t ct_size;
  byte* ct_msg = trusted_client_box((byte*)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);

}

request_message_t* generate_request_message(char* buffer, size_t buffer_len, size_t* finalsize, unsigned char* secret, unsigned short request_type){
  request_message_t* message_buffer = (request_message_t*)malloc(buffer_len+sizeof(request_message_t));

  message_buffer->request_type = request_type;
  message_buffer->len = buffer_len;
  memcpy(message_buffer->secret, secret, SECRET_LEN);
  memcpy(message_buffer->payload, buffer, buffer_len);

  *finalsize = buffer_len + sizeof(request_message_t);

  return message_buffer;
};

request_message_t* generate_exit_message(size_t* finalsize){

  request_message_t* message_buffer = (request_message_t*)malloc(sizeof(request_message_t));
  message_buffer->request_type = MSG_EXIT;
  message_buffer->len = 0;

  *finalsize = sizeof(request_message_t);

  return message_buffer;

}
