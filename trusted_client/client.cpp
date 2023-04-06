#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <unistd.h>
#include "trusted_client.h"
#include "client.h"

#define SESSION_CTX_SIZE 256

#define PORTNUM 8067
int fd_sock;
struct sockaddr_in server_addr;
struct hostent *server;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];


void send_buffer(byte* buffer, size_t len){
  write(fd_sock, &len, sizeof(size_t));
  write(fd_sock, buffer, len);  
}

byte* recv_buffer(size_t* len){
  ssize_t n_read = read(fd_sock, local_buffer, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[TC] Invalid message header\n");
    trusted_client_exit();
  }
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    trusted_client_exit();
  }
  n_read = read(fd_sock, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    trusted_client_exit();
  }

  *len = reply_size;
  return reply;
}

int main(int argc, char *argv[]) {
  int ignore_valid = 0;
  if(argc < 2) {
    printf("Usage %s hostname\n", argv[0]);
    exit(-1);
  }

  if(argc >= 3){
    if(strcmp(argv[2],"--ignore-valid") == 0){
      ignore_valid =1;
    }
  }
  
  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if(fd_sock < 0){
    printf("No socket\n");
    exit(-1);
  }
  server = gethostbyname(argv[1]);
  if(server == NULL) {
    printf("Can't get host\n");
    exit(-1);
  }
  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr.sin_port = htons(PORTNUM);
  if( connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    printf("Can't connect\n");
    exit(-1);
  }

  printf("[TC] Connected to enclave host!\n");

  /* Establish channel */
  trusted_client_init();
  
  size_t report_size;
  byte* report_buffer = recv_buffer(&report_size);
  trusted_client_get_report(report_buffer, ignore_valid);
  free(report_buffer);

  /* Send pubkey */
/* DEMO CHANGES */
  // size_t pubkey_size;
  // byte* pubkey = trusted_client_pubkey(&pubkey_size);
  // send_buffer(pubkey, pubkey_size); 
  
  size_t session_ctx_size = SESSION_CTX_SIZE;
  byte session_context_buffer[SESSION_CTX_SIZE];
  if(!gen_session_context(session_context_buffer)){
    exit(-1);
  }
  // TODO: understand why is necessary to break the message (this is an open issue on keystone)
  send_buffer(session_context_buffer, 128);
  send_buffer(session_context_buffer+128, 128);
/* END DEMO CHANGES */
  
  /* Send/recv messages */
  printf("\n\n\tAvailable services\n");
  printf("1. generate keys\n");
  printf("2. store verifiable credential\n");
  printf("3. get verifiable presentation\n");
  printf(" . everything else to quit\n");
  
  unsigned char secret[SECRET_LEN];
  randombytes_buf(secret, SECRET_LEN);

  for(;;){
    // TODO: send a REAL but still fixed verifiable credential
    char vc[37] = "This is a demo verifiable credential";

    printf("\nType the service to request:\n> ");
    memset(local_buffer, 0, BUFFERLEN);
    fgets((char*)local_buffer, BUFFERLEN-1, stdin);
    printf("\n");

    /* Handle quit */
    if(local_buffer[0] == 'q' && (local_buffer[1] == '\0' || local_buffer[1] == '\n')){
      send_exit_message();
      close(fd_sock);
      exit(0);
    } else {
      unsigned short request_type;
      switch(local_buffer[0]){
        case '1':
          request_type = SERVICE_GEN_KEYS;
          // TODO: make the client choose the key type and build a correct request
        break;
        case '2':
          request_type = SERVICE_STORE_VC;
          // TODO: here we should send the VC
          memcpy(local_buffer, vc, 37);
        break;
        case '3':
          request_type = SERVICE_GET_VP;
        break;
        default:
          send_exit_message();
          close(fd_sock);
          exit(0);
        break;
      }
      
      send_request_message((char*)local_buffer, secret, request_type);
      size_t reply_size;
      byte* reply = recv_buffer(&reply_size);
      response_message_t* response = trusted_client_read_reply(reply, &reply_size);
      // TODO: process response or return response

      free(reply);
    }
  }
  return 0;
}
