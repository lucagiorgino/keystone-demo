#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h"
/* DEMO CHANGES */
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "./include/eh_shared.h"
/* END DEMO CHANGES */

#define PRINT_MESSAGE_BUFFERS 1

/* We hardcode these for demo purposes. */
const char* enc_path = "server_eapp.eapp_riscv";
const char* runtime_path = "eyrie-rt";

#define PORTNUM 8067
int fd_clientsock;
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

void send_buffer(byte* buffer, size_t len){
  write(fd_clientsock, &len, sizeof(size_t));
  write(fd_clientsock, buffer, len);
}

byte* recv_buffer(size_t* len){
  read(fd_clientsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size); // FIXME:  chi libera questa mem? 
  read(fd_clientsock, reply, reply_size);
  *len = reply_size;
  return reply;
}

void print_hex_data(unsigned char* data, size_t len){
  unsigned int i;
  std::string str;
  for(i=0; i<len; i+=1){
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();
    if(i>0 && (i+1)%8 == 0){
      if((i+1)%32 == 0){
	str += "\n";
      }
      else{
	str += " ";
      }
    }
  }
  printf("%s\n\n",str.c_str());
}

unsigned long print_buffer(char* str){
  printf("[SE] %s",str);
  return strlen(str);
}

void print_value(unsigned long val){
  printf("[SE] value: %u\n",val);
  return;
}

void send_reply(void* data, size_t len){
  printf("[EH] Sending encrypted reply:\n");

  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)data, len);

  send_buffer((byte*)data, len);
}

void* wait_for_client_pubkey(){
  size_t len;
  return recv_buffer(&len);
}

encl_message_t wait_for_message(){

  size_t len;

  void* buffer = recv_buffer(&len);

  printf("[EH] Got an encrypted message:\n");
  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

void send_report(void* buffer, size_t len) {
  send_buffer((byte*)buffer, len);
}
// FIXME: this is for debug, must be eliminated
void dump_buf( char* title, unsigned char *buf, size_t len ) {
    size_t i;

    printf( "%s\n", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );	
}

std::string BinaryToHexString(const unsigned char* inBinaryData, size_t inBinaryDataLength) {
  static const char *hexDigits = "0123456789ABCDEF";

  // Create a string and give a hint to its final size (twice the size
  // of the input binary data)
  std::string hexString;
  hexString.reserve(inBinaryDataLength * 2);

  // Run through the binary data and convert to a hex string
  std::for_each(
      inBinaryData,
      inBinaryData + inBinaryDataLength,
      [&hexString](uint8_t inputByte) {
          hexString.push_back(hexDigits[inputByte >> 4]);
          hexString.push_back(hexDigits[inputByte & 0x0F]);
      });

  return hexString;
} 

std::string get_file_name(const unsigned char* client_pk, unsigned short file_type){
  
  // TODO: is the/this path a good solution?
  std::string filename = "/root/"; 
  filename += BinaryToHexString(client_pk, crypto_kx_PUBLICKEYBYTES);
  
  switch (file_type) {
    case FILE_CLIENT_KEYS_SIGNATURE:
       filename += "_keys_sign";
    break;
    case FILE_CLIENT_VC_SIGNATURE:
      filename += "_vc_sign";
    break;
  }

  std::cout << "[EH] Filename: " << filename << std::endl;

  return filename;
}

void save_sealed_data(void* data, size_t len){
  printf("[EH] Saving sealed data\n");

  stored_data_t* stored_data = (stored_data_t*) malloc(len);
  if(stored_data == NULL){
    printf("Unable to allocate\n");
    exit(-1);
  }
  memcpy(stored_data , data, len);
  
  std::string filename = get_file_name(stored_data->client_pk, stored_data->file_type);
 
  std::ofstream myfile;
  myfile.open ( filename, std::ios::out | std::ios::binary );
  if (!myfile.is_open()) {
    std::cout << "[EH] Failed to open outputfile.\n";
  }
  myfile.write((char*)stored_data->content, stored_data->c_len);
  myfile.close();
}

encl_message_t retrieve_sealed_data(void* data, size_t len){

  stored_data_t* stored_data = (stored_data_t*) malloc(len);
  if(stored_data == NULL){
    printf("Unable to allocate\n");
    exit(-1);
  }
  memcpy(stored_data , data, len);
  
  std::string filename = get_file_name(stored_data->client_pk, stored_data->file_type);

  std::ifstream fin(filename, std::ios::in | std::ios::binary );
  if(fin.fail()){
    printf("Unable to open client files.\n");
    exit(-1);
  }
  fin.seekg (0, fin.end);
  size_t file_len = fin.tellg();
  fin.seekg(0, std::ios::beg);

  byte* buffer = (byte*)  malloc(file_len); // FIXME: chi libera questa mem? 

  fin.read((char*) buffer, file_len);

  printf("[EH] File size: %ld\n", file_len);
  dump_buf("[EH] Retrieved Data: ", (unsigned char*) buffer, file_len);

  
  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = file_len;
  return message;

}

void init_network_wait(){

  int fd_sock;
  struct sockaddr_in server_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORTNUM);
  if( bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }
  listen(fd_sock,2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);
  if (fd_clientsock < 0){
    printf("No valid client socket\n");
    exit(-1);
  }
}

int main(int argc, char** argv)
{

  /* Wait for network connection */
  init_network_wait();

  printf("[EH] Got connection from remote client\n");

  Keystone::Enclave enclave;
  Keystone::Params params;

  if(enclave.init(enc_path, runtime_path, params) != Keystone::Error::Success){
    printf("HOST: Unable to start enclave\n");
    exit(-1);
  }

  edge_init(&enclave);

  Keystone::Error rval = enclave.run();
  printf("rval: %i\n",rval);

  return 0;
}
