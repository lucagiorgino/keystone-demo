#include <sodium.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4

void dump_buf(char *title, unsigned char *buf, size_t len) {
  size_t i;

  printf("%s [%lu]\n", title,len);
  for (i = 0; i < len; i++)
    printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
           "0123456789ABCDEF"[buf[i] % 16]);
  printf("\n");
}

void dump_buf_2(char *title, unsigned char *buf, size_t len) {
  size_t i;

  printf("static const unsigned char %s[] = {\n", title);
  for (i = 0; i < len; i++){
    if(i%8 == 0) printf(" ");
    printf("0x%c%c", "0123456789abcdef"[buf[i] / 16],
           "0123456789abcdef"[buf[i] % 16]);
    if (i != len-1) printf(", ");
    if((i+1)%8 == 0) printf("\n");
  }
    
  printf("};\n"); 
  printf("static const size_t %s_len = %lu;\n\n", title,len);
}

int main(void) {

  printf("/* These are known client TESTING keys, use them for testing on platforms/qemu */\n\n");
  printf("\n// #warning Using TEST client key. No integrity guarantee.\n\n");
  if (sodium_init() < 0) {
      printf("\npanic! the library couldn't be initialized; it is not safe to use!\n");
  }

  unsigned char root_pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char root_sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(root_pk, root_sk);

  dump_buf_2("_root_public_key", root_pk,crypto_sign_PUBLICKEYBYTES);
  dump_buf_2("_root_secret_key", root_sk,crypto_sign_SECRETKEYBYTES);

  unsigned char client_pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char client_sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(client_pk, client_sk);

  dump_buf_2("_client_public_key", client_pk,crypto_sign_PUBLICKEYBYTES);
  dump_buf_2("_client_secret_key", client_sk,crypto_sign_SECRETKEYBYTES);

  unsigned char signature_of_client_pk[crypto_sign_BYTES];

  crypto_sign_detached(signature_of_client_pk, NULL, client_pk, crypto_sign_PUBLICKEYBYTES, root_sk);

  if (crypto_sign_verify_detached(signature_of_client_pk, client_pk, crypto_sign_PUBLICKEYBYTES, root_pk) != 0) {
    printf("\nincorrect signature!\n");
  }
  printf("// must be computed and fixed for each device \n");
  dump_buf_2("_signature_of_client_pk", signature_of_client_pk,crypto_sign_BYTES);
  
  return 0;
}
