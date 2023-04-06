// #include <openssl/evp.h>
// #include <openssl/rsa.h>
#include "app/eapp_utils.h"
#include "services.h"
#include "sodium.h"
#include "syscall.h"
#include "app/sealing.h"
#include "eapp_utils.h"
#include "string.h"
#include "edge_wrapper.h"
#include "eh_shared.h"

#define EdDSA 1
#define RSA 2
#define BBS 3

#define BUFFER_SIZE 2048

unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];

unsigned char enclave_signing_sk[crypto_sign_SECRETKEYBYTES];
unsigned char enclave_signing_pk[crypto_sign_PUBLICKEYBYTES];

unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
unsigned char enc_key[crypto_aead_chacha20poly1305_KEYBYTES];

struct pub_EdDSA_keys_t {
  unsigned char pk_auth[crypto_sign_PUBLICKEYBYTES];
  unsigned char pk_ass[crypto_sign_PUBLICKEYBYTES];
};

struct EdDSA_keys_t {
  unsigned char sk_ass[crypto_sign_SECRETKEYBYTES];
  unsigned char sk_auth[crypto_sign_SECRETKEYBYTES];
  struct pub_EdDSA_keys_t pub_EdDSA_keys;
};

// FIXME: this is for debug, must be eliminated
void dump_buf(char *title, unsigned char *buf, size_t len)
{
  size_t i;

  printf("%s [%lu]\n", title,len);
  for (i = 0; i < len; i++)
    printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
           "0123456789ABCDEF"[buf[i] % 16]);
  printf("\n");
}

void setup_sealing_material(unsigned char* secret);
int store_data(unsigned char *buffer, size_t len, unsigned short file_type);
unsigned char* seal_data_and_sign(unsigned char *data, size_t data_len, size_t *sign_len);
unsigned char* retrieve_data_and_unseal(unsigned short file_type, unsigned long long* data_len);

response_message_t* build_response(size_t *pt_finalsize, unsigned short response_type, unsigned char *buffer, size_t len);
response_message_t* generate_public_keys(size_t *pt_finalsize, int key_type);
response_message_t* store_verifiable_credential(size_t *pt_finalsize, unsigned char *vc, size_t vc_len);
response_message_t* get_verifiable_presentation(size_t *pt_finalsize, unsigned char *nonce, size_t nonce_len, int key_type);



response_message_t* process_request(request_message_t *request, size_t *pt_finalsize) {

  setup_sealing_material(request->secret);

  switch (request->request_type) {
    case SERVICE_GEN_KEYS:
      return generate_public_keys(pt_finalsize, EdDSA); // FIXME: this is just for testing
      break;
    case SERVICE_STORE_VC:
      return store_verifiable_credential(pt_finalsize, request->payload, request->len);
      break;
    case SERVICE_GET_VP:
      return get_verifiable_presentation(pt_finalsize, request->payload, request->len, EdDSA); // FIXME: this is just for testing
      break;
    default: 
      ocall_print_buffer("Invalid request type!\n");
  }
  return NULL;
}

response_message_t *generate_public_keys(size_t *pt_finalsize, int key_type) {
  printf("generate_public_keys\n");
  if (key_type == EdDSA) {
    // TODO: save also keytype, we need to know when decrypting it
    struct EdDSA_keys_t EdDSA_keys;
    crypto_sign_keypair(EdDSA_keys.pub_EdDSA_keys.pk_auth, EdDSA_keys.sk_auth);
    crypto_sign_keypair(EdDSA_keys.pub_EdDSA_keys.pk_ass, EdDSA_keys.sk_ass);

    dump_buf("\nEdDSA_keys_t: ", (unsigned char*) &EdDSA_keys, sizeof(EdDSA_keys));
    unsigned char *sign;
    size_t sign_len;

    sign = seal_data_and_sign((unsigned char *)&EdDSA_keys, sizeof(EdDSA_keys), &sign_len);
    store_data(sign, sign_len, FILE_CLIENT_KEYS_SIGNATURE);

    free(sign);

    return build_response(pt_finalsize, SERVICE_GEN_KEYS, (unsigned char *)&EdDSA_keys.pub_EdDSA_keys, sizeof(struct pub_EdDSA_keys_t));
  }

  return NULL;
}

response_message_t *store_verifiable_credential(size_t *pt_finalsize, unsigned char *vc, size_t vc_len)
{
  printf("store_verifiable_credential\n");
  unsigned char *sign;
  size_t sign_len;

  sign = seal_data_and_sign(vc, vc_len, &sign_len);
  store_data(sign, sign_len, FILE_CLIENT_VC_SIGNATURE);

  free(sign);

  int return_value = 0;
  return build_response(pt_finalsize, SERVICE_STORE_VC, (unsigned char *)&return_value, sizeof(int));
}

response_message_t *get_verifiable_presentation(size_t *pt_finalsize, unsigned char *nonce, size_t nonce_len, int key_type)
{
  printf("get_verifiable_presentation\n");

  unsigned char *client_keys, *vc, *vp;
  unsigned long long client_keys_len, vc_len, vp_len;

  client_keys = retrieve_data_and_unseal(FILE_CLIENT_KEYS_SIGNATURE, &client_keys_len);
  vc = retrieve_data_and_unseal(FILE_CLIENT_VC_SIGNATURE, &vc_len);

  dump_buf("\nClient keys:", client_keys, (unsigned long) client_keys_len);
  dump_buf("\nVerifiable credential:", vc, (unsigned long) vc_len);

  if (key_type == EdDSA) {
    struct EdDSA_keys_t EdDSA_keys;
    memcpy(&EdDSA_keys, client_keys, sizeof(struct EdDSA_keys_t));

    unsigned char vp_buffer[BUFFER_SIZE];
    // TODO: add nonce
    crypto_sign_detached(vp_buffer, &vp_len, vc, vc_len, EdDSA_keys.sk_ass);
    vp = (unsigned char*) malloc(vp_len);
    // TODO: build json here? 
    memcpy(vp, vp_buffer, vp_len);
  }

  dump_buf("\nVerifiable presentation:", vp, (unsigned long) vp_len);
  return build_response(pt_finalsize, SERVICE_GET_VP, vp, vp_len);
}

unsigned char* retrieve_data_and_unseal(unsigned short file_type, unsigned long long* data_len) {

  struct edge_data msg;
  struct stored_data_t *saved_data = (stored_data_t *)malloc(sizeof(stored_data_t));
  memcpy(saved_data->client_pk, client_pk, crypto_kx_PUBLICKEYBYTES); // this is needed to reconstruct the filename
  saved_data->c_len = 0;

  saved_data->file_type = file_type;
  ocall_retrieve_sealed_data((unsigned char *)saved_data, sizeof(stored_data_t), &msg);

  unsigned char *sign = (unsigned char *) malloc(msg.size);
  size_t sign_len = msg.size;
  copy_from_shared(sign, msg.offset, msg.size);

  // dump_buf("\nRetrieved signed data:", sign, sign_len);

  unsigned char signature_buffer[BUFFER_SIZE];
  unsigned long long unsigned_message_len;
  
  if (crypto_sign_open(signature_buffer, &unsigned_message_len,
                      sign, (unsigned long long) sign_len, enclave_signing_pk) != 0) {
    ocall_print_buffer("Invalid signature!\n");
    EAPP_RETURN(-1);
  }
  
  // dump_buf("\nOpened signed data:", signature_buffer, (size_t) unsigned_message_len);
  
  unsigned char decrypted_buffer[BUFFER_SIZE];
  unsigned long long decrypted_len;
  if (crypto_aead_chacha20poly1305_decrypt(decrypted_buffer, &decrypted_len,
                                          NULL,
                                          signature_buffer, unsigned_message_len,
                                          NULL,
                                          0,
                                          nonce, enc_key) != 0) {
    ocall_print_buffer("Message forged!\n");
    EAPP_RETURN(-1);
  }
  
  // dump_buf("\nDecrypted data:", decrypted_buffer, (unsigned long) decrypted_len);

  unsigned char* data = (unsigned char*) malloc(decrypted_len);
  memcpy(data, decrypted_buffer, decrypted_len);
  *data_len = decrypted_len;
  return data;
}

unsigned char* seal_data_and_sign(unsigned char *data, size_t data_len,
                        size_t *sign_len)
{
  // encryption phase
  unsigned long long c_len;
  unsigned char *c = (unsigned char *) malloc(data_len + crypto_aead_chacha20poly1305_ABYTES);

  // encrypt the 2 keys
  crypto_aead_chacha20poly1305_encrypt(c, &c_len,
                                       data, (unsigned long long)data_len,
                                       NULL, 0,
                                       NULL, nonce, enc_key);

  // signing phase
  unsigned long long s_len;
  unsigned char *s = (unsigned char *) malloc(crypto_sign_BYTES + c_len);

  crypto_sign(s, &s_len, c, c_len, enclave_signing_sk);

  dump_buf("\nCiphertext ", c, c_len);
  dump_buf("\nSign ", s, s_len);

  free(c);
  *sign_len = (unsigned long)s_len;
  return s;
}

int store_data(unsigned char *buffer, size_t len, unsigned short file_type) {
  struct stored_data_t *saved_data;
  size_t sd_len;

  sd_len = len + sizeof(stored_data_t);
  saved_data = (stored_data_t *) malloc(sd_len);
  if (saved_data == NULL) {
    ocall_print_buffer("malloc error!\n");
    EAPP_RETURN(-1);
  }
  saved_data->file_type = file_type;
  memcpy(saved_data->client_pk, client_pk, crypto_kx_PUBLICKEYBYTES);
  saved_data->c_len = len;
  memcpy(saved_data->content, buffer, len);

  ocall_save_sealed_data((unsigned char *)saved_data, sd_len);
  free(saved_data);

  return 1;
}

void setup_sealing_material(unsigned char* secret) {
  // TODO: this is done each time the client make a request, enhance this to do at connection  (beware: the client must send the SECRET the first time only)
  struct sealing_key sealing_material;
  int ret = 0;
  
  /* Derive the sealing key */
  ret = get_sealing_key(&sealing_material, sizeof(sealing_material), secret, SECRET_LEN);

  if (ret) {
    ocall_print_buffer("Sealing key derivation failed!\n");
    EAPP_RETURN(-1);
  }

  // here sealing_key is used as a seed to gen sign keys
  crypto_sign_seed_keypair(enclave_signing_pk, enclave_signing_sk,
                            sealing_material.key);

  // sealing key here is used for the data encryption usage
  memcpy(enc_key, sealing_material.key, crypto_aead_chacha20poly1305_KEYBYTES); // crypto_aead_chacha20poly1305_keygen(enc_key);
  // TODO: create two different nonces, one for keys and one for vc
  memcpy(nonce, sealing_material.key + crypto_aead_chacha20poly1305_KEYBYTES,
          crypto_aead_chacha20poly1305_NPUBBYTES); // randombytes_buf(nonce, sizeof nonce);

  ocall_print_buffer("Sealing key derivation successful!\n");
}

response_message_t *build_response(size_t *pt_finalsize, unsigned short response_type, unsigned char *buffer, size_t len)
{

  response_message_t *response;
  response = (response_message_t *)malloc(len + sizeof(request_message_t));
  memcpy(response->payload, buffer, len);

  response->len = (unsigned long)len;
  *pt_finalsize = len + sizeof(request_message_t);
  response->response_type = response_type;

  dump_buf("Response payload: ", response->payload, response->len);

  return response;
}