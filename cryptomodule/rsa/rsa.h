#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include "cryptomodule_lib.h"

extern EVP_PKEY* init_pkey(const char* pubkey, size_t pubkey_len,
                           const char* privkey, size_t privkey_len);

extern int rsa_sign(unsigned char* msg, size_t msg_len,
                    EVP_PKEY* pkey,
                    unsigned char* signature, size_t* signature_len);
extern int rsa_verify(unsigned char* msg, size_t msg_len,
                      unsigned char* signature, size_t signature_len,
                      EVP_PKEY* pkey);

extern int rsa_encrypt(unsigned char* msg, size_t msg_len,
                       EVP_PKEY* pkey, unsigned char* iv,
                       EVP_CIPHER* cipher_id,
                       unsigned char* session_key, size_t* session_key_len,
                       unsigned char* enc_msg, size_t* enc_msg_len);
extern int rsa_decrypt(unsigned char* enc_msg, size_t enc_msg_len,
                       EVP_PKEY* pkey, unsigned char* iv,
                       EVP_CIPHER* cipher_id,
                       unsigned char* session_key, size_t session_key_len,
                       unsigned char* msg, size_t* msg_len);
