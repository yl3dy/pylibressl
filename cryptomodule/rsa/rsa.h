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
