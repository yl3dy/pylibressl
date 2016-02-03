#pragma once

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "cryptomodule_lib.h"

extern EVP_PKEY* pkey_hmac_init(unsigned char* private_key, int private_key_len,
                                char* error_string, int error_string_len);

extern int hmac_sign(const EVP_MD* digest_id,
                     unsigned char* msg, size_t msg_len,
                     unsigned char* signature, size_t* sign_len,
                     EVP_PKEY* pkey,
                     char* error_string, size_t error_string_len);

extern int hmac_verify(const EVP_MD* digest_id,
                       unsigned char* msg, size_t msg_len,
                       unsigned char* signature, size_t sign_len,
                       EVP_PKEY* pkey,
                       char* error_string, size_t error_string_len);
