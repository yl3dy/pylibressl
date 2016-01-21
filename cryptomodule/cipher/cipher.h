#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>

extern int cipher_encrypt(EVP_CIPHER* cipher, const char* data, int data_len, unsigned char* key,
                          unsigned char* iv, unsigned char* enc_data,
                          int* enc_data_len);
extern int cipher_decrypt(EVP_CIPHER* cipher, unsigned char* enc_data, int enc_data_len,
                          unsigned char* key, unsigned char* iv,
                          unsigned char* data, int* data_len);
