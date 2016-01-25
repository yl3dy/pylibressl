#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include "cryptomodule_lib.h"

extern const int AEAD_TAG_SIZE;

extern int cipher_encrypt(EVP_CIPHER* cipher, unsigned char* data, int data_len, unsigned char* key,
                          unsigned char* iv, unsigned char* enc_data,
                          int* enc_data_len, char* error_string, size_t error_string_len);
extern int cipher_decrypt(EVP_CIPHER* cipher, unsigned char* enc_data, int enc_data_len,
                          unsigned char* key, unsigned char* iv,
                          unsigned char* data, int* data_len, char* error_string, size_t error_string_len);

extern int cipher_aead_encrypt(EVP_CIPHER* cipher,
                               unsigned char* data, int data_len,
                               unsigned char* key, unsigned char* iv,
                               unsigned char* enc_data, int* enc_data_len,
                               unsigned char* tag,
                               unsigned char* aad, int aad_len,
                               char* error_string, size_t error_string_len);
extern int cipher_aead_decrypt(EVP_CIPHER* cipher,
                               unsigned char* enc_data, int enc_data_len,
                               unsigned char* key, unsigned char* iv,
                               unsigned char* data, int* data_len,
                               unsigned char* tag,
                               unsigned char* aad, int aad_len,
                               char* error_string, size_t error_string_len);
