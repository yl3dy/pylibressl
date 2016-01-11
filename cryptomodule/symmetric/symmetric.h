#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>

extern int gost_encrypt(const char* data, int data_len, unsigned char* key,
                        unsigned char* iv, unsigned char* enc_data,
                        int* enc_data_len);
extern int gost_decrypt(unsigned char* enc_data, int enc_data_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* data, int* data_len);

static void report_error(const char* msg);
