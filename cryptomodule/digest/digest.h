#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>

extern EVP_MD_CTX* streebog_init(void);
extern void streebog_teardown(EVP_MD_CTX* digest_ctx);
extern int streebog_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len);
extern int streebog_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len);
