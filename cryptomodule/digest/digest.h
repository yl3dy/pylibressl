#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>

extern const EVP_MD* digest_id_init(const char* name);
extern EVP_MD_CTX* digest_init(const EVP_MD* hash_id);
extern void digest_teardown(EVP_MD_CTX* digest_ctx);
extern int digest_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len);
extern int digest_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len);
