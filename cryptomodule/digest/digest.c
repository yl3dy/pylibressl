#include "digest.h"

const EVP_MD* digest_id_init(const char* name)
{
    OpenSSL_add_all_digests();
    return EVP_get_digestbyname(name);
}

EVP_MD_CTX* digest_init(const EVP_MD* hash_id)
{
    ERR_load_crypto_strings();

    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!EVP_DigestInit_ex(digest_ctx, hash_id, NULL)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return digest_ctx;
}

void digest_teardown(EVP_MD_CTX* digest_ctx)
{
    EVP_MD_CTX_destroy(digest_ctx);
    EVP_cleanup();
}

int digest_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len)
{
    if(!EVP_DigestUpdate(digest_ctx, msg, msg_len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int digest_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len)
{
    if(!EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}
