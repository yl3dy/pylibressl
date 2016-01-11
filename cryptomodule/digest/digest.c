#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

EVP_MD_CTX* streebog_init(void)
{
    ERR_load_crypto_strings();

    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!EVP_DigestInit_ex(digest_ctx, EVP_streebog512(), NULL)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return digest_ctx;
}

void streebog_teardown(EVP_MD_CTX* digest_ctx)
{
    EVP_MD_CTX_destroy(digest_ctx);
}

int streebog_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len)
{
    if(!EVP_DigestUpdate(digest_ctx, msg, msg_len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

int streebog_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len)
{
    if(!EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}
