#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int streebog_digest(unsigned char* msg, unsigned char* digest, unsigned int* digest_len)
{
    ERR_load_crypto_strings();

    EVP_MD_CTX* digest_ctx;

    digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if(!EVP_DigestInit_ex(digest_ctx, EVP_streebog512(), NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if(!EVP_DigestUpdate(digest_ctx, msg, strlen((const char*)msg))) {
        ERR_print_errors_fp(stderr);
    }

    if(!EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_MD_CTX_destroy(digest_ctx);
    return 0;
}
