#include "digest.h"

int digest(EVP_MD* digest_id,
           unsigned char* msg, unsigned int msg_len,
           unsigned char* digest, unsigned int* digest_len)
{
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        goto err;
    }

    if(1 != EVP_DigestInit_ex(digest_ctx, digest_id, NULL)) {
        goto err;
    }

    if(1 != EVP_DigestUpdate(digest_ctx, msg, msg_len)) {
        goto err;
    }

    if(1 != EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        goto err;
    }

    EVP_MD_CTX_destroy(digest_ctx);
    return 1;

err:
    if(digest_ctx) {
        EVP_MD_CTX_destroy(digest_ctx);
    }
    return 0;
}
