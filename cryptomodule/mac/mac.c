#include "mac.h"

EVP_PKEY* pkey_hmac_init(unsigned char* private_key, int private_key_len)
{
    EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, private_key, private_key_len);
    if(!pkey) {
        return NULL;
    }
    return pkey;
}

int hmac_sign(const EVP_MD* digest_id,
              unsigned char* msg, size_t msg_len,
              unsigned char* signature, size_t* sign_len,
              EVP_PKEY* pkey)
{
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        goto cleanup;
    }

    if(1 != EVP_DigestInit_ex(digest_ctx, digest_id, NULL)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignInit(digest_ctx, NULL, digest_id, NULL, pkey)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignUpdate(digest_ctx, msg, msg_len)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignFinal(digest_ctx, signature, sign_len)) {
        goto cleanup;
    }

    EVP_MD_CTX_destroy(digest_ctx);
    return 1;

cleanup:
    if(digest_ctx) {
        EVP_MD_CTX_destroy(digest_ctx);
    }
    return 0;
}

int hmac_verify(const EVP_MD* digest_id,
                unsigned char* msg, size_t msg_len,
                unsigned char* signature, size_t sign_len,
                EVP_PKEY* pkey)
{
    unsigned char buf_mac[EVP_MAX_MD_SIZE];  // buffer for MAC to compare with
    size_t buf_mac_len;

    if(!hmac_sign(digest_id, msg, msg_len, buf_mac, &buf_mac_len, pkey)) {
        return 0;   // error message is already prepared
    }

    // This should be used to mitigate timing attacks - CRYPTO_memcmp takes
    // constant time.
    int result = CRYPTO_memcmp(signature, buf_mac, buf_mac_len);

    OPENSSL_cleanse(buf_mac, sizeof(buf_mac));
    return (result == 0) ? 1 : -1;
}
