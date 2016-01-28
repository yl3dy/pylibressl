#include "sign.h"

EVP_PKEY* pkey_hmac_init(unsigned char* private_key, int private_key_len, char* error_string, int error_string_len)
{
    EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, private_key, private_key_len);
    if(!pkey) {
        report_error(error_string, error_string_len);
        return NULL;
    }
    return pkey;
}

int hmac_sign(const EVP_MD* digest_id,
              unsigned char* msg, size_t msg_len,
              unsigned char* signature, size_t* sign_len,
              EVP_PKEY* pkey,
              char* error_string, size_t error_string_len)
{
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        report_error(error_string, error_string_len);
        return 0;
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
    report_error(error_string, error_string_len);
    EVP_MD_CTX_destroy(digest_ctx);
    return 0;
}

int hmac_verify(const EVP_MD* digest_id,
                unsigned char* msg, size_t msg_len,
                unsigned char* signature, size_t sign_len,
                EVP_PKEY* pkey,
                char* error_string, size_t error_string_len)
{
    unsigned char buf_mac[EVP_MAX_MD_SIZE];  // buffer for MAC to compare with
    size_t buf_mac_len;

    if(!hmac_sign(digest_id, msg, msg_len, buf_mac, &buf_mac_len, pkey, error_string, error_string_len)) {
        return 0;   // error message is already prepared
    }

    // This should be used to mitigate timing attacks - CRYPTO_memcmp takes
    // constant time.
    int result = CRYPTO_memcmp(signature, buf_mac, buf_mac_len);

    OPENSSL_cleanse(buf_mac, sizeof(buf_mac));
    return (result == 0) ? 1 : -1;
}
