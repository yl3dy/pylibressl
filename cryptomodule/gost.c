// Should be used as an argument to ffi.set_source

#include <openssl/evp.h>

static void report_error(const char* msg) {
    printf(">>> OpenSSL C interface: %s\n", msg);
}

static int gost_encrypt(const char* data, int data_len, unsigned char* key,
                        unsigned char* iv, unsigned char* enc_data,
                        int* enc_data_len)
{
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX* gost_ctx = EVP_CIPHER_CTX_new();
    if(!gost_ctx) {
        report_error("EVP context initialization failed");
        return 1;
    }

    if(1 != EVP_EncryptInit_ex(gost_ctx, EVP_gost2814789_cnt(), NULL, key, iv)) {
        report_error("EVP init failed\n");
        goto cleanup;
    }

    int len, enc_len;
    EVP_EncryptUpdate(gost_ctx, enc_data, &len, data, data_len);
    enc_len = len;
    EVP_EncryptFinal_ex(gost_ctx, enc_data + len, &len);
    enc_len += len;
    *enc_data_len = enc_len;

    return 0;

cleanup:
    EVP_CIPHER_CTX_free(gost_ctx);
    return 1;
}

static int gost_decrypt(unsigned char* enc_data, int enc_data_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* data, int* data_len)
{
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX* gost_ctx = EVP_CIPHER_CTX_new();
    if(!gost_ctx) {
        report_error("EVP context initialization failed");
        return 1;
    }

    if(!EVP_DecryptInit_ex(gost_ctx, EVP_gost2814789_cnt(), NULL, key, iv)) {
        report_error("Could not initialize EVP decryptor");
        goto cleanup;
    }

    int len, dec_data_len;
    if(!EVP_DecryptUpdate(gost_ctx, data, &len, enc_data, enc_data_len)) {
        report_error("Could not decrypt data");
        goto cleanup;
    }
    dec_data_len = len;
    if(!EVP_DecryptFinal_ex(gost_ctx, data + len, &len)) {
        report_error("Descryption finalization failed");
        goto cleanup;
    }
    dec_data_len += len;
    *data_len = dec_data_len;

    return 0;

cleanup:
    EVP_CIPHER_CTX_free(gost_ctx);
    return 1;
}

static int streebog_digest(unsigned char* msg, unsigned char* digest,
                           unsigned int* digest_len)
{
    EVP_MD_CTX* digest_ctx;

    digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        report_error("Could not initialize digest context");
        return 1;
    }

    if(!EVP_DigestInit_ex(digest_ctx, EVP_streebog512(), NULL)) {
        report_error("Could not initialize Streebog512");
        return 1;
    }

    if(!EVP_DigestUpdate(digest_ctx, msg, strlen((const char*)msg))) {
        report_error("Could not update digest");
    }

    if(!EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        report_error("Could not finalize digest");
        return 1;
    }

    EVP_MD_CTX_destroy(digest_ctx);
    return 0;
}
