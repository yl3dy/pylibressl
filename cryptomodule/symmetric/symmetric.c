#include "symmetric.h"

static void report_error(const char* msg) {
    printf(">>> OpenSSL C interface: %s\n", msg);
}

int gost_encrypt(const char* data, int data_len, unsigned char* key,
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

int gost_decrypt(unsigned char* enc_data, int enc_data_len,
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
