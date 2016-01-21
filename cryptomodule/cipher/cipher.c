#include "cipher.h"

int cipher_encrypt(EVP_CIPHER* cipher, const char* data, int data_len, unsigned char* key,
                   unsigned char* iv, unsigned char* enc_data,
                   int* enc_data_len)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(1 != EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    int len, enc_len;
    EVP_EncryptUpdate(cipher_ctx, enc_data, &len, data, data_len);
    enc_len = len;
    EVP_EncryptFinal_ex(cipher_ctx, enc_data + len, &len);
    enc_len += len;
    *enc_data_len = enc_len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_cleanup();

    return 1;

cleanup:
    EVP_CIPHER_CTX_free(cipher_ctx);
    return 0;
}

int cipher_decrypt(EVP_CIPHER* cipher, unsigned char* enc_data, int enc_data_len,
                   unsigned char* key, unsigned char* iv,
                   unsigned char* data, int* data_len)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    int len, dec_data_len;
    if(!EVP_DecryptUpdate(cipher_ctx, data, &len, enc_data, enc_data_len)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    dec_data_len = len;
    if(!EVP_DecryptFinal_ex(cipher_ctx, data + len, &len)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    dec_data_len += len;
    *data_len = dec_data_len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_cleanup();

    return 1;

cleanup:
    EVP_CIPHER_CTX_free(cipher_ctx);
    return 0;
}
