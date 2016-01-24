#include "cipher.h"

const int AEAD_TAG_SIZE = 16;

/////////// Ordinary modes (CTR, CBC etc.) /////////////////

int cipher_encrypt(EVP_CIPHER* cipher, unsigned char* data, int data_len, unsigned char* key,
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


/////////// AEAD modes (GCM) /////////////////

int cipher_aead_encrypt(EVP_CIPHER* cipher,
                       unsigned char* data, int data_len,
                       unsigned char* key, unsigned char* iv,
                       unsigned char* enc_data, int* enc_data_len,
                       unsigned char* tag,
                       unsigned char* aad, int aad_len)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(1 != EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if(1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_TAG_SIZE, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if(1 != EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    int len, enc_len;
    // Add AAD
    if(aad_len > 0) {
        if(1 != EVP_EncryptUpdate(cipher_ctx, NULL, &len, aad, aad_len)) {
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }
    EVP_EncryptUpdate(cipher_ctx, enc_data, &len, data, data_len);
    enc_len = len;
    EVP_EncryptFinal_ex(cipher_ctx, enc_data + len, &len);
    enc_len += len;
    *enc_data_len = enc_len;

    if(1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_SIZE, tag)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_cleanup();

    return 1;

cleanup:
    EVP_CIPHER_CTX_free(cipher_ctx);
    return 0;
}

int cipher_aead_decrypt(EVP_CIPHER* cipher,
                       unsigned char* enc_data, int enc_data_len,
                       unsigned char* key, unsigned char* iv,
                       unsigned char* data, int* data_len,
                       unsigned char* tag,
                       unsigned char* aad, int aad_len)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if(!EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if(1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, AEAD_TAG_SIZE, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if(!EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    int len, dec_data_len;
    if(aad_len > 0) {
        if(1 != EVP_DecryptUpdate(cipher_ctx, NULL, &len, aad, aad_len)) {
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }
    if(!EVP_DecryptUpdate(cipher_ctx, data, &len, enc_data, enc_data_len)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if(!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_SIZE, tag)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    dec_data_len = len;
    if(!EVP_DecryptFinal_ex(cipher_ctx, data + len, &len)) {
        // if message is not authentic
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -1;
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
