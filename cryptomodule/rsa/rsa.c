#include "rsa.h"

EVP_PKEY* init_pkey(const char* pubkey, size_t pubkey_len, const char* privkey, size_t privkey_len)
{
    BIO *pubkey_buf = NULL, *privkey_buf = NULL;
    RSA *rsa_pub = NULL, *rsa_priv = NULL;
    EVP_PKEY* pkey = EVP_PKEY_new();

    if(pubkey_len > 0) {
        pubkey_buf = BIO_new_mem_buf((void*)pubkey, pubkey_len);
        if(!pubkey_buf) {
            goto cleanup;
        }
        rsa_pub = PEM_read_bio_RSAPublicKey(pubkey_buf, NULL, NULL, NULL);
        if(!rsa_pub) {
            goto cleanup;
        }
        if(1 != EVP_PKEY_assign_RSA(pkey, rsa_pub)) {
            goto cleanup;
        }
    }
    if(privkey_len > 0) {
        privkey_buf = BIO_new_mem_buf((void*)privkey, privkey_len);
        if(!privkey_buf) {
            goto cleanup;
        }
        rsa_priv = PEM_read_bio_RSAPrivateKey(privkey_buf, NULL, NULL, NULL);
        if(!rsa_priv) {
            goto cleanup;
        }
        if(1 != EVP_PKEY_assign_RSA(pkey, rsa_priv)) {
            goto cleanup;
        }
    }

    BIO_free_all(pubkey_buf);
    BIO_free_all(privkey_buf);

    return pkey;

cleanup:
    if(pubkey_buf != NULL) {
        BIO_free_all(pubkey_buf);
    }
    if(privkey_buf != NULL) {
        BIO_free_all(privkey_buf);
    }

    // following are called only if EVP_PKEY_assign_RSA or earlier failed
    if(rsa_pub != NULL) {
        RSA_free(rsa_pub);
    }
    if(rsa_priv != NULL) {
        RSA_free(rsa_priv);
    }

    if(pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return NULL;
}

int rsa_sign(unsigned char* msg, size_t msg_len,
             EVP_PKEY* pkey,
             unsigned char* signature, size_t* signature_len)
{
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        goto cleanup;
    }
    if(1 != EVP_DigestInit_ex(digest_ctx, EVP_sha256(), NULL)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignInit(digest_ctx, NULL, EVP_sha256(), NULL, pkey)) {
        goto cleanup;
    }

    if(1 != EVP_DigestSignUpdate(digest_ctx, msg, msg_len)) {
        goto cleanup;
    }

    size_t slen;
    if(1 != EVP_DigestSignFinal(digest_ctx, signature, &slen)) {
        goto cleanup;
    }
    *signature_len = slen;

    EVP_MD_CTX_destroy(digest_ctx);
    return 1;

cleanup:
    if(digest_ctx != NULL) {
        EVP_MD_CTX_destroy(digest_ctx);
    }

    return 0;
}

int rsa_verify(unsigned char* msg, size_t msg_len,
               unsigned char* signature, size_t signature_len,
               EVP_PKEY* pkey)
{
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_create();
    if(!digest_ctx) {
        goto cleanup;
    }
    if(1 != EVP_DigestInit_ex(digest_ctx, EVP_sha256(), NULL)) {
        goto cleanup;
    }

    if(1 != EVP_DigestVerifyInit(digest_ctx, NULL, EVP_sha256(), NULL, pkey)) {
        goto cleanup;
    }

    if(1 != EVP_DigestVerifyUpdate(digest_ctx, msg, msg_len)) {
        goto cleanup;
    }

    int status = EVP_DigestVerifyFinal(digest_ctx, signature, signature_len);
    if(status == 1) {      // message is authentic
        EVP_MD_CTX_destroy(digest_ctx);
        return 1;
    }
    else if(status == 0) { // message isn't authentic
        EVP_MD_CTX_destroy(digest_ctx);
        return -1;
    }
    else {                 // other error
        goto cleanup;
    }

cleanup:
    if(digest_ctx != NULL) {
        EVP_MD_CTX_destroy(digest_ctx);
    }

    return 0;
}

int rsa_encrypt(unsigned char* msg, size_t msg_len,
                EVP_PKEY* pkey, unsigned char* iv,
                EVP_CIPHER* cipher_id,
                unsigned char* session_key, size_t* session_key_len,
                unsigned char* enc_msg, size_t* enc_msg_len)
{
    EVP_PKEY* pkeys[] = { pkey };
    unsigned char* sess_keys[] = { session_key };

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        goto cleanup;
    }

    int skl;
    if(1 != EVP_SealInit(cipher_ctx, cipher_id, sess_keys, &skl, iv, pkeys, 1)) {
        goto cleanup;
    }
    *session_key_len = skl;

    int len;
    if(1 != EVP_SealUpdate(cipher_ctx, enc_msg, &len, msg, msg_len)) {
        goto cleanup;
    }

    *enc_msg_len = len;
    if(1 != EVP_SealFinal(cipher_ctx, enc_msg, &len)) {
        goto cleanup;
    }
    *enc_msg_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;

cleanup:
    if(!cipher_ctx) {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }

    return 0;
}

int rsa_decrypt(unsigned char* enc_msg, size_t enc_msg_len,
                EVP_PKEY* pkey, unsigned char* iv,
                EVP_CIPHER* cipher_id,
                unsigned char* session_key, size_t session_key_len,
                unsigned char* msg, size_t* msg_len)
{
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(!cipher_ctx) {
        goto cleanup;
    }

    if(1 != EVP_OpenInit(cipher_ctx, cipher_id, session_key, session_key_len, iv, pkey)) {
        goto cleanup;
    }

    int len;
    if(1 != EVP_OpenUpdate(cipher_ctx, msg, &len, enc_msg, enc_msg_len)) {
        goto cleanup;
    }

    *msg_len = len;
    if(1 != EVP_OpenFinal(cipher_ctx, msg, &len)) {
        goto cleanup;
    }
    *msg_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;

cleanup:
    if(!cipher_ctx) {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }

    return 0;
}

