// Should be used as an argument to ffi.set_source

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

struct gost_suite {
    ENGINE* engine;
    EVP_CIPHER* cipher;
    EVP_CIPHER_CTX* ctx;
};

static void setup_openssl(void) {
    OpenSSL_add_all_algorithms();
    OPENSSL_config("./openssl.cnf");
}

static void report_error(const char* msg) {
    printf(">>> OpenSSL C interface: %s\n", msg);
}

static int init_gost(struct gost_suite* gost) {
    ENGINE* gost_engine;
    gost_engine = ENGINE_by_id("gost");
    if(!gost_engine) {
        report_error("Could not load gost engine!");
        return 0;
    }
    if(!ENGINE_init(gost_engine)) {
        report_error("Gost engine initialization failed!");
        ENGINE_free(gost_engine);
        return 0;
    }
    ENGINE_set_default_ciphers(gost_engine);

    const EVP_CIPHER* gost_cipher = ENGINE_get_cipher(gost_engine, NID_id_Gost28147_89);
    if(!gost_cipher) {
        // TODO: proper cleanup
        report_error("Could not load gost cipher!");
        return 0;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        report_error("Could not get gost cipher context!");
        ENGINE_finish(gost_engine);
        ENGINE_free(gost_engine);
        return 0;
    }

    gost->engine = gost_engine;
    gost->cipher = gost_cipher;
    gost->ctx = ctx;

    return 1;
}

static void gost_cleanup(struct gost_suite* gost) {
    EVP_CIPHER_CTX_free(gost->ctx);
    // TODO: does cipher need cleanup?
    gost->cipher = 0;    // in case the function gets called too early
    ENGINE_finish(gost->engine);
    ENGINE_free(gost->engine);
}

static int gost_encrypt(const char* data, int data_len, unsigned char* key,
                        unsigned char* iv, unsigned char* enc_data,
                        int* enc_data_len)
{
    setup_openssl();

    struct gost_suite gost;
    if(!init_gost(&gost)) {
        return 1;
    }

    if(1 != EVP_EncryptInit_ex(gost.ctx, gost.cipher, gost.engine, key, iv)) {
        report_error("EVP init failed\n");
        return 1;
    }

    int len, enc_len;
    EVP_EncryptUpdate(gost.ctx, enc_data, &len, data, data_len);
    enc_len = len;
    EVP_EncryptFinal_ex(gost.ctx, enc_data + len, &len);
    enc_len += len;
    *enc_data_len = enc_len;

    gost_cleanup(&gost);
    return 0;
}

static int gost_decrypt(unsigned char* enc_data, int enc_data_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* data, int* data_len)
{
    setup_openssl();

    struct gost_suite gost;
    if(!init_gost(&gost)) {
        return 1;
    }

    if(!EVP_DecryptInit_ex(gost.ctx, gost.cipher, gost.engine, key, iv)) {
        report_error("Could not initialize EVP decryptor");
        return 1;
    }

    int len, dec_data_len;
    if(!EVP_DecryptUpdate(gost.ctx, data, &len, enc_data, enc_data_len)) {
        report_error("Could not decrypt data");
        return 1;
    }
    dec_data_len = len;
    if(!EVP_DecryptFinal_ex(gost.ctx, data + len, &len)) {
        report_error("Descryption finalization failed");
        return 1;
    }
    dec_data_len += len;

    gost_cleanup(&gost);

    *data_len = dec_data_len;

    return 0;
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

    if(!EVP_DigestUpdate(digest_ctx, msg, strlen(msg))) {
        report_error("Could not update digest");
    }

    if(!EVP_DigestFinal_ex(digest_ctx, digest, digest_len)) {
        report_error("Could not finalize digest");
        return 1;
    }

    EVP_MD_CTX_destroy(digest_ctx);
    return 0;
}
