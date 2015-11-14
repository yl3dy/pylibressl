// Should be used as an argument to ffi.set_source

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

static void setup_openssl(void) {
    OpenSSL_add_all_algorithms();
    OPENSSL_config("./openssl.cnf");
}

static int gost_encrypt(const char* data, int data_len, unsigned char* key,
                        unsigned char* iv, unsigned char* enc_data,
                        int* enc_data_len)
{
    setup_openssl();

    /*********** load GOST engine ***************/
    ENGINE* gost_engine;
    const char* gost_id = "gost";  // as specified in config
    gost_engine = ENGINE_by_id(gost_id);
    if(!gost_engine) {
        printf("Could not load gost engine!\\n");
        return 1;
    }
    if(!ENGINE_init(gost_engine)) {
        ENGINE_free(gost_engine);
        return 1;
    }
    ENGINE_set_default_RSA(gost_engine);
    ENGINE_set_default_DSA(gost_engine);
    ENGINE_set_default_ciphers(gost_engine);

    /********* get EVP cipher ********/
    const EVP_CIPHER* cipher = ENGINE_get_cipher(gost_engine, NID_id_Gost28147_89);
    if(cipher == 0) {
        printf("Could not get cipher\\n");
        return 1;
    }
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if(1 != EVP_EncryptInit_ex(cipher_ctx, cipher, gost_engine, key, iv)) {
        printf("EVP init failed\\n");
        return 1;
    }

    /************** Perform encryption ************/
    int len, enc_len;
    EVP_EncryptUpdate(cipher_ctx, enc_data, &len, data, data_len);
    enc_len = len;
    EVP_EncryptFinal_ex(cipher_ctx, enc_data + len, &len);
    enc_len += len;
    *enc_data_len = enc_len;

    /******** Finalizing ************/
    EVP_CIPHER_CTX_free(cipher_ctx);
    ENGINE_finish(gost_engine);
    ENGINE_free(gost_engine);

    return 0;
}
