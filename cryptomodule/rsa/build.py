from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_PKEY;
typedef ... EVP_CIPHER;
const EVP_CIPHER* EVP_aes_256_ctr(void);

char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);
void EVP_PKEY_free(EVP_PKEY *key);

EVP_PKEY* init_pkey(const char* pubkey, size_t pubkey_len,
                    const char* privkey, size_t privkey_len);
int rsa_sign(unsigned char* msg, size_t msg_len,
             EVP_PKEY* pkey,
             unsigned char* signature, size_t* signature_len);
int rsa_verify(unsigned char* msg, size_t msg_len,
               unsigned char* signature, size_t signature_len,
               EVP_PKEY* pkey);
int rsa_encrypt(unsigned char* msg, size_t msg_len,
                EVP_PKEY* pkey, unsigned char* iv,
                EVP_CIPHER* cipher_id,
                unsigned char* session_key, size_t* session_key_len,
                unsigned char* enc_msg, size_t* enc_msg_len);
int rsa_decrypt(unsigned char* enc_msg, size_t enc_msg_len,
                EVP_PKEY* pkey, unsigned char* iv,
                EVP_CIPHER* cipher_id,
                unsigned char* session_key, size_t session_key_len,
                unsigned char* msg, size_t* msg_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'rsa', cdef)

if __name__ == '__main__':
    ffi.compile()
