from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_PKEY;

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
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'rsa', cdef)

if __name__ == '__main__':
    ffi.compile()
