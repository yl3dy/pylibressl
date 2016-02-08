from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_MD;
typedef ... EVP_PKEY;

const EVP_MD* EVP_streebog512(void);
void EVP_PKEY_free(EVP_PKEY*);

char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);

EVP_PKEY* pkey_hmac_init(unsigned char* private_key, int private_key_len);

int hmac_sign(const EVP_MD* digest_id,
              unsigned char* msg, size_t msg_len,
              unsigned char* signature, size_t* sign_len,
              EVP_PKEY* pkey);

int hmac_verify(const EVP_MD* digest_id,
                unsigned char* msg, size_t msg_len,
                unsigned char* signature, size_t sign_len,
                EVP_PKEY* pkey);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'mac', cdef)

if __name__ == '__main__':
    ffi.compile()
