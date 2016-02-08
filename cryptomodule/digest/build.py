from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_MD;
#define EVP_MAX_MD_SIZE ...

char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);

const EVP_MD* EVP_streebog512(void);
const EVP_MD* EVP_sha512(void);

int digest(EVP_MD* digest_id,
           unsigned char* msg, unsigned int msg_len,
           unsigned char* digest, unsigned int* digest_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'digest', cdef)

if __name__ == '__main__':
    ffi.compile()
