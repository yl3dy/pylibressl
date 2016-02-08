from cryptomodule import build as core_build
import cffi

cdef = """
char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);

int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter, int keylen,
    unsigned char *out);
"""

ffi = cffi.FFI()
core_build.configure_ffi_simple(ffi, 'kdf', cdef)

if __name__ == '__main__':
    ffi.compile()
