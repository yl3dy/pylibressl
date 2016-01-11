from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_MD_CTX;

EVP_MD_CTX* streebog_init();
void streebog_teardown(EVP_MD_CTX* digest_ctx);
int streebog_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len);
int streebog_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'digest', cdef)

if __name__ == '__main__':
    ffi.compile()
