from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_MD_CTX;
typedef ... EVP_MD;

extern const EVP_MD* digest_id_init(const char* name);
extern EVP_MD_CTX* digest_init(const EVP_MD* hash_id);
extern void digest_teardown(EVP_MD_CTX* digest_ctx);
extern int digest_update(EVP_MD_CTX* digest_ctx, const char* msg, unsigned int msg_len);
extern int digest_final(EVP_MD_CTX* digest_ctx, unsigned char* digest, unsigned int* digest_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'digest', cdef)

if __name__ == '__main__':
    ffi.compile()
