"""
Some building machinery for the cryptomodule.

Defines building options and convenience building functions. Also registers
common C module with FFI (all other library sections depend on this module!).
To build the module manually, just run this file like `PYTHONPATH='.'
cryptomodule/build.py`.

"""
import os
import cffi

TOPLEVEL_PACKAGE_PATH = os.path.abspath(os.path.dirname(__file__))
SOURCES = []
LIBRARIES = ['crypto']
LIBRARY_DIRS = ['/usr/local/ssl/lib']
INCLUDE_DIRS = ['/usr/local/ssl/include', TOPLEVEL_PACKAGE_PATH]
EXTRA_COMPILE_ARGS = []
EXTRA_LINK_ARGS = []

cdef = '''
void OPENSSL_add_all_algorithms_noconf(void);

void ERR_load_crypto_strings(void);
char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);

typedef ... ENGINE;

/////// Digests /////////
typedef ... EVP_MD;
typedef ... EVP_MD_CTX;
#define EVP_MAX_MD_SIZE ...

const EVP_MD* EVP_streebog512(void);
const EVP_MD* EVP_sha512(void);

EVP_MD_CTX *EVP_MD_CTX_create(void);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
/////////////////////////

/////// PBKDF2 //////////
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter, int keylen,
    unsigned char *out);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt,
    int saltlen, int iter, const EVP_MD *digest, int keylen,
    unsigned char *out);
/////////////////////////
'''
src = '''
#include <openssl/evp.h>
#include <openssl/err.h>
'''

ffi = cffi.FFI()
ffi.cdef(cdef)
ffi.set_source('cryptomodule._cryptomodule', src,
               libraries=LIBRARIES, library_dirs=LIBRARY_DIRS,
               include_dirs=INCLUDE_DIRS, sources=SOURCES,
               extra_compile_args=EXTRA_COMPILE_ARGS,
               extra_link_args=EXTRA_LINK_ARGS)

if __name__ == '__main__':
    ffi.compile()
