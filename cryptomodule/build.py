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
typedef ... ENGINE;
typedef ... BIO;

int CRYPTO_memcmp(const void *a, const void *b, size_t len);
void OPENSSL_cleanse(void *ptr, size_t len);

BIO *BIO_new_mem_buf(void *buf, int len);
void BIO_free_all(BIO *a);

/////// Error handling /////////
void ERR_load_crypto_strings(void);
char *ERR_error_string(unsigned long e, char *buf);
unsigned long ERR_get_error(void);
////////////////////////////////

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

/////// Private/public keys //////////
typedef ... EVP_PKEY;
typedef ... EVP_PKEY_CTX;
#define EVP_PKEY_HMAC ...
#define EVP_PKEY_RSA ...

EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key,
    int keylen);
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY*);
//////////////////////////////////////

/////// Signing //////////
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int _wrap_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size);

int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t siglen);
int _wrap_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size);
//////////////////////////

/////// Symmetric ciphers //////////
typedef ... EVP_CIPHER;
typedef ... EVP_CIPHER_CTX;

#define EVP_CTRL_GCM_SET_TAG ...
#define EVP_CTRL_GCM_GET_TAG ...
#define EVP_CTRL_GCM_SET_IVLEN ...

const EVP_CIPHER *EVP_aes_256_ctr(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_gost2814789_cnt(void);

int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
////////////////////////////////////

/////// RSA //////////
typedef ... RSA;
typedef ... pem_password_cb;

int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,
                    pem_password_cb *cb, void *u);
RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x,
                    pem_password_cb *cb, void *u);

void RSA_free(RSA *r);
//////////////////////

/////// Asymmetric cipher //////////
int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk,
    int npubk);
int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int _wrap_EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);

int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    const unsigned char *ek, int ekl, const unsigned char *iv, EVP_PKEY *priv);
int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int _wrap_EVP_OpenUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
////////////////////////////////////
'''
src = '''
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

extern int _wrap_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size);
int _wrap_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size)
{
    return EVP_DigestSignUpdate(ctx, msg, size);
}

extern int _wrap_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size);
int _wrap_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void* msg, size_t size)
{
    return EVP_DigestVerifyUpdate(ctx, msg, size);
}

extern int _wrap_EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
int _wrap_EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
    return EVP_SealUpdate(ctx, out, outl, in, inl);
}

extern int _wrap_EVP_OpenUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl);
int _wrap_EVP_OpenUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{
    return EVP_OpenUpdate(ctx, out, outl, in, inl);
}
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
