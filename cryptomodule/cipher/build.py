from cryptomodule import build as core_build
import cffi

cdef = """
typedef ... EVP_CIPHER;

const EVP_CIPHER* EVP_gost2814789_cnt(void);
const EVP_CIPHER* EVP_aes_256_ctr(void);
const EVP_CIPHER* EVP_aes_256_cbc(void);
const EVP_CIPHER* EVP_aes_256_gcm(void);

const int AEAD_TAG_SIZE;

int cipher_encrypt(EVP_CIPHER* cipher, unsigned char* data, int data_len, unsigned char* key,
                   unsigned char* iv, unsigned char* enc_data,
                   int* enc_data_len);
int cipher_decrypt(EVP_CIPHER* cipher, unsigned char* enc_data, int enc_data_len,
                   unsigned char* key, unsigned char* iv,
                   unsigned char* data, int* data_len);

int cipher_aead_encrypt(EVP_CIPHER* cipher,
                       unsigned char* data, int data_len,
                       unsigned char* key, unsigned char* iv,
                       unsigned char* enc_data, int* enc_data_len,
                       unsigned char* tag,
                       unsigned char* aad, int aad_len);
int cipher_aead_decrypt(EVP_CIPHER* cipher,
                       unsigned char* enc_data, int enc_data_len,
                       unsigned char* key, unsigned char* iv,
                       unsigned char* data, int* data_len,
                       unsigned char* tag,
                       unsigned char* aad, int aad_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'cipher', cdef)

if __name__ == '__main__':
    ffi.compile()
