from cryptomodule import build as core_build
import cffi

cdef = """
int gost_encrypt(const char* data, int data_len, unsigned char* key,
                 unsigned char* iv, unsigned char* enc_data,
                 int* enc_data_len);
int gost_decrypt(unsigned char* enc_data, int enc_data_len,
                 unsigned char* key, unsigned char* iv,
                 unsigned char* data, int* data_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'symmetric', cdef)

if __name__ == '__main__':
    ffi.compile()
