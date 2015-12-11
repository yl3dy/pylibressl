"""Builder for OpenSSL C API interaction part."""

from cffi import FFI
import os.path

def _get_gost_source():
    """Read C source for CFFI."""
    package_path = os.path.abspath(os.path.dirname(__file__))
    gost_src_file = os.path.join(package_path, 'gost.c')
    with open(gost_src_file, 'r') as f:
        gost_src = f.read()
    return gost_src

ffi = FFI()
ffi.set_source('cryptomodule._cryptomodule', _get_gost_source(),
               libraries=['crypto'], library_dirs=['/usr/local/ssl/lib'],
               include_dirs=['/usr/local/ssl/include'])
ffi.cdef("""
static int gost_encrypt(const char* data, int data_len, unsigned char* key,
                        unsigned char* iv, unsigned char* enc_data,
                        int* c_enc_data_len);
static int gost_decrypt(unsigned char* enc_data, int enc_data_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* data, int* data_len);
static int streebog_digest(unsigned char* msg, unsigned char* digest,
                           unsigned int* digest_len);
""")

if __name__ == '__main__':
    ffi.compile()
