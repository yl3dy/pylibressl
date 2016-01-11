from cryptomodule import build as core_build
import cffi

cdef = """
int streebog_digest(unsigned char* msg, unsigned char* digest,
                           unsigned int* digest_len);
"""

ffi = cffi.FFI()
core_build.configure_ffi(ffi, 'digest', cdef)

if __name__ == '__main__':
    ffi.compile()
