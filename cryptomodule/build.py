from cffi import FFI

ffi = FFI()
ffi.set_source('_cryptomodule',
               """#include <openssl/conf.h>
                  #include <openssl/evp.h>

                  void setup_openssl(void) {
                    OpenSSL_add_all_algorithms();
                    OPENSSL_config("./openssl.cnf");
                  }

               """, libraries=['crypto'])
ffi.cdef("""
    void setup_openssl(void);
""")

def build():
    ffi.compile()
