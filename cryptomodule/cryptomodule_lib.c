#include "cryptomodule_lib.h"

void initialize_libressl(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}
