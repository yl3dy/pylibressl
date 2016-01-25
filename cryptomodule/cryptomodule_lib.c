#include "cryptomodule_lib.h"

void report_error(char* buf, size_t buflen) {
    unsigned long errn = ERR_get_error();
    ERR_error_string_n(errn, buf, buflen);
}

void initialize_libressl(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}
