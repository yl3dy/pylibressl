#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>

void report_error(char* buf, size_t buflen);
extern void initialize_libressl(void);
