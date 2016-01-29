#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include "cryptomodule_lib.h"

extern int digest(EVP_MD* digest_id,
                  unsigned char* msg, unsigned int msg_len,
                  unsigned char* digest, unsigned int* digest_len,
                  char* error_string, size_t error_string_len);
