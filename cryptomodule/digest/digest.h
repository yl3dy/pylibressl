#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

extern int streebog_digest(unsigned char* msg, unsigned char* digest,
                           unsigned int* digest_len);
