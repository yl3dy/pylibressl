from ..lib import retrieve_bytes, check_status
from ..exceptions import *
from .. import _libressl
import os

ffi, clib = _libressl.ffi, _libressl.lib

def libressl_get_random_bytes(length):
    """Get a string of random bytes with specified length.

    Uses LibreSSL PRNG (system source + arc4random).

    """
    if length <= 0:
        raise ValueError('Random bytestring length is less or equal zero')
    c_length = int(length)
    c_random_buf = ffi.new('unsigned char[]', length)

    check_status(clib.RAND_bytes(c_random_buf, c_length))
    random_bytes = retrieve_bytes(c_random_buf, c_length)
    return random_bytes

def get_random_bytes(length):
    """Get a string of random bytes with specified length.

    Uses system PRNG provided by Python.

    """
    if length <= 0:
        raise ValueError('Random bytestring length is less or equal zero')

    return os.urandom(length)
