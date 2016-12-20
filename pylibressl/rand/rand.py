from ..lib import retrieve_bytes, check_status
from ..exceptions import *
from .. import _libressl
import os
from math import ceil

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

def getrandbits(bit_number):
    """Get an integer containing `bit_number` random bits.

    Analogous to `Crypto.Random.random.getrandbits` from pycrypto.

    """
    if bit_number <= 0:
        raise ValueError('Bit number should be bigger than zero')

    byte_num = ceil(bit_number / 8)
    base = int.from_bytes(get_random_bytes(byte_num), 'big')
    return base >> (byte_num*8 - bit_number)
