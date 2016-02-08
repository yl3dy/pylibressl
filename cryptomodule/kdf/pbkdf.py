try:
    from . import _kdf
except ImportError:
    raise ImportError('KDF C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class _PBKDF(object):
    pass

class PBKDF_HMAC_SHA1(_PBKDF):
    @classmethod
    def new(cls, salt, iteration_number, key_length):
        """Create new PBKDF object."""
        if type(salt) != type(b''):
            raise ValueError('Salt should be a byte string')

        pbkdf = cls(salt, iteration_number, key_length)
        return pbkdf

    def __init__(self, salt, iteration_number, key_length):
        ffi = _kdf.ffi

        self._c_salt = ffi.new('unsigned char[]', salt)
        self._iter_num = iteration_number
        self._keylen = key_length

    def derivate(self, password):
        """Derivate key from a password."""
        if type(password) != type(b''):
            raise ValueError('Password should be a byte string')

        ffi = _kdf.ffi

        c_passw = ffi.new('const char[]', password)
        c_out_key = ffi.new('unsigned char[]', self._keylen)

        status = _kdf.lib.PKCS5_PBKDF2_HMAC_SHA1(c_passw, len(c_passw),
                                                 self._c_salt,
                                                 len(self._c_salt),
                                                 self._iter_num, self._keylen,
                                                 c_out_key)

        if not status:
            raise LibreSSLError(lib.get_libressl_error(ffi, _kdf.lib))

        derivated_key = lib.retrieve_bytes(ffi, c_out_key, self._keylen)
        return derivated_key
