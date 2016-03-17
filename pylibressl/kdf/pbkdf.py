from .. import lib
from ..exceptions import *
from .. import _libressl
from ..digest.digest import _Hash
from ..digest import Streebog512, SHA256

ffi, clib = _libressl.ffi, _libressl.lib

class PBKDF_HMAC(object):
    @classmethod
    def new(cls, hash_type):
        """Create new PBKDF object."""
        if not issubclass(hash_type, _Hash):
            raise ValueError('Hash type should be _Hash instance')

        class new_pbkdf_hmac(cls):
            _hash_id = hash_type._HASH_ID

        return new_pbkdf_hmac

    def __init__(self, salt, iteration_number, key_length):
        if type(salt) != type(b''):
            raise ValueError('Salt should be a byte string')

        self._c_salt = ffi.new('unsigned char[]', salt)
        self._c_salt_len = len(salt)
        self._iter_num = iteration_number
        self._keylen = key_length

    def derivate(self, password):
        """Derivate key from a password."""
        if type(password) != type(b''):
            raise ValueError('Password should be a byte string')

        c_passw = ffi.new('const char[]', password)
        c_out_key = ffi.new('unsigned char[]', self._keylen)

        status = clib.PKCS5_PBKDF2_HMAC(c_passw, len(password), self._c_salt,
                                        self._c_salt_len, self._iter_num,
                                        self._hash_id, self._keylen, c_out_key)

        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        derived_key = lib.retrieve_bytes(c_out_key, self._keylen)
        return derived_key

PBKDF_HMAC_Streebog512 = PBKDF_HMAC.new(Streebog512)
PBKDF_HMAC_Streebog512.__doc__ = 'PBKDF-HMAC-Streebog512'

PBKDF_HMAC_SHA256 = PBKDF_HMAC.new(SHA256)
PBKDF_HMAC_SHA256.__doc__ = 'PBKDF-HMAC-SHA256'
