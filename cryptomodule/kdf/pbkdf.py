from .. import lib
from ..exceptions import *
from .. import _cryptomodule
from ..digest.digest import _Hash

class PBKDF_HMAC(object):
    @classmethod
    def new(cls, salt, iteration_number, key_length, hash_type):
        """Create new PBKDF object."""
        if type(salt) != type(b''):
            raise ValueError('Salt should be a byte string')
        if not issubclass(hash_type, _Hash):
            raise ValueError('Hash type should be _Hash instance')

        pbkdf = cls(salt, iteration_number, key_length, hash_type)
        return pbkdf

    def __init__(self, salt, iteration_number, key_length, hash_type):
        ffi = _cryptomodule.ffi

        self._c_salt = ffi.new('unsigned char[]', salt)
        self._c_salt_len = len(salt)
        self._iter_num = iteration_number
        self._keylen = key_length
        self._hash_id = hash_type._HASH_ID

    def derivate(self, password):
        """Derivate key from a password."""
        if type(password) != type(b''):
            raise ValueError('Password should be a byte string')

        ffi, clib = _cryptomodule.ffi, _cryptomodule.lib

        c_passw = ffi.new('const char[]', password)
        c_out_key = ffi.new('unsigned char[]', self._keylen)

        status = clib.PKCS5_PBKDF2_HMAC(c_passw, len(password), self._c_salt,
                                        self._c_salt_len, self._iter_num,
                                        self._hash_id, self._keylen, c_out_key)

        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        derived_key = lib.retrieve_bytes(c_out_key, self._keylen)
        return derived_key
