from .. import lib
from ..exceptions import *
from .. import _libressl
from .cipher import BaseCipher
from .auth import BaseCipherAuth
from .auth import GOST89_HMAC_Streebog512, AES256_GCM

ffi, clib = _libressl.ffi, _libressl.lib

class OnionCipher(object):
    """Onion ciphering."""
    @classmethod
    def new(cls, cipher_list):
        """Create new onion cipher chain.

        Ciphers are set in encryption order.

        """
        if isinstance(cipher_list, str):
            raise ValueError('cipher_list should be a list-like thing')
        try:
            for cipher in cipher_list:
                if not issubclass(cipher, BaseCipher):
                    raise ValueError('Cipher list should contain BaseCipher ' +
                                     'subclasses.')
        except TypeError:
            raise ValueError('cipher_list should be a list-like thing')

        cls.cipher_list = cipher_list
        return cls

    def __init__(self, key_list):
        """Initialize onion ciphering."""
        if len(key_list) != len(self.cipher_list):
            raise ValueError('Key list length is not equal to number of ' +
                             'ciphers in a chain')

        self._cipher_instances = [cipher(*key) for cipher, key in
                                  zip(self.cipher_list, key_list)]

    def encrypt(self, data):
        """Encrypt a message."""
        is_authenticated = [issubclass(cipher, BaseCipherAuth) for cipher in
                            self.cipher_list]

        message, auth_codes = data, []
        for cipher, is_ae in zip(self._cipher_instances, is_authenticated):
            output = cipher.encrypt(message)
            if is_ae:
                message, auth_code = output
                auth_codes.append(auth_code)
            else:
                message = output
                auth_codes.append(None)

        return message, auth_codes

    def decrypt(self, data, auth_codes):
        """Decrypt a message."""
        if len(auth_codes) != len(self._cipher_instances):
            raise ValueError('Authentication code list length mismatch')

        is_authenticated = [issubclass(cipher, BaseCipherAuth) for cipher in
                            self.cipher_list]
        message = data
        for cipher, is_ae, auth_code in zip(reversed(self._cipher_instances),
                                            reversed(is_authenticated),
                                            reversed(auth_codes)):
            if is_ae:
                message = cipher.decrypt(message, auth_code)
            else:
                message = cipher.decrypt(message)

        return message


Onion_AES256_GOST89 = OnionCipher.new((AES256_GCM, GOST89_HMAC_Streebog512))
Onion_AES256_GOST89.__doc__ = 'Onion ciphering: AES256-GCM + ' + \
                              'GOST89-HMAC-Streebog512'
