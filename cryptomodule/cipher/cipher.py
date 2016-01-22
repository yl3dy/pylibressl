import warnings
try:
    from . import _cipher
except ImportError:
    warnings.warn('Symmetric encryption C module not compiled', RuntimeWarning)
    _cipher = None

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class _Cipher(object):
    @classmethod
    def new(cls, key, iv):
        if not _cipher:
            raise CipherError("Can't create cipher object: cipher C module is not compiled")

        # verify key/IV validity
        if type(key) != type(b'') or type(iv) != type(b''):
            raise ValueError('Key/IV values should be bytes instances')
        if len(key) != cls.KEY_LENGTH or len(iv) != cls.IV_LENGTH:
            raise ValueError('Key/IV lengths are incorrect')

        cipher = cls(key, iv)
        return cipher

    def __init__(self, key, iv):
        self._key = key
        self._iv = iv

    def encrypt(self, data):
        ffi = _cipher.ffi

        c_data = ffi.new('const char[]', data)
        c_key = ffi.new('unsigned char[]', self._key)
        c_iv = ffi.new('unsigned char[]', self._iv)
        c_enc_data = ffi.new('unsigned char[]', 2*len(data))
        c_enc_data_len = ffi.new('int *')

        status = _cipher.lib.cipher_encrypt(self._CIPHER_ID, c_data, len(data),
                                            c_key, c_iv, c_enc_data,
                                            c_enc_data_len)

        if not status:
            raise CipherError('LibreSSL binding error')

        encrypted_data = lib.retrieve_bytes(_cipher.ffi, c_enc_data, c_enc_data_len[0])
        return encrypted_data

    def decrypt(self, data):
        ffi = _cipher.ffi

        c_enc_data = ffi.new('unsigned char[]', data)
        c_key = ffi.new('unsigned char[]', key)
        c_iv = ffi.new('unsigned char[]', iv)
        c_dec_data = ffi.new('unsigned char[]', len(data))
        c_dec_data_len = ffi.new('int*')

        status = _cipher.lib.cipher_decrypt(self._CIPHER_ID, c_enc_data,
                                            len(data), c_key, c_iv, c_dec_data,
                                            c_dec_data_len)
        if not status:
            raise CipherError('LibreSSL binding error')

        decrypted_data = lib.retrieve_bytes(_cipher.ffi, c_dec_data, c_dec_data_len[0])
        return decrypted_data

class GOST89(_Cipher):
    """GOST89 cipher in counter mode."""
    KEY_LENGTH = 32
    IV_LENGTH = 8
    MODE = 'CTR'

    def __init__(self, *args):
        _Cipher.__init__(self, *args)
        self._CIPHER_ID = _cipher.lib.EVP_gost2814789_cnt()
