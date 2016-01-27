try:
    from . import _cipher
except ImportError:
    raise ImportError('Symmetric encryption C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

# Mode identifiers
MODE_CTR = 1
MODE_GCM = 2
MODE_CBC = 3

class _Cipher(object):
    """Generic cipher object."""

    @classmethod
    def new(cls, key, iv, mode):
        """Create new cipher object."""
        # verify key/IV validity
        if type(key) != type(b'') or type(iv) != type(b''):
            raise ValueError('Key/IV values should be bytes instances')
        if len(key) != cls.KEY_LENGTH or len(iv) != cls.BLOCK_SIZE:
            raise ValueError('Key/IV lengths are incorrect')

        if not mode in cls._CIPHER_IDS.keys():
            raise ValueError('Incorrect mode specified')

        cipher = cls(key, iv, mode)
        return cipher

    def __init__(self, key, iv, mode):
        self._key = key
        self._iv = iv
        self._CIPHER_ID = self._CIPHER_IDS[mode]
        self.MODE = mode
        self.MODES = tuple(self._CIPHER_IDS.keys())
        self._AEAD_TAG_SIZE = _cipher.lib.AEAD_TAG_SIZE


    def _encrypt(self, data):
        ffi = _cipher.ffi

        c_data = ffi.new('unsigned char[]', data)
        c_key = ffi.new('unsigned char[]', self._key)
        c_iv = ffi.new('unsigned char[]', self._iv)
        c_enc_data = ffi.new('unsigned char[]', 2*len(data))
        c_enc_data_len = ffi.new('int *')
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _cipher.lib.cipher_encrypt(self._CIPHER_ID, c_data, len(data),
                                            c_key, c_iv, c_enc_data,
                                            c_enc_data_len, c_err_msg,
                                            lib.ERROR_MSG_LENGTH)

        if not status:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

        encrypted_data = lib.retrieve_bytes(_cipher.ffi, c_enc_data, c_enc_data_len[0])
        return encrypted_data

    def _encrypt_gcm(self, data, **kwargs):
        ffi = _cipher.ffi
        aad = kwargs.get('aad')
        if aad != None and type(aad) != type(b''):
            raise ValueError('AAD should be a byte string')

        c_data = ffi.new('const char[]', data)
        c_key = ffi.new('unsigned char[]', self._key)
        c_iv = ffi.new('unsigned char[]', self._iv)
        c_enc_data = ffi.new('unsigned char[]', 2*len(data))
        c_enc_data_len = ffi.new('int *')
        c_tag = ffi.new('unsigned char[]', self._AEAD_TAG_SIZE)
        c_aad = ffi.new('unsigned char[]', aad if aad else b'\x00')
        aad_len = len(aad) if aad else 0
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _cipher.lib.cipher_aead_encrypt(self._CIPHER_ID, c_data,
                                                 len(data), c_key, c_iv,
                                                 c_enc_data, c_enc_data_len,
                                                 c_tag, c_aad, aad_len,
                                                 c_err_msg,
                                                 lib.ERROR_MSG_LENGTH)

        if not status:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

        encrypted_data = lib.retrieve_bytes(_cipher.ffi, c_enc_data, c_enc_data_len[0])
        tag = lib.retrieve_bytes(_cipher.ffi, c_tag, self._AEAD_TAG_SIZE)
        return encrypted_data, tag

    def encrypt(self, data, **kwargs):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        if self.MODE == MODE_GCM:
            return self._encrypt_gcm(data, **kwargs)
        else:
            return self._encrypt(data)


    def _decrypt(self, data):
        ffi = _cipher.ffi

        c_enc_data = ffi.new('unsigned char[]', data)
        c_key = ffi.new('unsigned char[]', self._key)
        c_iv = ffi.new('unsigned char[]', self._iv)
        c_dec_data = ffi.new('unsigned char[]', len(data))
        c_dec_data_len = ffi.new('int*')
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _cipher.lib.cipher_decrypt(self._CIPHER_ID, c_enc_data,
                                            len(data), c_key, c_iv, c_dec_data,
                                            c_dec_data_len, c_err_msg,
                                            lib.ERROR_MSG_LENGTH)
        if not status:
            err_msg = lib.report_libressl_error(ffi,c_err_msg)
            raise LibreSSLError(err_msg)

        decrypted_data = lib.retrieve_bytes(_cipher.ffi, c_dec_data, c_dec_data_len[0])
        return decrypted_data

    def _decrypt_gcm(self, data, tag, **kwargs):
        ffi = _cipher.ffi
        aad = kwargs.get('aad')

        if aad != None and type(aad) != type(b''):
            raise ValueError('AAD should be a byte string')
        if type(tag) != type(b''):
            raise ValueError('Tag should be a byte string')

        c_enc_data = ffi.new('unsigned char[]', data)
        c_key = ffi.new('unsigned char[]', self._key)
        c_iv = ffi.new('unsigned char[]', self._iv)
        c_dec_data = ffi.new('unsigned char[]', len(data))
        c_dec_data_len = ffi.new('int*')
        c_tag = ffi.new('unsigned char[]', tag)
        c_aad = ffi.new('unsigned char[]', aad if aad else b'\x00')
        aad_len = len(aad) if aad else 0
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _cipher.lib.cipher_aead_decrypt(self._CIPHER_ID, c_enc_data,
                                                 len(data), c_key, c_iv,
                                                 c_dec_data, c_dec_data_len,
                                                 c_tag, c_aad, aad_len,
                                                 c_err_msg,
                                                 lib.ERROR_MSG_LENGTH)

        if not status:
            if status == -1:
                raise AuthencityError('Cannot decrypt message: is not authentic')
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

        decrypted_data = lib.retrieve_bytes(_cipher.ffi, c_dec_data, c_dec_data_len[0])
        return decrypted_data

    def decrypt(self, data, *args, **kwargs):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        if self.MODE == MODE_GCM:
            tag = args[0]
            return self._decrypt_gcm(data, tag, **kwargs)
        else:
            return self._decrypt(data)



class GOST89(_Cipher):
    """GOST R 28147-89 cipher."""
    KEY_LENGTH = 32
    BLOCK_SIZE = 8
    _CIPHER_IDS = {MODE_CTR: _cipher.lib.EVP_gost2814789_cnt()}

class AES256(_Cipher):
    """AES 256-bit cipher."""
    KEY_LENGTH = 32
    BLOCK_SIZE = 16
    _CIPHER_IDS = {MODE_CTR: _cipher.lib.EVP_aes_256_ctr(),
                   MODE_CBC: _cipher.lib.EVP_aes_256_cbc(),
                   MODE_GCM: _cipher.lib.EVP_aes_256_gcm()}
