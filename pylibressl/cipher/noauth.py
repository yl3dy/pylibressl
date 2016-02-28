from .. import lib
from ..exceptions import *
from .. import _libressl
from .cipher import BaseCipher
from .cipher import MODE_CBC, MODE_CTR

ffi, clib = _libressl.ffi, _libressl.lib

class BaseCipherNoauth(BaseCipher):
    """Base symmetric cipher class (without AE)."""

    def _init_cipher_ctx(self, is_encrypt):
        init_func = clib.EVP_EncryptInit_ex if is_encrypt else clib.EVP_DecryptInit_ex

        c_cipher_ctx = ffi.gc(clib.EVP_CIPHER_CTX_new(),
                              clib.EVP_CIPHER_CTX_free)
        if c_cipher_ctx == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error())

        status = init_func(c_cipher_ctx, self._CIPHER_ID, ffi.NULL,
                           self._c_key, self._c_iv)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        return c_cipher_ctx

    def encrypt(self, data):
        """Encrypt a message.

        :param data: data to encrypt as a byte string
        :return: encrypted message

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        c_data = ffi.new('unsigned char[]', data)
        c_enc_data_alloc = 2*len(data)   # allocated enc_data size
        c_enc_data = ffi.new('unsigned char[]', c_enc_data_alloc)  # FIXME
        c_tmp_len = ffi.new('int*')

        c_cipher_ctx = self._init_cipher_ctx(is_encrypt=True)

        status = clib.EVP_EncryptUpdate(c_cipher_ctx, c_enc_data,
                                        c_tmp_len, c_data, len(data))
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        enc_data_len = c_tmp_len[0]

        status = clib.EVP_EncryptFinal_ex(c_cipher_ctx,
                                          c_enc_data[c_tmp_len[0]:c_enc_data_alloc],
                                          c_tmp_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        enc_data_len += c_tmp_len[0]

        encrypted_data = lib.retrieve_bytes(c_enc_data, enc_data_len)
        return encrypted_data

    def decrypt(self, data):
        """Decrypt a message.

        :param data: data to encrypt as a byte string
        :return: decrypted message

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        c_data = ffi.new('unsigned char[]', data)
        c_dec_data_alloc = len(data)
        c_dec_data = ffi.new('unsigned char[]', c_dec_data_alloc)
        c_tmp_len = ffi.new('int*')

        c_cipher_ctx = self._init_cipher_ctx(is_encrypt=False)

        status = clib.EVP_DecryptUpdate(c_cipher_ctx, c_dec_data,
                                        c_tmp_len, c_data, len(data))
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        dec_data_len = c_tmp_len[0]

        status = clib.EVP_DecryptFinal_ex(c_cipher_ctx,
                                          c_dec_data[c_tmp_len[0]:c_dec_data_alloc],
                                          c_tmp_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        dec_data_len += c_tmp_len[0]

        decrypted_data = lib.retrieve_bytes(c_dec_data, dec_data_len)
        return decrypted_data


class AES256_CTR(BaseCipherNoauth):
    """AES 256-bit cipher in CTR (counter) mode."""
    _CIPHER_ID = clib.EVP_aes_256_ctr()
    _MODE = MODE_CTR

class AES256_CBC(BaseCipherNoauth):
    """AES 256-bit cipher in CBC (cipher block chaining) mode."""
    _CIPHER_ID = clib.EVP_aes_256_cbc()
    _MODE = MODE_CBC

class GOST89_CTR(BaseCipherNoauth):
    """GOST R 28147-89 256-bit cipher in CTR (counter) mode."""
    _CIPHER_ID = clib.EVP_gost2814789_cnt()
    _MODE = MODE_CTR
