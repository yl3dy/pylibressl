from .. import lib
from ..exceptions import *
from .. import _libressl
from .cipher import BaseCipher, MODE_GCM
from .noauth import GOST89_CTR, AES256_CTR, BaseCipherNoauth
from ..digest.digest import _Hash, Streebog512, SHA512
from ..mac import HMAC

ffi, clib = _libressl.ffi, _libressl.lib

class BaseCipherAuth(BaseCipher):
    def encrypt(self, data):
        raise NotImplementedError

    def decrypt(self, data, auth_code):
        raise NotImplementedError


class CipherHMAC(BaseCipherAuth):
    """Ready to use cipher+HMAC combination."""
    @classmethod
    def new(cls, cipher_type, hash_type):
        """Create new cipher+HMAC type."""
        if not issubclass(cipher_type, BaseCipherNoauth):
            raise ValueError('Cipher should be a BaseCipherNoauth subclass')
        if not issubclass(hash_type, _Hash):
            raise ValueError('Wrong hash type')

        cls.CIPHER_TYPE = cipher_type
        cls.HASH_TYPE = hash_type
        return cls

    def __init__(self, key, iv):
        """Initialize cipher+HMAC with key and IV."""
        self._cipher = self.CIPHER_TYPE(key, iv)
        self._hmac = HMAC.new(self.HASH_TYPE)(key)

    def encrypt(self, data):
        """Encrypt a message.

        :param data: data to encrypt as a byte string
        :return: encrypted message and authencity code as byte strings

        """
        enc_data = self._cipher.encrypt(data)
        auth_code = self._hmac.sign(enc_data)
        return enc_data, auth_code

    def decrypt(self, data, auth_code):
        """Encrypt a message.

        :param data: data to encrypt as a byte string
        :param auth_code: authencity code as byte strings
        :return: decrypted message

        """
        if not self._hmac.verify(data, auth_code):
            raise AuthencityError
        else:
            dec_data = self._cipher.decrypt(data)
        return dec_data

GOST89_HMAC_Streebog512 = CipherHMAC.new(GOST89_CTR, Streebog512)
GOST89_HMAC_Streebog512.__doc__ = 'GOST89-HMAC-Streebog512'

AES256_HMAC_SHA512 = CipherHMAC.new(AES256_CTR, SHA512)
AES256_HMAC_SHA512.__doc__ = 'AES256-HMAC-SHA512'



class BaseCipherGCM(BaseCipherAuth):
    """Base GCM symmetric cipher class."""

    _AEAD_TAG_SIZE = 16

    @classmethod
    def iv_length(self):
        return self._AEAD_TAG_SIZE

    def _init_cipher_ctx(self, is_encrypt):
        init_func = clib.EVP_EncryptInit_ex if is_encrypt else clib.EVP_DecryptInit_ex

        c_cipher_ctx = ffi.gc(clib.EVP_CIPHER_CTX_new(),
                              clib.EVP_CIPHER_CTX_free)
        if c_cipher_ctx == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error())

        status = init_func(c_cipher_ctx, self._CIPHER_ID, ffi.NULL,
                           ffi.NULL, ffi.NULL)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        # Set IV length to 16
        status = clib.EVP_CIPHER_CTX_ctrl(c_cipher_ctx,
                                          clib.EVP_CTRL_GCM_SET_IVLEN,
                                          self._AEAD_TAG_SIZE, ffi.NULL)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = init_func(c_cipher_ctx, ffi.NULL, ffi.NULL, self._c_key,
                           self._c_iv)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        return c_cipher_ctx

    def encrypt(self, data, aad=None):
        """Encrypt a message.

        :param data: data to encrypt as a byte string
        :param aad: AAD data for GCM mode
        :return: encrypted message and tag as byte strings

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if aad != None and type(aad) != type(b''):
            raise ValueError('AAD should be a byte string')

        c_cipher_ctx = self._init_cipher_ctx(is_encrypt=True)

        c_data = ffi.new('unsigned char[]', data)
        c_enc_data_alloc = 2*len(data)
        c_enc_data = ffi.new('unsigned char[]', c_enc_data_alloc)
        c_tmp_len = ffi.new('int*')
        c_tag = ffi.new('unsigned char[]', self._AEAD_TAG_SIZE)
        if aad:
            c_aad = ffi.new('unsigned char[]', aad)

        # Write AAD
        if aad:
            status = clib.EVP_EncryptUpdate(c_cipher_ctx, ffi.NULL, c_tmp_len,
                                            c_aad, len(aad))
            if status != 1:
                raise LibreSSLError(lib.get_libressl_error())

        # Write data to encrypt
        status = clib.EVP_EncryptUpdate(c_cipher_ctx, c_enc_data, c_tmp_len,
                                        c_data, len(data))
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        enc_data_len = c_tmp_len[0]

        status = clib.EVP_EncryptFinal_ex(c_cipher_ctx,
                                          c_enc_data[c_tmp_len[0]:c_enc_data_alloc],
                                          c_tmp_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        enc_data_len += c_tmp_len[0]

        status = clib.EVP_CIPHER_CTX_ctrl(c_cipher_ctx,
                                          clib.EVP_CTRL_GCM_GET_TAG,
                                          self._AEAD_TAG_SIZE, c_tag)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        encrypted_data = lib.retrieve_bytes(c_enc_data, enc_data_len)
        tag = lib.retrieve_bytes(c_tag, self._AEAD_TAG_SIZE)
        return encrypted_data, tag

    def decrypt(self, data, tag, aad=None):

        """Decrypt a message.

        :param data: data to encrypt as a byte string
        :param tag: tag value
        :param aad: AAD data for GCM mode
        :return: decrypted message

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if aad != None and type(aad) != type(b''):
            raise ValueError('AAD should be a byte string')
        if type(tag) != type(b''):
            raise ValueError('Tag should be a byte string')
        if len(tag) != self._AEAD_TAG_SIZE:
            raise ValueError('Tag size is incorrect')

        c_cipher_ctx = self._init_cipher_ctx(is_encrypt=False)

        c_data = ffi.new('unsigned char[]', data)
        c_dec_data_alloc = 2*len(data)
        c_dec_data = ffi.new('unsigned char[]', c_dec_data_alloc)
        c_tmp_len = ffi.new('int*')
        c_tag = ffi.new('unsigned char[]', tag)
        if aad:
            c_aad = ffi.new('unsigned char[]', aad)

        # Write AAD
        if aad:
            status = clib.EVP_DecryptUpdate(c_cipher_ctx, ffi.NULL, c_tmp_len,
                                            c_aad, len(aad))
            if status != 1:
                raise LibreSSLError(lib.get_libressl_error())

        # Write data to decrypt
        status = clib.EVP_DecryptUpdate(c_cipher_ctx, c_dec_data, c_tmp_len,
                                        c_data, len(data))
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        dec_data_len = c_tmp_len[0]

        status = clib.EVP_CIPHER_CTX_ctrl(c_cipher_ctx,
                                          clib.EVP_CTRL_GCM_SET_TAG,
                                          self._AEAD_TAG_SIZE, c_tag)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib.EVP_DecryptFinal_ex(c_cipher_ctx,
                                          c_dec_data[c_tmp_len[0]:c_dec_data_alloc],
                                          c_tmp_len)
        if status <= 0:
            raise AuthencityError
        dec_data_len += c_tmp_len[0]

        decrypted_data = lib.retrieve_bytes(c_dec_data, dec_data_len)
        return decrypted_data


class AES256_GCM(BaseCipherGCM):
    """AES 256-bit cipher in GCM (Galois counter) mode."""
    _CIPHER_ID = clib.EVP_aes_256_gcm()
    _MODE = MODE_GCM
