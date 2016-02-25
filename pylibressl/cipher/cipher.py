from .. import lib
from ..exceptions import *
from .. import _libressl

ffi, clib = _libressl.ffi, _libressl.lib

# Mode identifiers
MODE_CTR = 1
MODE_GCM = 2
MODE_CBC = 3
MODES = {'CTR': MODE_CTR, 'GCM': MODE_GCM, 'CBC': MODE_CBC}


class _Cipher(object):
    """Base symmetric cipher class."""

    _CIPHER_ID = None  # EVP function returning EVP_CIPHER ID
    _MODE = None  # mode identifier (see MODE_* constants)

    @classmethod
    def new(cls, key, iv):
        """Create new cipher object."""
        # verify key/IV validity
        if type(key) != type(b'') or type(iv) != type(b''):
            raise ValueError('Key/IV values should be bytes instances')
        if len(key) != cls.key_length() or len(iv) != cls.iv_length():
            raise ValueError('Key/IV lengths are incorrect')

        cipher = cls(key, iv)
        return cipher

    @classmethod
    def ctx(cls):
        """Create simple container for cipher context"""
        class CtxTracker(object):
            pass

        CtxTracker._CIPHER_ID = cls._CIPHER_ID
        CtxTracker._MODE = cls._MODE
        CtxTracker.block_size = cls.block_size
        CtxTracker.key_length = cls.key_length
        CtxTracker.iv_length = cls.iv_length
        CtxTracker.mode = cls.iv_length

        ctxtracker = CtxTracker()
        ctxtracker.c_cipher_ctx = ffi.gc(clib.EVP_CIPHER_CTX_new(),
                                         clib.EVP_CIPHER_CTX_free)

        return ctxtracker

    def __init__(self, key, iv):
        self._c_key = ffi.new('unsigned char[]', key)
        self._c_key_len = len(key)
        self._c_iv = ffi.new('unsigned char[]', iv)
        self._c_iv_len = len(iv)

    @classmethod
    def block_size(self):
        return clib.EVP_CIPHER_block_size(self._CIPHER_ID)

    @classmethod
    def key_length(self):
        return clib.EVP_CIPHER_key_length(self._CIPHER_ID)

    @classmethod
    def iv_length(self):
        return clib.EVP_CIPHER_iv_length(self._CIPHER_ID)

    @classmethod
    def mode(self):
        return self._MODE

    def encrypt(self, data, **kwargs):
        """Encrypt a message.

        :param data: data to encrypt as a byte string
        :param **kwargs: additional options, `aad` - AAD data for GCM mode
        :return: encrypted message and (if GCM mode) tag as byte strings

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        return self._encrypt(data, **kwargs)

    def decrypt(self, data, **kwargs):
        """Decrypt a message.

        :param data: data to encrypt as a byte string
        :param *args: (if GCM mode) tag value
        :param **kwargs: additional options, `aad` - AAD data for GCM mode
        :return: decrypted message

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        return self._decrypt(data, **kwargs)

    def _init_cipher_ctx(self, is_encrypt):
        """Initialise cipher context.

        Should return cipher context cdata. It should be ready to do
        EVP_CipherUpdate.

        """
        raise NotImplementedError

    def _encrypt(self, **kwargs):
        raise NotImplementedError

    def _decrypt(self, **kwargs):
        raise NotImplementedError


class _CipherOrdinary(_Cipher):
    """Base ordinary (i.e. not AEAD) symmetric cipher class."""

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

    def _encrypt(self, data, **kwargs):
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

    def _decrypt(self, data, **kwargs):
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


class _CipherAEAD(_Cipher):
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

    def _encrypt(self, data, **kwargs):
        aad = kwargs.get('aad')
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

    def _decrypt(self, data, **kwargs):
        aad = kwargs.get('aad')
        tag = kwargs.get('tag')
        if aad != None and type(aad) != type(b''):
            raise ValueError('AAD should be a byte string')
        if not tag or type(tag) != type(b''):
            raise ValueError('Tag should be present and a byte string')
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



class AES256_CTR(_CipherOrdinary):
    """AES 256-bit cipher in CTR (counter) mode."""
    _CIPHER_ID = clib.EVP_aes_256_ctr()
    _MODE = MODE_CTR

class AES256_CBC(_CipherOrdinary):
    """AES 256-bit cipher in CBC (cipher block chaining) mode."""
    _CIPHER_ID = clib.EVP_aes_256_cbc()
    _MODE = MODE_CBC

class AES256_GCM(_CipherAEAD):
    """AES 256-bit cipher in GCM (Galois counter) mode."""
    _CIPHER_ID = clib.EVP_aes_256_gcm()
    _MODE = MODE_GCM

class GOST89_CTR(_CipherOrdinary):
    """GOST R 28147-89 256-bit cipher in CTR (counter) mode."""
    _CIPHER_ID = clib.EVP_gost2814789_cnt()
    _MODE = MODE_CTR


AES256 = {MODE_CBC: AES256_CBC, MODE_CTR: AES256_CTR, MODE_GCM: AES256_GCM}
