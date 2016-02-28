from .. import lib
from ..exceptions import *
from .. import _libressl

ffi, clib = _libressl.ffi, _libressl.lib

# Mode identifiers
MODE_CTR = 1
MODE_GCM = 2
MODE_CBC = 3
MODES = {'CTR': MODE_CTR, 'GCM': MODE_GCM, 'CBC': MODE_CBC}


class BaseCipher(object):
    """Base symmetric cipher class."""

    _CIPHER_ID = None  # EVP function returning EVP_CIPHER ID
    _MODE = None  # mode identifier (see MODE_* constants)

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
        """Create new cipher object."""
        if type(key) != type(b'') or type(iv) != type(b''):
            raise ValueError('Key/IV values should be bytes instances')
        if len(key) != self.key_length() or len(iv) != self.iv_length():
            raise ValueError('Key/IV lengths are incorrect')

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
        raise NotImplementedError

    def decrypt(self, data, **kwargs):
        raise NotImplementedError

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
