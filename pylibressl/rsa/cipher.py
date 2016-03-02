from .. import lib
from ..exceptions import *
from .. import _libressl
from ..cipher import AES256_CTR
from ..cipher.noauth import BaseCipherNoauth
from .keypair import RSAKeypair

ffi, clib = _libressl.ffi, _libressl.lib

class RSACrypt(object):
    """RSA en/decryption class."""

    @classmethod
    def new(cls, symmetric_cipher):
        """Create new RSA cipher class."""
        if not issubclass(symmetric_cipher, BaseCipherNoauth):
            raise ValueError('Symmetric cipher should be BaseCipherNoauth subclass')

        cls._cipher_type = symmetric_cipher
        return cls

    def __init__(self, keypair):
        """Create Rsa ciphering object."""
        if not isinstance(keypair, RSAKeypair):
            raise ValueError('Keypair should be RSAKeypair instance')
        self._keypair = keypair

    def encrypt(self, data):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        c_msg = ffi.new('unsigned char[]', data)
        c_msg_len = len(data)
        # FIXME: here should be length of RSA key in bytes
        c_session_key = ffi.new('unsigned char[]', 256)
        c_session_key_len = ffi.new('int*')
        c_iv = ffi.new('unsigned char[]', self._cipher_type.iv_length())
        c_enc_msg = ffi.new('unsigned char[]', 2*c_msg_len)
        c_enc_msg_len = ffi.new('int*')

        c_pkey = self._keypair._c_pkey
        c_cipher_id = self._cipher_type._CIPHER_ID
        ctx_tracker = self._cipher_type.ctx()    # track cipher ctx only
        c_cipher_ctx = ctx_tracker.c_cipher_ctx

        # TODO: many pkeys/session_keys
        c_pkeys = ffi.new('EVP_PKEY*[1]', (c_pkey,))
        c_session_keys = ffi.new('unsigned char*[]', (c_session_key,))
        keynum = 1

        status = clib.EVP_SealInit(c_cipher_ctx, c_cipher_id, c_session_keys,
                                   c_session_key_len, c_iv, c_pkeys, keynum)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib._wrap_EVP_SealUpdate(c_cipher_ctx, c_enc_msg, c_enc_msg_len,
                                     c_msg, c_msg_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        enc_msg_len = c_enc_msg_len[0]

        status = clib.EVP_SealFinal(c_cipher_ctx, c_enc_msg, c_enc_msg_len)
        enc_msg_len += c_enc_msg_len[0]

        encoded_msg = lib.retrieve_bytes(c_enc_msg, enc_msg_len)
        iv = lib.retrieve_bytes(c_iv, self._cipher_type.iv_length())
        session_key = lib.retrieve_bytes(c_session_keys[0],
                                         c_session_key_len[0])

        return encoded_msg, session_key, iv

    def decrypt(self, data, session_key, iv):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if type(session_key) != type(b''):
            raise ValueError('Session key should be a byte string')

        c_enc_msg = ffi.new('unsigned char[]', data)
        c_enc_msg_len = len(data)
        c_session_key = ffi.new('unsigned char[]', session_key)
        c_session_key_len = len(session_key)
        c_iv = ffi.new('unsigned char[]', iv)
        c_msg = ffi.new('unsigned char[]', 2*c_enc_msg_len)
        c_msg_len = ffi.new('int*')

        c_pkey = self._keypair._c_pkey
        c_cipher_id = self._cipher_type._CIPHER_ID
        ctx_tracker = self._cipher_type.ctx()    # track cipher ctx only
        c_cipher_ctx = ctx_tracker.c_cipher_ctx

        status = clib.EVP_OpenInit(c_cipher_ctx, c_cipher_id, c_session_key,
                                   c_session_key_len, c_iv, c_pkey)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib._wrap_EVP_OpenUpdate(c_cipher_ctx, c_msg, c_msg_len, c_enc_msg,
                                     c_enc_msg_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        msg_len = c_msg_len[0]

        status = clib.EVP_OpenFinal(c_cipher_ctx, c_msg, c_msg_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        msg_len += c_msg_len[0]

        message = lib.retrieve_bytes(c_msg, msg_len)
        return message

RSACrypt_AES256 = RSACrypt.new(AES256_CTR)
