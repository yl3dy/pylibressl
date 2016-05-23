from ..lib import retrieve_bytes, check_status, get_libressl_error
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

        class new_rsa_cipher(cls):
            _cipher_type = symmetric_cipher
        return new_rsa_cipher

    def __init__(self, keypair):
        """Create RSA ciphering object.

        :param keypair: list of or a single RSAKeypair object

        """
        if isinstance(keypair, RSAKeypair):
            self._keypairs = (keypair,)
        elif isinstance(keypair, (list, tuple)):   # TODO: more sane check if keypair is a list
            keysize = None
            for kp in keypair:
                if not isinstance(kp, RSAKeypair):
                    raise ValueError('RSAKeypair should be an RSAKeypair instance ' +
                                     'or a list of them')
            self._keypairs = tuple(keypair)
        else:
            raise ValueError('RSAKeypair should be an RSAKeypair instance ' +
                             'or a list of them')



    def encrypt(self, data):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        c_msg = ffi.new('unsigned char[]', data)
        c_msg_len = len(data)
        c_iv = ffi.new('unsigned char[]', self._cipher_type.iv_length())
        c_enc_msg = ffi.new('unsigned char[]', 2*c_msg_len)
        c_enc_msg_len = ffi.new('int*')

        c_cipher_id = self._cipher_type._CIPHER_ID
        ctx_tracker = self._cipher_type.ctx()    # track cipher ctx only
        c_cipher_ctx = ctx_tracker.c_cipher_ctx

        c_pkeys = ffi.new('EVP_PKEY*[]', [kp._c_pkey for kp in self._keypairs])
        c_session_keys = ffi.new('unsigned char*[]',
                                 [ffi.new('unsigned char[]', key.key_size())
                                  for key in self._keypairs])
        c_session_key_len = ffi.new('int[]', len(self._keypairs))

        def seal_init_errcheck(errcode):
            """Custom error code check for EVP_SealInit."""
            if errcode == 0:
                raise LibreSSLError(*get_libressl_error())
        check_status(clib.EVP_SealInit(c_cipher_ctx, c_cipher_id,
                                       c_session_keys, c_session_key_len, c_iv,
                                       c_pkeys, len(self._keypairs)),
                     action=seal_init_errcheck)

        check_status(clib._wrap_EVP_SealUpdate(c_cipher_ctx, c_enc_msg,
                                               c_enc_msg_len, c_msg,
                                               c_msg_len))
        enc_msg_len = c_enc_msg_len[0]

        check_status(clib.EVP_SealFinal(c_cipher_ctx, c_enc_msg,
                                        c_enc_msg_len))
        enc_msg_len += c_enc_msg_len[0]

        encoded_msg = retrieve_bytes(c_enc_msg, enc_msg_len)
        iv = retrieve_bytes(c_iv, self._cipher_type.iv_length())
        session_keys = [retrieve_bytes(c_session_keys[i], c_session_key_len[i])
                        for i in range(len(self._keypairs))]
        if len(session_keys) == 1:
            session_keys = session_keys[0]

        return encoded_msg, session_keys, iv

    def decrypt(self, data, session_key, iv, key_idx=0):
        """Decrypt RSA ciphertext.

        :param key_idx: index of keypair to use for decryption. Usually should
                        be 0.

        """
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

        c_pkey = self._keypairs[key_idx]._c_pkey
        c_cipher_id = self._cipher_type._CIPHER_ID
        ctx_tracker = self._cipher_type.ctx()    # track cipher ctx only
        c_cipher_ctx = ctx_tracker.c_cipher_ctx

        check_status(clib.EVP_OpenInit(c_cipher_ctx, c_cipher_id,
                                       c_session_key, c_session_key_len, c_iv,
                                       c_pkey))

        check_status(clib._wrap_EVP_OpenUpdate(c_cipher_ctx, c_msg, c_msg_len,
                                               c_enc_msg, c_enc_msg_len))
        msg_len = c_msg_len[0]

        check_status(clib.EVP_OpenFinal(c_cipher_ctx, c_msg, c_msg_len))
        msg_len += c_msg_len[0]

        message = retrieve_bytes(c_msg, msg_len)
        return message

RSACrypt_AES256 = RSACrypt.new(AES256_CTR)
