try:
    from . import _rsa
except ImportError:
    raise ImportError('RSA C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *
from cryptomodule.cipher.cipher import _Cipher

class RSAKeypair(object):
    """RSA keypair container."""

    def __init__(self, public_key=None, private_key=None):
        """Create new RSA keypair."""
        if not public_key and not private_key:
            raise ValueError('Should specify at least one key')

        if private_key and type(private_key) != type(b''):
            raise ValueError('Private key should be str or bytes')
        if public_key and type(public_key) != type(b''):
            raise ValueError('Public key should be str or bytes')

        self._is_privkey_present = (private_key != None)

        ffi = _rsa.ffi

        c_priv_key = ffi.new('const char[]', private_key if private_key else
                             b'')
        priv_key_len = len(private_key) if private_key else 0
        c_pub_key = ffi.new('const char[]', public_key if public_key else b'')
        pub_key_len = len(public_key) if public_key else 0

        self._pkey = ffi.gc(_rsa.lib.init_pkey(c_pub_key, pub_key_len,
                                               c_priv_key, priv_key_len),
                            _rsa.lib.EVP_PKEY_free)
        if self._pkey == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error(ffi, _rsa.lib))

    def has_private_key(self):
        """Returns True if private key is present in keypair."""
        return self._is_privkey_present


class RSASignVerify(object):
    """RSA signing class."""

    @classmethod
    def new(cls, rsa_keypair):
        """Create new RSA signing object."""
        if not isinstance(rsa_keypair, RSAKeypair):
            raise ValueError('Keypair should be RSAKeypair instance')

        pkey_sign = cls(rsa_keypair)
        return pkey_sign

    def __init__(self, rsa_keypair):
        self._keypair = rsa_keypair

    def sign(self, message):
        if type(message) != type(b''):
            raise ValueError('Message should be byte string')

        ffi = _rsa.ffi

        c_msg = ffi.new('unsigned char[]', message)
        c_signature = ffi.new('unsigned char[]', 8192)  # FIXME: should be actual keysize
        c_signature_len = ffi.new('size_t*')

        status = _rsa.lib.rsa_sign(c_msg, len(message), self._keypair._pkey,
                                   c_signature, c_signature_len)
        if not status:
            raise LibreSSLError(lib.get_libressl_error(ffi, _rsa.lib))

        signature = lib.retrieve_bytes(ffi, c_signature, c_signature_len[0])
        return signature

    def verify(self, message, signature):
        if type(message) != type(b''):
            raise ValueError('Message should be byte string')
        if type(signature) != type(b''):
            raise ValueError('Signature should be byte string')
        if not self._keypair.has_private_key():
            raise ValueError("Keypair doesn't contain private key, " + \
                             "verification impossible")
        ffi = _rsa.ffi

        c_msg = ffi.new('unsigned char[]', message)
        c_signature = ffi.new('unsigned char[]', signature)

        status = _rsa.lib.rsa_verify(c_msg, len(message), c_signature,
                                     len(signature), self._keypair._pkey)

        if status == 1:
            return True
        elif status == -1:
            return False
        else:
            raise LibreSSLError(lib.get_libressl_error(ffi, _rsa.lib))



class RSACrypt(object):
    """RSA en/decryption class."""

    @classmethod
    def new(cls, keypair, symmetric_cipher=None):
        """Create new en/decryption object.

        NB! Setting custom symmetric cipher is not supported yet, AES256-CTR is
        hardcoded.

        """
        if not isinstance(keypair, RSAKeypair):
            raise ValueError('Keypair should be RSAKeypair instance')

        rsacrypt = cls(keypair)
        return rsacrypt

    def __init__(self, keypair):
        self._keypair = keypair

    def encrypt(self, data):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        ffi = _rsa.ffi

        c_msg = ffi.new('unsigned char[]', data)
        c_msg_len = len(data)
        c_session_key = ffi.new('unsigned char[]', 1024)
        c_session_key_len = ffi.new('size_t*')
        c_iv = ffi.new('unsigned char[]', 16)
        c_enc_msg = ffi.new('unsigned char[]', 2*c_msg_len)
        c_enc_msg_len = ffi.new('size_t*')
        c_cipher_id = _rsa.lib.EVP_aes_256_ctr()   # TODO
        c_pkey = self._keypair._pkey

        status = _rsa.lib.rsa_encrypt(c_msg, c_msg_len, c_pkey,
                                      c_iv, c_cipher_id, c_session_key,
                                      c_session_key_len, c_enc_msg,
                                      c_enc_msg_len)

        if not status:
            raise LibreSSLError(lib.get_libressl_error(ffi, _rsa.lib))

        session_key = lib.retrieve_bytes(ffi, c_session_key,
                                         c_session_key_len[0])
        encoded_msg = lib.retrieve_bytes(ffi, c_enc_msg, c_enc_msg_len[0])
        iv = lib.retrieve_bytes(ffi, c_iv, 16)

        return encoded_msg, session_key, iv

    def decrypt(self, data, session_key, iv):
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if type(session_key) != type(b''):
            raise ValueError('Session key should be a byte string')

        ffi = _rsa.ffi

        c_enc_msg = ffi.new('unsigned char[]', data)
        c_enc_msg_len = len(data)
        c_session_key = ffi.new('unsigned char[]', session_key)
        c_session_key_len = len(session_key)
        c_iv = ffi.new('unsigned char[]', iv)
        c_msg = ffi.new('unsigned char[]', 2*c_enc_msg_len)
        c_msg_len = ffi.new('size_t*')
        c_cipher_id = _rsa.lib.EVP_aes_256_ctr()   # TODO

        status = _rsa.lib.rsa_decrypt(c_enc_msg, c_enc_msg_len,
                                      self._keypair._pkey, c_iv,
                                      c_cipher_id, c_session_key,
                                      c_session_key_len, c_msg, c_msg_len)

        if not status:
            raise LibreSSLError(lib.get_libressl_error(ffi, _rsa.lib))

        decoded_msg = lib.retrieve_bytes(ffi, c_msg, c_msg_len[0])

        return decoded_msg
