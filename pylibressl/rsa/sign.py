from .. import lib
from ..exceptions import *
from .. import _libressl
from .keypair import RSAKeypair
from ..digest.digest import _Hash
from ..digest import SHA512

ffi, clib = _libressl.ffi, _libressl.lib

class RSASign(object):
    """RSA signing class."""

    @classmethod
    def new(cls, digest_type):
        """Create new RSA signing class."""
        if not issubclass(digest_type, _Hash):
            raise ValueError('Digest type must be a _Hash subclass')

        class new_rsa_sign(cls):
            _digest_type = digest_type
        return new_rsa_sign

    def __init__(self, rsa_keypair):
        """Create RSA signing object."""
        if not isinstance(rsa_keypair, RSAKeypair):
            raise ValueError('Keypair should be RSAKeypair instance')
        self._keypair = rsa_keypair

    def sign(self, message):
        """Sign a message with RSA."""
        if type(message) != type(b''):
            raise ValueError('Message should be a byte string')

        digest = self._digest_type()
        c_digest_ctx = digest._c_digest_ctx
        c_pkey = self._keypair._c_pkey
        c_hash_id = self._digest_type._HASH_ID

        c_msg = ffi.new('unsigned char[]', message)
        c_msg_len = len(message)
        c_signature = ffi.new('unsigned char[]', 16384)  # FIXME
        c_signature_len = ffi.new('size_t*')
        c_signature_len[0] = 16384   # FIXME

        status = clib.EVP_DigestSignInit(c_digest_ctx, ffi.NULL,
                                         c_hash_id, ffi.NULL, c_pkey)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib._wrap_EVP_DigestSignUpdate(c_digest_ctx, c_msg, c_msg_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib.EVP_DigestSignFinal(c_digest_ctx, c_signature,
                                          c_signature_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        signature = lib.retrieve_bytes(c_signature, c_signature_len[0])
        return signature

    def verify(self, message, signature):
        """Verify signed message with RSA."""
        if type(message) != type(b''):
            raise ValueError('Message should be byte string')
        if type(signature) != type(b''):
            raise ValueError('Signature should be byte string')
        if not self._keypair.has_private_key():
            raise ValueError("Keypair doesn't contain private key, " + \
                             "verification impossible")

        digest = self._digest_type()
        c_digest_ctx = digest._c_digest_ctx
        c_pkey = self._keypair._c_pkey
        c_hash_id = self._digest_type._HASH_ID

        c_msg = ffi.new('unsigned char[]', message)
        c_msg_len = len(message)
        c_signature = ffi.new('unsigned char[]', signature)
        c_signature_len = len(signature)

        status = clib.EVP_DigestVerifyInit(c_digest_ctx, ffi.NULL, c_hash_id,
                                           ffi.NULL, c_pkey)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib._wrap_EVP_DigestVerifyUpdate(c_digest_ctx, c_msg, c_msg_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib.EVP_DigestVerifyFinal(c_digest_ctx, c_signature,
                                            c_signature_len)
        if status == 1:
            return True
        elif status == 0:
            return False
        else:
            raise LibreSSLError(lib.get_libressl_error())

RSASign_SHA512 = RSASign.new(SHA512)
