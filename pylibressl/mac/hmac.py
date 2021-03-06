from ..lib import retrieve_bytes, check_status
from ..exceptions import *
from .. import _libressl
from ..digest import BaseHash, Streebog512

ffi, clib = _libressl.ffi, _libressl.lib

class HMAC(object):
    """Generic HMAC class."""

    @classmethod
    def new(cls, hash_type, name='NewHMAC'):
        """Create new HMAC class with specified digest."""
        if not issubclass(hash_type, BaseHash):
            raise ValueError('Hash type should be a BaseHash subclass')

        return type(name, (cls,), {'_digest_type': hash_type})

    def __init__(self, private_key):
        """Create new HMAC instance."""
        if type(private_key) != type(b''):
            raise ValueError('Private key should be a byte string')

        # Set private key
        c_private_key = ffi.new('unsigned char[]', private_key)
        self._c_pkey = ffi.gc(clib.EVP_PKEY_new_mac_key(clib.EVP_PKEY_HMAC,
                                                        ffi.NULL,
                                                        c_private_key,
                                                        len(private_key)),
                              clib.EVP_PKEY_free)
        check_status(self._c_pkey, 'null')

    def _sign(self, data):
        digest_instance = self._digest_type()
        digest_ctx = digest_instance._c_digest_ctx   # shorthand
        c_msg = ffi.new('unsigned char[]', data)
        c_signature = ffi.new('unsigned char[]', self._digest_type.size())
        c_sign_len = ffi.new('size_t *')

        check_status(clib.EVP_DigestSignInit(digest_ctx, ffi.NULL,
                                             digest_instance._HASH_ID,
                                             ffi.NULL, self._c_pkey))

        check_status(clib._wrap_EVP_DigestSignUpdate(digest_ctx, c_msg,
                                                     len(data)))

        check_status(clib.EVP_DigestSignFinal(digest_ctx, c_signature,
                                              c_sign_len))
        assert c_sign_len[0] == self._digest_type.size()

        return c_signature, c_sign_len

    def sign(self, data):
        """Sign a message using HMAC."""
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        c_signature, c_sign_len = self._sign(data)
        return retrieve_bytes(c_signature, c_sign_len[0])

    def verify(self, data, auth_code):
        """Verify message authencity using HMAC signature."""
        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if type(auth_code) != type(b''):
            raise ValueError('MAC should be a byte string')

        c_data_hmac, c_data_hmac_len = self._sign(data)
        if c_data_hmac_len[0] != len(auth_code):
            raise ValueError('Incorrect authentication code length')

        c_signature = ffi.new('unsigned char[]', auth_code)

        comp_result = clib.CRYPTO_memcmp(c_signature, c_data_hmac,
                                         c_data_hmac_len[0])
        clib.OPENSSL_cleanse(c_data_hmac, c_data_hmac_len[0])   # TODO

        if comp_result == 0:
            return True
        else:
            return False

    def sign_size(self):
        """Return size of an authentication code."""
        return self._digest_type.size()

HMAC_Streebog512 = HMAC.new(Streebog512, name='HMAC_Streebog512')
HMAC_Streebog512.__doc__ = 'HMAC_Streebog512'
