from .. import lib
from ..exceptions import *
from .. import _cryptomodule

ffi, clib = _cryptomodule.ffi, _cryptomodule.lib

class _Hash(object):
    """Generic hash object.

    When implementing a digest, `C_HASH_NAME` should be specified as a string
    containing the name of digest as it is understood by LibreSSL.

    """

    # Cdata containing EVP_MD digest identifier. Children should set this value
    # to an appropriate one.
    _HASH_ID = None
    # Maximum LibreSSL hash size. Not optimal, but the size is not very big
    # anyway.
    _MAX_HASH_SIZE = _cryptomodule.lib.EVP_MAX_MD_SIZE

    @classmethod
    def new(cls, data=None):
        """Create new hash instance."""
        hash = cls()
        if data:
            hash.update(data)
        return hash

    def __init__(self):
        self._c_digest_ctx = ffi.gc(clib.EVP_MD_CTX_create(),
                                    clib.EVP_MD_CTX_destroy)
        if self._c_digest_ctx == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib.EVP_DigestInit_ex(self._c_digest_ctx, self._HASH_ID,
                                        ffi.NULL)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

    def update(self, data):
        """Append more data to digest."""
        if type(data) != type(b''):
            raise ValueError('Data should be a binary string')

        c_data = ffi.new('unsigned char[]', data)
        status = clib.EVP_DigestUpdate(self._c_digest_ctx, c_data,
                                       len(data))
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

    def digest(self):
        """Show digest as a byte string."""
        c_digest = ffi.new('unsigned char[]', self.size())
        c_digest_len = ffi.new('unsigned int*')

        status = clib.EVP_DigestFinal_ex(self._c_digest_ctx, c_digest,
                                         c_digest_len)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())
        assert c_digest_len[0] == self.size()

        digest_value = lib.retrieve_bytes(c_digest, c_digest_len[0])
        return digest_value

    @classmethod
    def size(cls):
        """Return size of digest in bytes."""
        return clib.EVP_MD_size(cls._HASH_ID)

    @classmethod
    def block_size(cls):
        """Return block size of digest in bytes."""
        return clib.EVP_MD_block_size(cls._HASH_ID)


class Streebog512(_Hash):
    """Streebog (GOST R 34.11.2012) hash."""
    _HASH_ID = clib.EVP_streebog512()

class SHA512(_Hash):
    """SHA512 hash."""
    _HASH_ID = clib.EVP_sha512()
