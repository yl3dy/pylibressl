from ..lib import retrieve_bytes, check_status
from ..exceptions import *
from .. import _libressl

ffi, clib = _libressl.ffi, _libressl.lib

class _Hash(object):
    """Generic hash object.

    When implementing a digest, `C_HASH_NAME` should be specified as a string
    containing the name of digest as it is understood by LibreSSL.

    """

    # Cdata containing EVP_MD digest identifier. Children should set this value
    # to an appropriate one.
    _HASH_ID = None

    def __init__(self, data=None):
        """Create new hash instance."""
        self._c_digest_ctx = ffi.gc(clib.EVP_MD_CTX_create(),
                                    clib.EVP_MD_CTX_destroy)
        check_status(self._c_digest_ctx, 'null')

        check_status(clib.EVP_DigestInit_ex(self._c_digest_ctx, self._HASH_ID,
                                            ffi.NULL))

        if data:
            self.update(data)

    def update(self, data):
        """Append more data to digest."""
        if type(data) != type(b''):
            raise ValueError('Data should be a binary string')

        c_data = ffi.new('unsigned char[]', data)
        check_status(clib.EVP_DigestUpdate(self._c_digest_ctx, c_data,
                                           len(data)))

    def digest(self):
        """Show digest as a byte string."""
        c_digest = ffi.new('unsigned char[]', self.size())
        c_digest_len = ffi.new('unsigned int*')

        check_status(clib.EVP_DigestFinal_ex(self._c_digest_ctx, c_digest,
                                             c_digest_len))
        assert c_digest_len[0] == self.size()

        digest_value = retrieve_bytes(c_digest, c_digest_len[0])
        return digest_value

    @classmethod
    def size(cls):
        """Return size of digest in bytes."""
        return clib.EVP_MD_size(cls._HASH_ID)

    @classmethod
    def block_size(cls):
        """Return block size of digest in bytes."""
        return clib.EVP_MD_block_size(cls._HASH_ID)

    @classmethod
    def max_size(cls):
        """Maximum hash size supported by LibreSSL."""
        return clib.EVP_MAX_MD_SIZE


class Streebog512(_Hash):
    """Streebog (GOST R 34.11.2012) hash."""
    _HASH_ID = clib.EVP_streebog512()

class SHA512(_Hash):
    """SHA512 hash."""
    _HASH_ID = clib.EVP_sha512()

class SHA256(_Hash):
    _HASH_ID = clib.EVP_sha256()
