from ..lib import retrieve_bytes, check_status
from ..exceptions import *
from .. import _libressl

ffi, clib = _libressl.ffi, _libressl.lib

class BaseHash(object):
    """Generic hash object.

    When implementing a digest, `_HASH_ID` should be set to appropriate EVP_MD*
    using LibreSSL EVP functions.

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
        self._digest_finalized = False

        if data:
            self.update(data)

    def update(self, data):
        """Append more data to digest.

        Should not be called after ``digest()`` call. Otherwise,
        ``DigestReuseError`` is raised.

        """
        if self._digest_finalized:
            raise DigestReuseError

        if type(data) != type(b''):
            raise ValueError('Data should be a binary string')

        c_data = ffi.new('unsigned char[]', data)
        check_status(clib.EVP_DigestUpdate(self._c_digest_ctx, c_data,
                                           len(data)))

    def digest(self):
        """Show digest as a byte string."""
        self._digest_finalized = True

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


class Streebog512(BaseHash):
    """Streebog (GOST R 34.11.2012) hash."""
    _HASH_ID = clib.EVP_streebog512()

class SHA512(BaseHash):
    """SHA512 hash."""
    _HASH_ID = clib.EVP_sha512()

class SHA256(BaseHash):
    _HASH_ID = clib.EVP_sha256()
