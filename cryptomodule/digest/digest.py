try:
    from . import _digest
except ImportError:
    raise ImportError('Digest C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

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
    _MAX_HASH_SIZE = _digest.lib.EVP_MAX_MD_SIZE

    @classmethod
    def new(cls, data=None):
        """Create new hash instance."""
        hash = cls()
        if data:
            hash.update(data)
        return hash

    def __init__(self):
        self._msg = b''

    def update(self, data):
        """Append more data to digest."""
        if type(data) != type(b''):
            raise ValueError('Data should be a binary string')
        self._msg += data

    def digest(self):
        """Show digest as a byte string."""
        ffi = _digest.ffi

        c_msg = ffi.new('unsigned char[]', self._msg)
        c_digest = ffi.new('unsigned char[]', self._MAX_HASH_SIZE)
        c_digest_len = ffi.new('unsigned int*')
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _digest.lib.digest(self._HASH_ID, c_msg, len(self._msg),
                                    c_digest, c_digest_len, c_err_msg,
                                    lib.ERROR_MSG_LENGTH)

        if not status:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

        digest_value = lib.retrieve_bytes(ffi, c_digest, c_digest_len[0])

        # should save _msg till the end to help debugging library errors
        self._msg = b''

        return digest_value


class Streebog512(_Hash):
    """Streebog (GOST R 34.11.2012) hash."""
    _HASH_ID = _digest.lib.EVP_streebog512()

class SHA512(_Hash):
    """SHA512 hash."""
    _HASH_ID = _digest.lib.EVP_sha512()
