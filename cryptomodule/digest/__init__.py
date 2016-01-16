import warnings
try:
    from . import _digest
except ImportError:
    warnings.warn('Digest C module not compiled', RuntimeWarning)
    _digest = None

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class _Hash(object):
    """Generic hash object.

    When implementing a digest, `C_HASH_NAME` should be specified as a string
    containing the name of digest as it is understood by LibreSSL.

    """

    HASH_NAME = ''

    @classmethod
    def new(cls, data=None):
        """Create new hash instance."""
        if not _digest:
            raise RuntimeError("Can't create hash object: digest module not compiled")

        hash = cls()
        if data:
            hash.update(data)
        return hash

    def __init__(self):
        ffi = _digest.ffi

        if self.HASH_NAME:
            c_digest_id = _digest.lib.digest_id_init(self.HASH_NAME.encode('ascii'))
            if c_digest_id == ffi.NULL:
                raise ValueError('Hash name is invalid. This is likely a bug in cryptomodule')
        else:
            raise ValueError('Hash name was not set. This is likely a bug in cryptomodule')

        self.c_digest_ctx = ffi.gc(_digest.lib.digest_init(c_digest_id),
                                   _digest.lib.digest_teardown)
        if self.c_digest_ctx == ffi.NULL:
            raise HashError('Could not initialize hash')

        self._finalize_called = False

    def update(self, data):
        """Append more data to digest.

        Note that you can't call this method after calling digest().

        """
        if type(data) != type(b''):
            raise ValueError('Data should be a binary string')
        if self._finalize_called:
            raise RuntimeError('Could not update hash: already finalized')
        c_data = _digest.ffi.new('const char[]', data)
        data_len = len(data)
        status = _digest.lib.digest_update(self.c_digest_ctx, c_data,
                                             data_len)
        if not status:
            raise HashError('Could not update hash')

    def digest(self):
        """Show digest as a byte string."""
        if self._finalize_called:
            return self._digest_value
        else:
            ffi = _digest.ffi
            c_digest = ffi.new('unsigned char[]', 1024)   # FIXME
            c_digest_len = ffi.new('unsigned int*')

            status = _digest.lib.digest_final(self.c_digest_ctx, c_digest,
                                                c_digest_len)
            if not status:
                raise HashError('Could not finalize hash')

            self._digest_value = lib.retrieve_bytes(ffi, c_digest, c_digest_len[0])
            self._finalize_called = True

            return self._digest_value


class Streebog512Hash(_Hash):
    """Streebog (GOST R 34.11.2012) hash."""
    HASH_NAME = 'streebog512'

class SHA512Hash(_Hash):
    """SHA512 hash."""
    HASH_NAME = 'sha512'
