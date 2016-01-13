import warnings
try:
    from . import _digest
except ImportError:
    warnings.warn('Digest C module not compiled', RuntimeWarning)
    _digest = None

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class Hash(object):
    """Generic digest class."""
    def __init__(self):
        pass

    @classmethod
    def new(cls, data=None):
        """Create new hash instance."""
        if not _digest:
            raise RuntimeError("Can't create hash object: digest module not compiled")

        hash = cls()
        if data:
            hash.update(data)
        return hash

    def update(self, data):
        """Append more data to digest."""

    def digest(self):
        """Show digest as a byte string."""

class Streebog512Hash(Hash):
    """Streebog (GOST R 34.11.2012) hash."""
    def __init__(self):
        ffi = _digest.ffi
        self.c_digest_ctx = ffi.gc(_digest.lib.streebog_init(),
                                   _digest.lib.streebog_teardown)
        if self.c_digest_ctx == ffi.NULL:
            raise HashError('Could not initialize Streebog hash')

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
        status = _digest.lib.streebog_update(self.c_digest_ctx, c_data,
                                             data_len)
        if not status:
            raise HashError('Could not update Streebog hash')

    def digest(self):
        """Show digest as a byte string."""
        if self._finalize_called:
            return self._digest_value
        else:
            ffi = _digest.ffi
            c_digest = ffi.new('unsigned char[]', 1024)   # FIXME
            c_digest_len = ffi.new('unsigned int*')

            status = _digest.lib.streebog_final(self.c_digest_ctx, c_digest,
                                                c_digest_len)
            if not status:
                raise HashError('Could not finalize Streebog hash')

            self._digest_value = lib.retrieve_bytes(ffi, c_digest, c_digest_len[0])
            self._finalize_called = True

            return self._digest_value
