import warnings
try:
    from . import _digest
except ImportError:
    warnings.warn('Digest C module not compiled', RuntimeWarning)
    _digest = None

import cryptomodule.lib as lib

def hash(data):
    set_arg = _digest.ffi.new

    c_msg = set_arg('unsigned char[]', data)
    c_digest = set_arg('unsigned char[]', 1024)   # FIXME
    c_digest_len = set_arg('unsigned int*')

    status = _digest.lib.streebog_digest(c_msg, c_digest, c_digest_len)

    if status != 0:
        raise ValueError('Digest status nonzero')

    digest = lib.retrieve_bytes(_digest.ffi, c_digest, c_digest_len[0])
    return digest
