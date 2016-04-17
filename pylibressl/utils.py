"""Miscellaneous useful utilities from LibreSSL."""
from . import _libressl

def secure_compare(rhs, lhs):
    """Securely compare byte strings.

    Constant-time comparison of byte strings using ``CRYPTO_memcmp`` from
    LibreSSL. Note that when byte string lengths are different, exception is
    raised at once.

    """
    ffi, clib = _libressl.ffi, _libressl.lib

    if type(rhs) != type(b'') or type(lhs) != type(b''):
        raise ValueError('Comparison arguments should be byte strings')
    if len(rhs) != len(lhs):
        raise ValueError('Arguments should be of the same length')

    c_rhs = ffi.new('unsigned char[]', rhs)
    c_lhs = ffi.new('unsigned char[]', lhs)
    length = len(rhs)

    comp_result = clib.CRYPTO_memcmp(c_rhs, c_lhs, length)

    return comp_result == 0
