"""
Various auxiliary routines

NB: intended only for internal use!

"""

try:
    from . import _cryptomodule
except ImportError:
    raise ImportError('Cryptomodule CFFI library not compiled')
from .exceptions import *

def initialize_libressl():
    _cryptomodule.lib.OPENSSL_add_all_algorithms_noconf();
    _cryptomodule.lib.ERR_load_crypto_strings();

def get_libressl_error():
    """Report LibreSSL error w/o passing a string."""
    ffi, lib = _cryptomodule.ffi, _cryptomodule.lib

    c_errno = lib.ERR_get_error()
    c_err_msg = lib.ERR_error_string(c_errno, ffi.NULL)
    err_msg = ffi.string(c_err_msg)

    # Usually, we don't want to see some weird characters from EBDIC.
    # Still, if there are bytes from range 128-255, then report as a byte
    # string.
    try:
        err_msg = err_msg.decode('ascii')
    except UnicodeDecodeError:
        pass
    return err_msg

def retrieve_bytes(cdata, size):
    """Retrieve byte string from cdata."""
    ffi = _cryptomodule.ffi
    return bytes(ffi.buffer(cdata, size))

def check_errcode(status):
    if status != 1:
        raise LibreSSLError(get_libressl_error())
