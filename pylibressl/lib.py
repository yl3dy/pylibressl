"""
Various auxiliary routines

**Intended only for internal use!**

"""

try:
    from . import _libressl
except ImportError:
    raise ImportError('LibreSSL CFFI library not compiled')
from .exceptions import *

ffi, clib = _libressl.ffi, _libressl.lib

def initialize_libressl():
    clib.OPENSSL_add_all_algorithms_noconf();
    clib.ERR_load_crypto_strings();

def get_libressl_error():
    """Report LibreSSL error w/o passing a string."""
    c_errno = clib.ERR_get_error()
    c_err_msg = clib.ERR_error_string(c_errno, ffi.NULL)
    err_msg = ffi.string(c_err_msg)

    # Usually, we don't want to see some weird characters from EBDIC.
    # Still, if there are bytes from range 128-255, then report as a byte
    # string.
    try:
        err_msg = err_msg.decode('ascii')
    except UnicodeDecodeError:
        pass
    return err_msg, c_errno

def retrieve_bytes(cdata, size):
    """Retrieve byte string from cdata."""
    return bytes(ffi.buffer(cdata, size))

def check_status(status_code, action=None):
    """Wrapper for status code processing.

    :param status_code: value, returned by LibreSSL function
    :param action: type of status code verification

    Action list:
        - None or 'simple': check if status_code != 1
        - 'null': check if status_code is NULL
        - 'auth': check if status_code == 0 (authentication in GCM mode)
        - 'verify': return True on 1, False on 0, raise exception on other
        - callable: call it with status_code as argument

    """
    if not action or action == 'simple':
        if status_code != 1:
            raise LibreSSLError(*get_libressl_error())
    elif action == 'null':
        if status_code == ffi.NULL:
            raise LibreSSLError(*get_libressl_error())
    elif action == 'auth':
        if status_code == 0:
            raise AuthencityError
    elif action == 'verify':
        if status_code == 1:
            return True
        elif status_code == 0:
            return False
        else:
            raise LibreSSLError(*get_libressl_error())
    elif callable(action):
        action(status_code)
    else:
        raise ValueError('Illegal action specified')
