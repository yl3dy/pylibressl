"""
Various auxiliary routines

NB: intended only for internal use!

"""

def get_libressl_error(ffi, lib):
    """Report LibreSSL error w/o passing a string."""
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

def retrieve_bytes(ffi, cdata, size):
    """Retrieve byte string from cdata."""
    return bytes(ffi.buffer(cdata, size))
