"""
Various auxiliary routines

NB: intended only for internal use!

"""
ERROR_MSG_LENGTH = 256     # should be >= 120 !

def report_libressl_error(ffi, c_err_msg):
    """Represent LibreSSL error as a string."""
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
