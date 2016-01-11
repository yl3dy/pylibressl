def retrieve_bytes(ffi, cdata, size):
    """Retrieve byte string from cdata."""
    return bytes(ffi.buffer(cdata, size))
