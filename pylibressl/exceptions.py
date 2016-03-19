"""
Cryptomodule exceptions

"""

class PaddingError(Exception):
    """Raised when decrypting message with incorrect padding using block
    cipher."""

class AuthencityError(Exception):
    pass

class RSAKeyError(Exception):
    pass

class LibreSSLError(Exception):
    def __init__(self, message, err_code):
        self.error_code = err_code
        self.message = message
        Exception.__init__(self, message)
