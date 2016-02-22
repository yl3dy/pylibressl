"""
Key derivation algorithms.

Usage example:

>>> from cryptomodule.kdf import PBKDF_HMAC
>>> from cryptomodule.digest import SHA512
>>> password = b'qwerty123'
>>> key = PBKDF_HMAC.new(b'Salt', 8192, 64, SHA512).derivate(password)

"""

from .pbkdf import PBKDF_HMAC

__all__ = ['PBKDF_HMAC']
