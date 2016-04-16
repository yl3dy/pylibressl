"""
Key derivation functions.

Usage example:

>>> from pylibressl.kdf import PBKDF_HMAC_SHA256
>>>
>>> password = b'qwerty123'
>>> salt = b'salty salt'
>>> iteration_number = 16384
>>> key_length = 64
>>>
>>> deriv_key = PBKDF_HMAC_SHA256(salt, iteration_number, key_length).derivate(password)

"""

from .pbkdf import PBKDF_HMAC, PBKDF_HMAC_SHA256, PBKDF_HMAC_Streebog512

__all__ = ['PBKDF_HMAC', 'PBKDF_HMAC_SHA256', 'PBKDF_HMAC_Streebog512']
