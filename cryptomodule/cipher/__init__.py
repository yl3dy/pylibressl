"""
Ciphers

Usage example:

>>> from cryptomodule.cipher import GOST89
>>> key, iv = b'1'*GOST89.KEY_LENGTH, b'2'*GOST89.IV_LENGTH
>>> data = b'Some data to be encoded'
>>> encoded_data = GOST89.new(key, iv).encrypt(data)

"""

from .cipher import GOST89
