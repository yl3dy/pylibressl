"""
Ciphers

Usage example:

>>> from cryptomodule.cipher import GOST89, MODE_CTR
>>> key, iv = b'1'*GOST89.KEY_LENGTH, b'2'*GOST89.BLOCK_SIZE
>>> data = b'Some data to be encoded'
>>> encoded_data = GOST89.new(key, iv, MODE_CTR).encrypt(data)

"""

from .cipher import MODE_CTR, MODE_GCM, MODE_CBC
from .cipher import GOST89, AES256
