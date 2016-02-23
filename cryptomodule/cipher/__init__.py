"""
Symmetric ciphers

Usage example:

>>> from cryptomodule.cipher import GOST89_CTR
>>> key, iv = b'1'*GOST89_CTR.key_length(), b'2'*GOST89_CTR.block_size()
>>> data = b'Some data to be encoded'
>>> encoded_data = GOST89_CTR.new(key, iv).encrypt(data)

"""

from .cipher import AES256_CTR, AES256_GCM, AES256_CBC, GOST89_CTR
from .cipher import MODE_CTR, MODE_GCM, MODE_CBC

__all__ = ['AES256_CTR', 'AES256_GCM', 'AES256_CBC', 'GOST89_CTR',
           'MODE_CBC', 'MODE_CTR', 'MODE_GCM']
