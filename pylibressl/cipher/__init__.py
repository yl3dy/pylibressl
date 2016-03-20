"""
Symmetric ciphers

Usage example:

>>> from pylibressl.cipher import GOST89_CTR
>>> key, iv = b'1'*GOST89_CTR.key_length(), b'2'*GOST89_CTR.block_size()
>>> data = b'Some data to be encoded'
>>> encoded_data = GOST89_CTR(key, iv).encrypt(data)

"""

from .cipher import MODE_CTR, MODE_GCM, MODE_CBC, BLOCK_MODES
from .auth import AES256_GCM, CipherHMAC, AES256_HMAC_SHA512, GOST89_HMAC_Streebog512
from .noauth import AES256_CBC, AES256_CTR, GOST89_CTR
from .onion import OnionCipher, Onion_AES256_GOST89

AES256 = {MODE_CBC: AES256_CBC, MODE_CTR: AES256_CTR, MODE_GCM: AES256_GCM}

__all__ = ['AES256_CTR', 'AES256_GCM', 'AES256_CBC', 'GOST89_CTR', 'MODE_CBC',
           'MODE_CTR', 'MODE_GCM', 'BLOCK_MODES', 'AES256', 'CipherHMAC',
           'AES256_HMAC_SHA512', 'GOST89_HMAC_Streebog512', 'OnionCipher',
           'Onion_AES256_GOST89']
