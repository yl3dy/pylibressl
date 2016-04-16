"""
Symmetric ciphers

Includes both authenticated and not authenticated modes and onion ciphering.

Non-authenticated example:

>>> from pylibressl.cipher import GOST89_CTR
>>> key, iv = b'1'*GOST89_CTR.key_length(), b'2'*GOST89_CTR.iv_length()
>>> data = b'Some data to be encoded'
>>> encoded_data = GOST89_CTR(key, iv).encrypt(data)

Authenticated example:

>>> from pylibresl.cipher import GOST89_HMAC_Streebog512
>>>
>>> data = b'Attack at dawn'
>>> key = b'\xf1' * GOST89_HMAC_Streebog512.CIPHER_TYPE.key_length()
>>> iv = b'\x3a' * GOST89_HMAC_Streebog512.CIPHER_TYPE.iv_length()
>>> ciphertext, auth_code = GOST89_HMAC_Streebog512(key, iv).encrypt(data)
>>>
>>> # Decryption:
>>> decrypted = GOST89_HMAC_Streebog512(key, iv).decrypt(ciphertext, auth_code)
>>> assert decrypted == data

AEAD (AES-GCM) example:

>>> from pylibressl.cipher import AES256_GCM
>>>
>>> data = b'PIN code is 1234'
>>> key = b'1' * AES256_GCM.key_length()
>>> iv = b'2' * AES256_GCM.iv_length()
>>> aad = b'Credit card data for John Doe'   # additional authenticated data
>>> ciphertext, tag = AES256_GCM(key, iv).encrypt(data, aad=aad)
>>>
>>> # Decryption:
>>> decrypted = AES256_GCM(key, iv).decrypt(data, tag, aad=aad)
>>> assert data == decrypted

Onion ciphering:

>>> from pylibressl.cipher import Onion_AES256_GOST89, AES256_GCM, GOST89_CTR
>>>
>>> key1 = b'\xf0' * AES256_GCM.key_length()
>>> iv1 = b'\xf1' * AES256_GCM.iv_length()
>>> key2 = b'\xf2' * GOST89_CTR.key_length()
>>> iv2 = b'\xf3' * GOST89_CTR.iv_length()
>>> key_list = [(key1, iv1), (key2, iv2)]
>>>
>>> data = b'Attack at dawn.'
>>>
>>> ciphertext, auth_codes = Onion_AES256_GOST89(key_list).encrypt(data)
>>> decrypted = Onion_AES256_GOST89(key_list).decrypt(data, auth_codes)
>>> assert data == decrypted

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
