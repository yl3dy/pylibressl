"""
Crypto signing: HMAC etc.

Signing example:

>>> from pylibressl.mac import HMAC_Streebog512
>>> data = b'Some data to sign'
>>> private_key = b'Some private key 12345678990asdfghjkl'
>>> signature = HMAC_Streebog512(private_key).sign(data)

Verifying example:

>>> from pylibressl.mac import HMAC_Streebog512
>>> data = b'Some data to verify'
>>> private_key = b'Some private key 12345678990asdfghjkl'
>>> signature = b'signature'
>>> if HMAC_Streebog512(private_key).verify(data, signature):
>>>     print('Signature is ok')
>>> else:
>>>     print('Data or signature are corrupt!')

"""

from .hmac import HMAC, HMAC_Streebog512

__all__ = ['HMAC', 'HMAC_Streebog512']
