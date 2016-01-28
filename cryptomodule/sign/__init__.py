"""
Crypto signing: HMAC etc.

Signing example:

>>> from cryptomodule.sign import HMACStreebog512
>>> data = b'Some data to sign'
>>> private_key = b'Some private key 12345678990asdfghjkl'
>>> signature = HMACStreebog512.new(private_key).sign(data)

Verifying example:

>>> from cryptomodule.sign import HMACStreebog512
>>> data = b'Some data to verify'
>>> private_key = b'Some private key 12345678990asdfghjkl'
>>> signature = b'signature'
>>> if HMACStreebog512.new(private_key).verify(data, signature):
>>>     print('Signature is ok')
>>> else:
>>>     print('Data or signature are corrupt!')

"""

from .hmac import HMACStreebog512

__all__ = ['HMACStreebog512']
