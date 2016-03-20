"""
RSA signing and encryption.

Contains routines to sign/verify, encrypt/decrypt messages using RSA and a
wrapper class to store RSA keypair.

Example:

>>> from pylibressl.rsa import RSAKeypair, RSASign_SHA512
>>>
>>> privkey = open('private_key.pem', 'rb').read()
>>> keypair = RSAKeypair(private_key=privkey)
>>> signer = RSASign_SHA512(keypair)
>>>
>>> message = b'Example message. 1234567890'
>>> signature = signer.sign(message)
>>>
>>> if signer.verify(message, signature):
...     print('Signature is ok')
>>> else:
...     print('Signature is NOT ok!!!')

"""

from .keypair import RSAKeypair
from .sign import RSASign, RSASign_SHA512
from .cipher import RSACrypt, RSACrypt_AES256

__all__ = ['RSAKeypair', 'RSASign', 'RSACrypt', 'RSASign_SHA512',
           'RSACrypt_AES256']
