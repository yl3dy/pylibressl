"""
RSA signing and encryption.

Contains routines to sign/verify, encrypt/decrypt messages using RSA and a
wrapper class to store RSA keypair.

Example:

>>> from cryptomodule.rsa import RSAKeypair, RSASign
>>>
>>> privkey = open('private_key.pem', 'rb').read()
>>> keypair = RSAKeypair(private_key=privkey)
>>> signer = RSASign(keypair)
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
from .sign import RSASign
from .cipher import RSACrypt

__all__ = ['RSAKeypair', 'RSASign', 'RSACrypt']
