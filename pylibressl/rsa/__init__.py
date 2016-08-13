"""
RSA signing and encryption.

Contains routines to sign/verify, encrypt/decrypt messages using RSA and a
wrapper class to store RSA keypair. Also it supports generation of RSA keys
with custom length and exponent. Note that only keys in PEM format are
supported.

Signing example:

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

Cipher example:

>>> from pylibressl.rsa import RSAKeypair, RSACrypt_AES256
>>>
>>> privkey = open('private_key.pem', 'rb').read()
>>> keypair = RSAKeypair(private_key=privkey)
>>> rsacrypt = RSACrypt_AES256(keypair)
>>>
>>> message = b'Example message. 1234567890'
>>> enc_message, session_key, iv = rsacrypt.encrypt(message)
>>> decoded_message = rsacrypt.decrypt(enc_message, session_key, iv)
>>> assert decoded_message == message

"""

from .keypair import RSAKeypair, public_from_private
from .sign import RSASign, RSASign_SHA512
from .cipher import RSACrypt, RSACrypt_AES256
from .keygen import generate_rsa_key

__all__ = ['RSAKeypair', 'RSASign', 'RSACrypt', 'RSASign_SHA512',
           'RSACrypt_AES256', 'generate_rsa_key', 'public_from_private']
