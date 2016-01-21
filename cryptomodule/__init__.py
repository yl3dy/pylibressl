"""
Cryptomodule for Ghostbox.

Contains many cryptographic primitives for usage in Ghostbox.

Examples:

>>> from cryptomodule.digest import SHA512
>>> data = b'Some binary data'
>>> data_digest = SHA512.new(data).digest()

"""
