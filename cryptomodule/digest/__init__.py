"""
Digests

Usage example:

>>> from cryptomodule.digest import SHA512
>>> data = b'Some binary data'
>>> data_digest = SHA512.new(data).digest()

"""

from .digest import Streebog512, SHA512
