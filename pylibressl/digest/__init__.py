"""
Digests

Usage example:

>>> from pylibressl.digest import SHA512
>>> data = b'Some binary data'
>>> data_digest = SHA512.new(data).digest()

"""

from .digest import Streebog512, SHA512, SHA256

__all__ = ['Streebog512', 'SHA512', 'SHA256']
