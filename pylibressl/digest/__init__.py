"""
Message digests

Usage example:

>>> from pylibressl.digest import SHA512
>>>
>>> data = b'Some binary data'
>>> hash = SHA512()
>>> hash_value = hash.update(data).digest()
>>>
>>> # Other possible form:
>>> # hash_value = SHA512(data).digest()

Note that you cannot call ``update()`` after ``digest()`` for the same hash
instance.

"""

from .digest import Streebog512, SHA512, SHA256, BaseHash

__all__ = ['Streebog512', 'SHA512', 'SHA256', 'BaseHash']
