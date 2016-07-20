"""
Random number generation.

When used with LibreSSL, it uses `arc4random` algorithm based on ChaCha.

Usage example:

>>> # We want to get 32 bytes from PRNG
>>> from pylibressl.rand import get_random_bytes
>>> random = get_random_bytes(32)

"""

from .rand import get_random_bytes

__all__ = ['get_random_bytes']
