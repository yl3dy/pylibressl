"""
Cryptomodule for Ghostbox.

Contains many cryptographic primitives for usage in Ghostbox. Currently only some
digests and symmetric ciphers are supported. For more details, see appropriate
subpackages.

"""

from .build import initialize_libressl
initialize_libressl()
