"""
Cryptomodule for Ghostbox.

Contains many cryptographic primitives for usage in Ghostbox. Specifically:

    * `digest` -- various hash functions
    * `cipher` -- symmetric ciphers
    * `mac` -- Message Authentication Codes
    * `rsa` -- RSA operations (sign/verify)
    * `kdf` -- key derivation algorithms

For more details, see appropriate subpackages.

"""

from .lib import initialize_libressl
initialize_libressl()
