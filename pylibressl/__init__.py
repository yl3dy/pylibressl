"""
LibreSSL bindings for Python.

Contains many cryptographic primitives, specifically:

    * `digest` -- various hash functions
    * `cipher` -- symmetric ciphers, incl. authenticated
    * `mac` -- Message Authentication Codes
    * `rsa` -- RSA operations (sign/verify)
    * `kdf` -- key derivation algorithms
    * `utils` -- miscellaneous crypto utilities

For more details, see appropriate subpackages.

"""

from .lib import initialize_libressl
initialize_libressl()
