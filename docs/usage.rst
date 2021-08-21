Usage
=====

A note about bundling
----------------------

This package is designed to work with a bundled LibreSSL library. Some advantages of such approach:

#. Ease of install on systems without LibreSSL in repositories (like Windows);
#. No need to install additional non-Python packages (useful for frozen builds);
#. Tighter control on version compatibility between pylibressl and LibreSSL.

Some of disadvantages:

#. *Security risks in case of vulnerabilities in LibreSSL*: the package needs to be completely rebuilt to update the library.
#. Somewhat larger wheels.

These points basically mirror the differences between dynamic and static linking. Choose carefully which of them are most important in a specific case.


General remarks
---------------

There are base classes with ``Base`` prefix. These are intended to be used to determine type of the primitive.

All returned sizes (e.g. by ``BaseCipher.key_length()``) are in bytes except where explicitly stated otherwise.

``rand.libressl_get_random_bytes`` is **NOT** fork-safe with at least LibreSSL 2.3.x. This is probably true for ``rand.get_random_bytes`` too.

For RSA key generation the following exponent values are recommended (according to `OpenSSL wiki <https://wiki.openssl.org/index.php/Manual:RSA_generate_key%283%29>`_): 3, 17, 65537 (default). In any case the exponent value should be odd.

Exceptions
----------

All exceptions are found in :doc:`pylibressl.exceptions`.

* ``AuthencityError``: message is not authentic. Used with authenticated decryption (e.g. AES-GCM);
* ``PaddingError``: message padding is wrong (block cipher decryption);
* ``RSAKeyError``: reading of an RSA key was unsuccessful;
* ``DigestReuseError``: ``BaseDigest.digest()`` method called more than once;
* ``LibreSSLError``: generic LibreSSL error. Note that several errors may be raised at once. Original error messages and error codes can be retrieved with ``LibreSSLError.message`` and ``LibreSSLError.error_code`` (both are always lists). If these lists are empty, it is likely a bug in pylibressl.


Examples
--------

See appropriate subpackage documentation for usage examples.
