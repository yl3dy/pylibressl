Usage
=====

General remarks
---------------

There are base classes with ``Base`` prefix. These are intended to be used to determine
type of the primitive.

All returned sizes (like by ``BaseCipher.key_length()``) are in bytes.


Exceptions
----------

All exceptions are found in :doc:`pylibressl.exceptions`.

* ``AuthencityError``: message is not authentic. Used with authenticated
  decryption (e.g. AES-GCM);
* ``PaddingError``: message padding is wrong (block cipher decryption);
* ``RSAKeyError``: RSA key reading was unsuccessful;
* ``LibreSSLError``: generic LibreSSL error. Original error message and error
  code can be retrieved with ``LibreSSLError.message`` and ``LibreSSL.error_code``.


Examples
--------

See appropriate subpackage documentation for usage examples.
