from .. import lib
from ..exceptions import *
from .. import _libressl

ffi, clib = _libressl.ffi, _libressl.lib

class RSAKeypair(object):
    """RSA keypair container."""

    def __init__(self, public_key=None, private_key=None):
        """Create new RSA keypair."""
        if not public_key and not private_key:
            raise ValueError('Should specify at least one key')

        if private_key and type(private_key) != type(b''):
            raise ValueError('Private key should be bytes')
        if public_key and type(public_key) != type(b''):
            raise ValueError('Public key should be bytes')

        self._is_privkey_present = (private_key != None)
        self._set_pkey(public_key, private_key)

    def _set_one_key(self, key, is_public):
        if is_public:
            rsa_read_func = clib.PEM_read_bio_RSAPublicKey
        else:
            rsa_read_func = clib.PEM_read_bio_RSAPrivateKey

        c_key = ffi.new('const char[]', key)
        c_key_buf = ffi.gc(clib.BIO_new_mem_buf(ffi.cast('void*', c_key),
                                                len(key)),
                            clib.BIO_free_all)
        if c_key_buf == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error())

        c_rsa = ffi.gc(rsa_read_func(c_key_buf, ffi.NULL, ffi.NULL, ffi.NULL),
                       clib.RSA_free)
        if c_rsa == ffi.NULL:
            raise LibreSSLError(lib.get_libressl_error())

        status = clib.EVP_PKEY_set1_RSA(self._c_pkey, c_rsa)
        if status != 1:
            raise LibreSSLError(lib.get_libressl_error())

    def _set_pkey(self, public_key, private_key):
        self._c_pkey = ffi.gc(clib.EVP_PKEY_new(), clib.EVP_PKEY_free)

        if public_key:
            self._set_one_key(public_key, is_public=True)
        if private_key:
            self._set_one_key(private_key, is_public=False)


    def has_private_key(self):
        """Returns True if private key is present in keypair."""
        return self._is_privkey_present