from ..lib import check_status, retrieve_bytes
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
        check_status(c_key_buf, 'null')

        c_rsa = ffi.gc(rsa_read_func(c_key_buf, ffi.NULL, ffi.NULL, ffi.NULL),
                       clib.RSA_free)
        check_status(c_rsa, 'null')

        modulus_size = clib.RSA_size(c_rsa)
        if modulus_size <= 0:
            raise LibreSSLError(lib.get_libressl_error())
        if hasattr(self, '_modulus_size'):
            if self._modulus_size != modulus_size:
                raise RSAKeyError
        else:
            self._modulus_size = modulus_size

        check_status(clib.EVP_PKEY_set1_RSA(self._c_pkey, c_rsa))

    def _set_pkey(self, public_key, private_key):
        self._c_pkey = ffi.gc(clib.EVP_PKEY_new(), clib.EVP_PKEY_free)
        check_status(self._c_pkey, 'null')

        if public_key:
            self._set_one_key(public_key, is_public=True)
        if private_key:
            self._set_one_key(private_key, is_public=False)


    def has_private_key(self):
        """Returns True if private key is present in keypair."""
        return self._is_privkey_present

    def key_size(self):
        """Get key size (actually, modulus length) in bytes."""
        return self._modulus_size


def public_from_private(private_key):
    """Derive public key from private one."""
    if not private_key or type(private_key) != type(b''):
        raise ValueError('Private key should be a byte string')

    # Allocate buffers
    c_privkey = ffi.new('const char[]', private_key)
    c_privkey_bio = ffi.gc(clib.BIO_new_mem_buf(ffi.cast('void*', c_privkey),
                                            len(private_key)),
                           clib.BIO_free_all)
    check_status(c_privkey_bio, 'null')
    c_pubkey_bio = ffi.gc(clib.BIO_new(clib.BIO_s_mem()), clib.BIO_free_all)
    check_status(c_pubkey_bio, 'null')

    # Load RSA key
    c_rsa = ffi.gc(clib.PEM_read_bio_RSAPrivateKey(c_privkey_bio, ffi.NULL,
                                                   ffi.NULL, ffi.NULL),
                   clib.RSA_free)
    check_status(c_rsa, 'null')

    # Derive public key
    check_status(clib.PEM_write_bio_RSAPublicKey(c_pubkey_bio, c_rsa))
    pubkey_len = clib.BIO_ctrl_pending(c_pubkey_bio)
    c_pubkey = ffi.new('unsigned char[]', pubkey_len)
    check_status(clib.BIO_read(c_pubkey_bio, ffi.cast('void*', c_pubkey),
                               pubkey_len), 'bio')

    pubkey = retrieve_bytes(c_pubkey, pubkey_len)
    return pubkey
