from ..lib import retrieve_bytes, check_status
from .. import _libressl
import warnings

ffi, clib = _libressl.ffi, _libressl.lib

# TODO: encrypt private key
def generate_rsa_key(bits=2048, exponent=65537):
    """Generate RSA key.

    :param bits: key length in bits
    :param exponent: exponent value, should be odd
    :returns: private key bytestring in PEM format

    """
    bits = int(bits)
    exponent = int(exponent)
    if exponent % 2 == 0:
        raise ValueError('Exponent should be odd')
    if bits < 1024:
        warnings.warn('Generating RSA key with insecurely short ' + \
                      'length: {}'.format(bits), RuntimeWarning)

    c_rsa = ffi.gc(clib.RSA_new(), clib.RSA_free)
    check_status(c_rsa, 'null')
    c_exponent = ffi.gc(clib.BN_new(), clib.BN_free)
    check_status(clib.BN_set_word(c_exponent, exponent))

    # Create BIOs for keys
    c_privkey_bio = ffi.gc(clib.BIO_new(clib.BIO_s_mem()), clib.BIO_free_all)
    check_status(c_privkey_bio, 'null')

    # Generate and read the keys
    check_status(clib.RSA_generate_key_ex(c_rsa, bits, c_exponent, ffi.NULL))
    check_status(clib.PEM_write_bio_RSAPrivateKey(c_privkey_bio, c_rsa, ffi.NULL,
                                                  ffi.NULL, 0, ffi.NULL,
                                                  ffi.NULL))

    # Retrieve key data from BIOs (ugh)
    privkey_len = clib.BIO_ctrl_pending(c_privkey_bio)
    c_privkey = ffi.new('unsigned char[]', privkey_len)

    check_status(clib.BIO_read(c_privkey_bio, ffi.cast('void*', c_privkey),
                               privkey_len), 'bio')

    privkey = retrieve_bytes(c_privkey, privkey_len)

    return privkey
