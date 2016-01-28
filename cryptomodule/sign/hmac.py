try:
    from . import _sign
except ImportError:
    raise ImportError('Signing and MAC C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class _HMAC(object):
    """Generic HMAC class."""

    _DIGEST = None
    _DIGEST_LENGTH = 64   # should be an exact value, i.e. not EVP_MAX_MD_SIZE

    @classmethod
    def new(cls, private_key):
        """Create new HMAC instance."""
        if type(private_key) != type(b''):
            raise ValueError('Private key should be a byte string')
        mac = cls(private_key)
        return mac

    def __init__(self, private_key):
        ffi = _sign.ffi

        c_private_key = ffi.new('unsigned char[]', private_key)
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        self._c_pkey = ffi.gc(_sign.lib.pkey_hmac_init(c_private_key,
                                                       len(private_key),
                                                       c_err_msg,
                                                       lib.ERROR_MSG_LENGTH),
                              _sign.lib.EVP_PKEY_free)
        if self._c_pkey == ffi.NULL:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

    def sign(self, data):
        """Sign a message using HMAC."""

        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')

        ffi = _sign.ffi

        c_msg = ffi.new('unsigned char[]', data)
        c_signature = ffi.new('unsigned char[]', self._DIGEST_LENGTH)
        c_sign_len = ffi.new('size_t *')
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _sign.lib.hmac_sign(self._DIGEST, c_msg, len(data),
                                     c_signature, c_sign_len, self._c_pkey,
                                     c_err_msg, lib.ERROR_MSG_LENGTH)
        if not status:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)

        assert(self._DIGEST_LENGTH >= c_sign_len[0])      # TODO: add proper exception
        signature = lib.retrieve_bytes(ffi, c_signature, c_sign_len[0])
        return signature

    def verify(self, data, auth_code):
        """Verify message authencity using HMAC signature."""

        if type(data) != type(b''):
            raise ValueError('Data should be a byte string')
        if type(auth_code) != type(b''):
            raise ValueError('MAC should be a byte string')

        ffi = _sign.ffi

        c_msg = ffi.new('unsigned char[]', data)
        c_signature = ffi.new('unsigned char[]', auth_code)
        c_err_msg = ffi.new('char[]', lib.ERROR_MSG_LENGTH)

        status = _sign.lib.hmac_verify(self._DIGEST, c_msg, len(data),
                                       c_signature, len(auth_code), self._c_pkey,
                                       c_err_msg, lib.ERROR_MSG_LENGTH)

        if status == 0:
            err_msg = lib.report_libressl_error(ffi, c_err_msg)
            raise LibreSSLError(err_msg)
        elif status == -1:
            return False
        else:
            return True



class HMACStreebog512(_HMAC):
    """HMAC-Streebog512"""
    _DIGEST = _sign.lib.EVP_streebog512()
    _DIGEST_LENGTH = 64
