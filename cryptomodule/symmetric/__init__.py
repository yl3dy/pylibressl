import warnings
try:
    from . import _symmetric
except ImportError:
    warnings.warn('Symmetric encryption C module not compiled', RuntimeWarning)
    _symmetric = None

import cryptomodule.lib as lib

def encrypt(data, qkey):
    """Encrypt data using GOST.

    data, key and iv should be `bytes` instances.

    """
    key, iv, method = qkey
    set_arg = _symmetric.ffi.new

    c_data = set_arg('const char[]', data)
    c_key = set_arg('unsigned char[]', key)
    c_iv = set_arg('unsigned char[]', iv)
    c_enc_data = set_arg('unsigned char[]', 2*len(data))
    c_enc_data_len = set_arg('int *')

    status = _symmetric.lib.gost_encrypt(c_data, len(data), c_key, c_iv,
                                         c_enc_data, c_enc_data_len)
    if status != 0:
        raise ValueError('Encrypt status nonzero')

    encrypted_data = lib.retrieve_bytes(_symmetric.ffi, c_enc_data, c_enc_data_len[0])
    return encrypted_data

def decrypt(data, qkey):
    """Decrypt data using GOST.

    data, key and iv should be `bytes` instances.

    """
    key, iv, method = qkey
    set_arg = _symmetric.ffi.new

    c_enc_data = set_arg('unsigned char[]', data)
    c_key = set_arg('unsigned char[]', key)
    c_iv = set_arg('unsigned char[]', iv)
    c_dec_data = set_arg('unsigned char[]', len(data))
    c_dec_data_len = set_arg('int*')

    status = _symmetric.lib.gost_decrypt(c_enc_data, len(data), c_key, c_iv,
                                         c_dec_data, c_dec_data_len)
    if status != 0:
        raise ValueError('Decrypt status nonzero')

    decrypted_data = lib.retrieve_bytes(_symmetric.ffi, c_dec_data, c_dec_data_len[0])
    return decrypted_data
