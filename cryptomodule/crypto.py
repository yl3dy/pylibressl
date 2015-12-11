"""Actual crypto routines."""

import cryptomodule._cryptomodule as _cryptomodule

def encrypt(data, qkey):
    """Encrypt data using GOST.

    data, key and iv should be `bytes` instances.

    """
    key, iv, method = qkey
    set_arg = _cryptomodule.ffi.new

    c_data = set_arg('const char[]', data)
    c_key = set_arg('unsigned char[]', key)
    c_iv = set_arg('unsigned char[]', iv)
    c_enc_data = set_arg('unsigned char[]', 2*len(data))
    c_enc_data_len = set_arg('int *')

    status = _cryptomodule.lib.gost_encrypt(c_data, len(data), c_key,
                                            c_iv, c_enc_data, c_enc_data_len)
    if status != 0:
        raise ValueError('Encrypt status nonzero')

    encrypted_data = _cryptomodule.ffi.string(c_enc_data, c_enc_data_len[0])
    return encrypted_data

def decrypt(data, qkey):
    """Decrypt data using GOST.

    data, key and iv should be `bytes` instances.

    """
    key, iv, method = qkey
    set_arg = _cryptomodule.ffi.new

    c_enc_data = set_arg('unsigned char[]', data)
    c_key = set_arg('unsigned char[]', key)
    c_iv = set_arg('unsigned char[]', iv)
    c_dec_data = set_arg('unsigned char[]', len(data))
    c_dec_data_len = set_arg('int*')

    status = _cryptomodule.lib.gost_decrypt(c_enc_data, len(data), c_key, c_iv,
                                            c_dec_data, c_dec_data_len)
    if status != 0:
        raise ValueError('Decrypt status nonzero')

    decrypted_data = _cryptomodule.ffi.string(c_dec_data, c_dec_data_len[0])
    return decrypted_data

def hash(data):
    set_arg = _cryptomodule.ffi.new

    c_msg = set_arg('unsigned char[]', data)
    c_digest = set_arg('unsigned char[]', 1024)   # FIXME
    c_digest_len = set_arg('unsigned int*')

    status = _cryptomodule.lib.streebog_digest(c_msg, c_digest, c_digest_len)

    if status != 0:
        raise ValueError('Digest status nonzero')

    digest = _cryptomodule.ffi.string(c_digest, c_digest_len[0])
    return digest
