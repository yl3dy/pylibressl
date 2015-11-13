"""Actual crypto routines."""

import cryptomodule._cryptomodule as _cryptomodule

def encrypt(data, qkey):
    key, iv, method = qkey
    set_arg = _cryptomodule.ffi.new

    c_data = set_arg('const char[]', data.encode())
    c_key = set_arg('unsigned char[]', key.encode())
    c_iv = set_arg('unsigned char[]', iv.encode())
    c_enc_data = set_arg('unsigned char[]', 2*len(data.encode()))
    c_enc_data_len = set_arg('int *')

    status = _cryptomodule.lib.gost_encrypt(c_data, len(data.encode()), c_key,
                                            c_iv, c_enc_data, c_enc_data_len)
    if status != 0:
        raise ValueError('Encrypt status nonzero')

    encrypted_data = _cryptomodule.ffi.string(c_enc_data, c_enc_data_len[0])
    return encrypted_data

def decrypt(data, qkey):
    pass
