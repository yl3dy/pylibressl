import _cryptomodule
# qkey = (key, iv, method)

def _setup_openssl():
    _cryptomodule.lib.setup_openssl()

def encrypt(data, qkey):
    key, iv, method = qkey

def decrypt(data, qkey):
    pass
