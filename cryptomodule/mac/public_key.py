try:
    from . import _sign
except ImportError:
    raise ImportError('Signing and MAC C module not compiled')

import cryptomodule.lib as lib
from cryptomodule.exceptions import *

class _PublicKeySign(object):
    @classmethod
    def new(cls):
        pkey_sign = cls()
        return pkey_sign

    def __init__(self):
        pass

    def sign(self):
        pass

    def verify(self):
        pass
