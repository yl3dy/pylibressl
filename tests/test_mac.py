import pytest
from pylibressl.mac import HMAC, HMAC_Streebog512
from pylibressl.digest import Streebog512, SHA512
from pylibressl.exceptions import LibreSSLError

class GenericHMACTest:
    """Generic class for HMAC testing.

    In inherited classes should specify the following properties:

        - HMAC_CLASS  :  class name of HMAC

    """
    GOOD_STRING = b" \xbe\xafT\xe1l\x07b\xb3Y\x07\xa2\xa0\\\x14\xb2\xd1\x87\xbeY\xea\xd3k}\xf3g\x04\xfa$+\xa7-Hc}\xeaR\x9f\xce\xe1qK3p}\xafK\xde\x1e\x1a\xd5>i\xadD\xbd\xa1\xad\x06l\x1b\xa0\t\x05\xfa\xfe;\x7f\xa9\x96\xd0ly5\x9e\x8b3\x84O\xa2\x0f\xaa?\xbb\x07\x81~\xab\x8dBO>7\xcf\x9eF\x04\xa2\x8d0\x97\x16i\xbb\x82e\xb1\xc85\xf4\xe8\xc3\xf8)\xd1\xee\xd5gq\x8f\r\xd2\xde8\x8aS\xbf\x9c}k\xae6ga\xecD+\xc7\x1b\x10\xb4\xc7\xc3\xa9\xbc\xb30\xe1!\x82&\x85\x1f\xc0\x98Z\xc5\xfd\xeb\xadG;\x9d\x1a\xe0X\x85\x06\xa5\xe3#1\xb7\xa102_;\x94~\xf5\x99\xbc'\x98\xc7\x05\xaay/*\xae\xf7\x939\xef\x10\x1d<n/U\x9c\x95!E\xab\x075\xc7,\x16\xeb\xb27\xaf\x9a\x99"

    GOOD_PRIVATE_KEY = b'\xd6\xec\xf4xK\x87V2\xbbY\xc2\xbfL)p\xc3"\xb4\x98\xccd@\xd0\x8b\xd7\xfc\xb0\xdd!\xf7.\xdc\x99\xfah~\xd6\xfd\x14\x92\xb4\xb46~\xed\x06\x11Q8\x88RyC\xef\xd2\xf4\xe0\t\xaf\xbe\xe0zB\xee\x81\x93\xb2\x1b\xf6\xa7\x02\xce\x958\xf89#q\xa6\x16\xef~D\xa0g\x1b\x9c\x7f\xa8\x956jV^S\x1aO|\xa1\xb3\x02|\x94/\xfc\xbf \xcc\xa4%\xa1\x986\xb4\xab\x81\x98\x14a\xdb\x0c\xf0\x15|"\xfdH\x95'

    HMAC_CLASS = None

    def test_pkey_type(self):
        bad_pkey = 'lalalalala'
        with pytest.raises(ValueError):
            mac = self.HMAC_CLASS(bad_pkey)

    def test_sign_data_type(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        with pytest.raises(ValueError):
            mac.sign(12345)

    def test_verify_data_type(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        with pytest.raises(ValueError):
            mac.verify(12345, b'\x11' * mac.sign_size())

    def test_verify_signature_type(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        with pytest.raises(ValueError):
            mac.verify(self.GOOD_STRING, 12345)

    def test_sign_verify(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        signature = mac.sign(self.GOOD_STRING)
        assert mac.verify(self.GOOD_STRING, signature)

    def test_tampered_signature(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        bad_signature = b'\x11'*mac.sign_size()
        assert not mac.verify(self.GOOD_STRING, bad_signature)

    def test_signature_size(self):
        mac = self.HMAC_CLASS(self.GOOD_PRIVATE_KEY)
        signature = mac.sign(self.GOOD_STRING)
        assert len(signature) == mac.sign_size()

    def test_inheritance_identification(self):
        assert issubclass(self.HMAC_CLASS, HMAC)


class TestHMACStreebog512(GenericHMACTest):
    HMAC_CLASS = HMAC.new(Streebog512)

class TestHMACSHA512(GenericHMACTest):
    HMAC_CLASS = HMAC.new(SHA512)

class TestHMACStreebog512_Preset(GenericHMACTest):
    HMAC_CLASS = HMAC_Streebog512
