import pylibressl.kdf as kdf
import pylibressl.digest as dgst
import pytest

class GenericPBKDFTest:
    good_salt = b'very cool salt, yeah'
    good_iter_num = 8192
    good_key_length = 64
    good_password = b'qwerty123'
    pbkdf_cls = None

    def test_key_length(self):
        pbkdf = self.pbkdf_cls(self.good_salt, self.good_iter_num,
                               self.good_key_length)
        key = pbkdf.derivate(self.good_password)
        assert len(key) == self.good_key_length

    def test_wrong_salt_type(self):
        bad_salt = 3456789
        with pytest.raises(ValueError):
            pbkdf = self.pbkdf_cls(bad_salt, self.good_iter_num,
                                   self.good_key_length)

    def test_wrong_pw_type(self):
        bad_pw = 3456789
        pbkdf = self.pbkdf_cls(self.good_salt, self.good_iter_num,
                               self.good_key_length)
        with pytest.raises(ValueError):
            key = pbkdf.derivate(bad_pw)

    def test_different_passwords(self):
        pbkdf = self.pbkdf_cls(self.good_salt, self.good_iter_num,
                               self.good_key_length)
        key1 = pbkdf.derivate(self.good_password)
        key2 = pbkdf.derivate(self.good_password + b'\xff')
        assert len(key1) == len(key2)
        assert key1 != key2


class TestPBKDFPreset_Streebog512(GenericPBKDFTest):
    pbkdf_cls = kdf.PBKDF_HMAC_Streebog512

class TestPBKDFPreset_SHA256(GenericPBKDFTest):
    pbkdf_cls = kdf.PBKDF_HMAC_SHA256

# To verify PBKDF_HMAC.new
class TestPBKDF_SHA512(GenericPBKDFTest):
    pbkdf_cls = kdf.PBKDF_HMAC.new(dgst.SHA512)
