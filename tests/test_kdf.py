import cryptomodule.kdf as kdf
import cryptomodule.digest as dgst
import pytest

class TestPBKDF2:
    good_salt = b'very cool salt, yeah'
    good_iter_num = 8192
    good_key_length = 64
    good_password = b'qwerty123'
    digest = dgst.Streebog512

    def test_key_length(self):
        pbkdf = kdf.PBKDF_HMAC.new(self.good_salt, self.good_iter_num,
                                        self.good_key_length, self.digest)
        key = pbkdf.derivate(self.good_password)
        assert len(key) == self.good_key_length

    def test_wrong_salt_type(self):
        bad_salt = 3456789
        with pytest.raises(ValueError):
            pbkdf = kdf.PBKDF_HMAC.new(bad_salt, self.good_iter_num,
                                            self.good_key_length, self.digest)

    def test_wrong_pw_type(self):
        bad_pw = 3456789
        pbkdf = kdf.PBKDF_HMAC.new(self.good_salt, self.good_iter_num,
                                   self.good_key_length, self.digest)
        with pytest.raises(ValueError):
            key = pbkdf.derivate(bad_pw)
