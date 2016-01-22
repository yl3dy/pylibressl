from cryptomodule.cipher import GOST89

class GenericCipherTest:
    """Base class for cipher tests

    The following variables should be set:

        - CIPHER_CLASS    : name of cipher class
        - KEY_LENGTH      : length of key
        - IV_LENGTH       : length of IV

    """
    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'

    def setup_key_iv(self):
        self.good_key = b'1' * self.KEY_LENGTH
        self.good_iv = b'2' * self.IV_LENGTH

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        cipher = GOST89.new(self.good_key, self.good_iv)
        encoded = cipher.encrypt(self.good_string)
        decoded = cipher.encrypt(encoded)

        assert self.good_string == decoded


class TestGOST89(GenericCipherTest):
    CIPHER_CLASS = GOST89
    KEY_LENGTH = 32
    IV_LENGTH = 8
