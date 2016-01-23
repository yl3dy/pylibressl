import pytest
from cryptomodule.cipher import GOST89, AES256
from cryptomodule.cipher import MODE_CTR, MODE_CBC

class GenericCipherTest:
    """Base class for cipher tests

    The following variables should be set:

        - CIPHER_CLASS    : name of cipher class
        - KEY_LENGTH      : length of key
        - BLOCK_SIZE      : length of IV
        - MODES           : modes to test

    """
    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'

    def setup_key_iv(self):
        self.good_key = b'a' * self.KEY_LENGTH
        self.good_key_2 = b'1' * self.KEY_LENGTH
        self.good_iv = b'2' * self.BLOCK_SIZE
        self.good_iv_2 = b'3' * self.BLOCK_SIZE


    def test_encryption_presence(self):
        self.setup_key_iv()

        for mode in self.MODES:
            cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv, mode)
            assert self.good_string != cipher.encrypt(self.good_string)

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        for mode in self.MODES:
            cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv, mode)
            encoded = cipher.encrypt(self.good_string)
            decoded = cipher.decrypt(encoded)
            assert self.good_string == decoded

    def test_decrypt_with_different_iv(self):
        self.setup_key_iv()

        for mode in self.MODES:
            cipher_1 = self.CIPHER_CLASS.new(self.good_key, self.good_iv,
                                              mode)
            cipher_2 = self.CIPHER_CLASS.new(self.good_key, self.good_iv_2,
                                              mode)
            encoded = cipher_1.encrypt(self.good_string)
            decoded = cipher_2.decrypt(encoded)
            assert self.good_string != decoded

    # The following test produces LibreSSL error:
    # digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:evp/evp_enc.c:529:
    # TODO: find out if this is ok for different keys
    #def test_decrypt_with_different_keys(self):
        #self.setup_key_iv()

        #for mode in self.MODES:
            #cipher_1 = self.CIPHER_CLASS.new(self.good_key, self.good_iv,
                                              #mode)
            #cipher_2 = self.CIPHER_CLASS.new(self.good_key_2, self.good_iv,
                                              #mode)
            #encoded = cipher_1.encrypt(self.good_string)
            #decoded = cipher_2.decrypt(encoded)
            #assert self.good_string != decoded

    def test_input_types(self):
        bad_key = 'lorem ipsum'
        bad_iv = 'sapere aude'
        bad_mode = 100500

        with pytest.raises(ValueError):
            cipher = self.CIPHER_CLASS.new(bad_key, bad_iv, bad_mode)


class TestGOST89(GenericCipherTest):
    CIPHER_CLASS = GOST89
    KEY_LENGTH = 32
    BLOCK_SIZE = 8
    MODES = (MODE_CTR,)

class TestAES256(GenericCipherTest):
    CIPHER_CLASS = AES256
    KEY_LENGTH = 32
    BLOCK_SIZE = 16
    MODES = (MODE_CTR, MODE_CBC)
