import pytest
from pylibressl.cipher import GOST89_CTR, AES256_CTR, AES256_CBC, AES256_GCM
from pylibressl.cipher import MODE_CTR, MODE_CBC, MODE_GCM
from pylibressl.exceptions import AuthencityError, LibreSSLError

class GenericOrdinaryCipherTest:
    """Base class for ordinary cipher tests.

    Should be subclassed for every cipher with mode.

    Subclasses ought to define the following variables:

        - CIPHER_CLASS   : name of cipher class
        - KEY_LENGTH     : only for some sanity checks
        - IV_LENGTH      :  --"--

    """

    CIPHER_CLASS = None
    KEY_LENGTH = None
    IV_LENGTH = None

    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'

    def setup_key_iv(self):
        self.good_key = b'\xa1' * self.CIPHER_CLASS.key_length()
        self.good_iv = b'\xaf' * self.CIPHER_CLASS.iv_length()
        self.good_key_2 = b'\xf1' * self.CIPHER_CLASS.key_length()
        self.good_iv_2 = b'\x3f' * self.CIPHER_CLASS.iv_length()

    def test_encryption_presence(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded = cipher.encrypt(self.good_string)
        assert self.good_string != encoded

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded = cipher.encrypt(self.good_string)
        decoded = cipher.decrypt(encoded)
        assert self.good_string == decoded

    def test_decrypt_with_different_iv(self):
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS.new(self.good_key, self.good_iv_2)
        encoded = cipher_1.encrypt(self.good_string)
        decoded = cipher_2.decrypt(encoded)
        assert self.good_string != decoded

    def test_decrypt_with_different_keys(self):
        # The following test should produce LibreSSL error for CBC mode (maybe
        # other block modes):
        # digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:evp/evp_enc.c:529:
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS.new(self.good_key_2, self.good_iv)
        encoded = cipher_1.encrypt(self.good_string)

        if self.CIPHER_CLASS.mode() == MODE_CBC:
            with pytest.raises(LibreSSLError):
                decoded = cipher_2.decrypt(encoded)
        else:
            decoded = cipher_2.decrypt(encoded)
            assert self.good_string != decoded

    def test_input_types(self):
        bad_key = 'lorem ipsum'
        bad_iv = 'sapere aude'

        with pytest.raises(ValueError):
            cipher = self.CIPHER_CLASS.new(bad_key, bad_iv)


class GenericAEADCipherTest:
    """Base class for AEAD cipher tests.

    Should be subclassed for every cipher with mode.

    Subclasses ought to define the following variables:

        - CIPHER_CLASS   : name of cipher class
        - KEY_LENGTH     : only for some sanity checks
        - IV_LENGTH      :  --"--

    """

    CIPHER_CLASS = None
    KEY_LENGTH = None
    IV_LENGTH = None

    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'
    good_aad = b'Example AAD message. \x00\xff\x11'

    def setup_key_iv(self):
        self.good_key = b'\xa1' * self.CIPHER_CLASS.key_length()
        self.good_iv = b'\xaf' * self.CIPHER_CLASS.iv_length()
        self.good_key_2 = b'\xf1' * self.CIPHER_CLASS.key_length()
        self.good_iv_2 = b'\x3f' * self.CIPHER_CLASS.iv_length()

    def test_encryption_presence(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        ciphertext, tag = cipher.encrypt(self.good_string)
        assert ciphertext != self.good_string
        assert tag != b'\x00'*len(tag)

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string)
        decoded = cipher.decrypt(encoded, tag=tag)
        assert self.good_string == decoded

    def test_encrypt_decrypt_with_aad(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)
        decoded = cipher.decrypt(encoded, tag=tag, aad=self.good_aad)
        assert decoded == self.good_string

    def test_decrypt_with_other_iv_aead(self):
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS.new(self.good_key, self.good_iv_2)
        encoded, tag = cipher_1.encrypt(self.good_string)
        with pytest.raises(AuthencityError):
            decoded = cipher_2.decrypt(encoded, tag=tag)

    def test_decrypt_with_other_tag_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string)
        bad_tag = b'\x01' * len(tag)

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=bad_tag)

    def test_decrypt_with_other_aad_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)
        new_aad = b'Some other AAD message'

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=tag, aad=new_aad)

    def test_decrypt_without_aad_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=tag)

    def test_input_types_aead(self):
        self.setup_key_iv()
        bad_aad = 'asdfasdfsdf'
        bad_tag = 42

        cipher = self.CIPHER_CLASS.new(self.good_key, self.good_iv)
        with pytest.raises(ValueError):
            cipher.encrypt(self.good_string, aad=bad_aad)
        with pytest.raises(ValueError):
            cipher.decrypt(self.good_string, tag=bad_tag)




class TestAES256_CTR(GenericOrdinaryCipherTest):
    CIPHER_CLASS = AES256_CTR
    KEY_LENGTH = 32
    IV_LENGTH = 16

class TestAES256_CBC(GenericOrdinaryCipherTest):
    CIPHER_CLASS = AES256_CBC
    KEY_LENGTH = 32
    IV_LENGTH = 16

class TestGOST89_CTR(GenericOrdinaryCipherTest):
    CIPHER_CLASS = GOST89_CTR
    KEY_LENGTH = 32
    IV_LENGTH = 8
