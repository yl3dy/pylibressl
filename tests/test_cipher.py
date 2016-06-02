import pytest
from pylibressl.cipher import GOST89_CTR, AES256_CTR, AES256_CBC, AES256_GCM
from pylibressl.cipher import MODE_CTR, MODE_CBC, MODE_GCM, BLOCK_MODES
from pylibressl.cipher import CipherHMAC, GOST89_HMAC_Streebog512
from pylibressl.cipher import AES256_HMAC_SHA512
from pylibressl.cipher import OnionCipher, Onion_AES256_GOST89
from pylibressl.digest import SHA256
from pylibressl.exceptions import AuthencityError, LibreSSLError, PaddingError

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

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded = cipher.encrypt(self.good_string)
        assert self.good_string != encoded

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded = cipher.encrypt(self.good_string)
        decoded = cipher.decrypt(encoded)
        assert self.good_string == decoded

    def test_decrypt_with_different_iv(self):
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS(self.good_key, self.good_iv_2)
        encoded = cipher_1.encrypt(self.good_string)
        decoded = cipher_2.decrypt(encoded)
        assert self.good_string != decoded

    def test_decrypt_with_different_keys(self):
        # The following test should produce LibreSSL error for block modes:
        # digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:evp/evp_enc.c:529:
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS(self.good_key_2, self.good_iv)
        encoded = cipher_1.encrypt(self.good_string)

        if self.CIPHER_CLASS.mode() in BLOCK_MODES:
            with pytest.raises(PaddingError):
                decoded = cipher_2.decrypt(encoded)
        else:
            decoded = cipher_2.decrypt(encoded)
            assert self.good_string != decoded

    def test_input_types(self):
        bad_key = 'lorem ipsum'
        bad_iv = 'sapere aude'

        with pytest.raises(ValueError):
            cipher = self.CIPHER_CLASS(bad_key, bad_iv)


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

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        ciphertext, tag = cipher.encrypt(self.good_string)
        assert ciphertext != self.good_string
        assert tag != b'\x00'*len(tag)

    def test_encrypt_decrypt(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string)
        decoded = cipher.decrypt(encoded, tag=tag)
        assert self.good_string == decoded

    def test_encrypt_decrypt_with_aad(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)
        decoded = cipher.decrypt(encoded, tag=tag, aad=self.good_aad)
        assert decoded == self.good_string

    def test_decrypt_with_other_iv_aead(self):
        self.setup_key_iv()

        cipher_1 = self.CIPHER_CLASS(self.good_key, self.good_iv)
        cipher_2 = self.CIPHER_CLASS(self.good_key, self.good_iv_2)
        encoded, tag = cipher_1.encrypt(self.good_string)
        with pytest.raises(AuthencityError):
            decoded = cipher_2.decrypt(encoded, tag=tag)

    def test_decrypt_with_other_tag_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string)
        bad_tag = b'\x01' * len(tag)

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=bad_tag)

    def test_decrypt_with_other_aad_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)
        new_aad = b'Some other AAD message'

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=tag, aad=new_aad)

    def test_decrypt_without_aad_aead(self):
        self.setup_key_iv()

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
        encoded, tag = cipher.encrypt(self.good_string, aad=self.good_aad)

        with pytest.raises(AuthencityError):
            decoded = cipher.decrypt(encoded, tag=tag)

    def test_input_types_aead(self):
        self.setup_key_iv()
        bad_aad = 'asdfasdfsdf'
        bad_tag = 42

        cipher = self.CIPHER_CLASS(self.good_key, self.good_iv)
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



class GenericCipherHMACTest:
    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'
    cipher_hmac = GOST89_HMAC_Streebog512

    def setup_key_iv(self):
        self.key = b'\x11' * self.cipher_hmac.CIPHER_TYPE.key_length()
        self.iv = b'\x0f' * self.cipher_hmac.CIPHER_TYPE.iv_length()

    def test_encrypt_decrypt(self):
        self.setup_key_iv()
        cipher_ae = self.cipher_hmac(self.key, self.iv)
        enc, auth_code = cipher_ae.encrypt(self.good_string)
        dec = cipher_ae.decrypt(enc, auth_code)
        assert dec == self.good_string

    def test_bad_auth_code(self):
        self.setup_key_iv()
        cipher_ae = self.cipher_hmac(self.key, self.iv)
        enc, auth_code = cipher_ae.encrypt(self.good_string)
        bad_auth_code = b'\xff' + auth_code[1:]
        with pytest.raises(AuthencityError):
            dec = cipher_ae.decrypt(enc, bad_auth_code)

    def test_corrupted_data(self):
        self.setup_key_iv()
        cipher_ae = self.cipher_hmac(self.key, self.iv)
        enc, auth_code = cipher_ae.encrypt(self.good_string)
        bad_enc = b'\xff' + enc[1:]
        with pytest.raises(AuthencityError):
            dec = cipher_ae.decrypt(bad_enc, auth_code)


class TestCipherHMAC_GOST89_Streebog512_Preset(GenericCipherHMACTest):
    cipher_hmac = GOST89_HMAC_Streebog512

class TestCipherHMAC_AES256_SHA512_Preset(GenericCipherHMACTest):
    cipher_hmac = AES256_HMAC_SHA512

class TestCipherHMAC_AES256CBC_SHA256(GenericCipherHMACTest):
    cipher_hmac = CipherHMAC.new(AES256_CBC, SHA256)



class TestOnionCipher:
    good_string = b'QY\xf4\xff\x9e\xee\xe2\xad\xcf\xf8\xf5\xf5\xddm\x18z\xbbp\xb83\x8aZ\x9a\x9a\x81\xfd\x10?\xac\xd3\xf9\xfcE\x81*\xeda\xf9i\xce\xd9\xe6\xecH\xdf\xe3\x1c}\x18\x16\x06bJ\xcb\xd7\x1b\x90\x04j\xe3\xe3\x05d\x86\xfe\x91\x13I\xb7\xf3\x869M\x16.\x03\xcf\xdf\x99\xa0`l\xcf\x06\xc7\xa1\x86xd\x0c\xa0\xd3\xbf\x8ct\t=\x8c\xe0\x05\xe2\xa2\xea18$b\t\xbf\xbe#o\xeb\x8f\xa8?\x89\x8aI\xa6\x00\x97\x0c\x99\xe7\xfe\x0bI'

    def test_encrypt_decrypt_preset(self):
        key_aes = b'\x12'*AES256_CTR.key_length()
        iv_aes = b'\xf0'*AES256_CTR.iv_length()
        key_gost = b'\x3d'*GOST89_CTR.key_length()
        iv_gost = b'\xac'*GOST89_CTR.iv_length()

        key_list = [(key_aes, iv_aes), (key_gost, iv_gost)]

        onion_cipher = Onion_AES256_GOST89(key_list)
        enc_msg, auth_codes = onion_cipher.encrypt(self.good_string)
        assert self.good_string == onion_cipher.decrypt(enc_msg, auth_codes)

    def test_encrypt_decrypt_noauth(self):
        onion_cipher_cls = OnionCipher.new((AES256_CBC, AES256_CTR))
        key_aes_1 = b'\x12'*AES256_CBC.key_length()
        iv_aes_1 = b'\xf0'*AES256_CBC.iv_length()
        key_aes_2 = b'\x3d'*AES256_CTR.key_length()
        iv_aes_2 = b'\xac'*AES256_CTR.iv_length()
        key_list = [(key_aes_1, iv_aes_1), (key_aes_2, iv_aes_2)]

        onion_cipher = onion_cipher_cls(key_list)
        enc_msg, auth_codes = onion_cipher.encrypt(self.good_string)
        assert self.good_string == onion_cipher.decrypt(enc_msg, auth_codes)
        assert auth_codes == [None, None]

    def test_wrong_key_list(self):
        key_list = [(b'asdf', b'23456789')]
        with pytest.raises(ValueError):
            onion_cipher = Onion_AES256_GOST89(key_list)
