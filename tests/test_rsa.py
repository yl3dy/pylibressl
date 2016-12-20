import pylibressl.rsa as rsa
import pylibressl.cipher as cipher
from pylibressl.exceptions import *
from pylibressl.digest import Streebog512
import pytest
import os

TEST_PATH = os.path.abspath(os.path.dirname(__file__))

class TestRSAKeypair:
    """Test RSA keypair container."""

    private_key = open(os.path.join(TEST_PATH, 'rsa_keys/private_2048.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_keys/public_2048.pem'), 'rb').read()
    private_key_2 = open(os.path.join(TEST_PATH, 'rsa_keys/private_1024.pem'), 'rb').read()
    public_key_2 = open(os.path.join(TEST_PATH, 'rsa_keys/public_1024.pem'), 'rb').read()

    def test_normal_init_private_public(self):
        kp = rsa.RSAKeypair(public_key=self.public_key,
                            private_key=self.private_key)
        assert kp.has_private_key()

    def test_normal_init_private(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        assert kp.has_private_key()

    def test_normal_init_public(self):
        kp = rsa.RSAKeypair(public_key=self.public_key)
        assert not kp.has_private_key()

    def test_no_keys(self):
        with pytest.raises(ValueError):
            kp = rsa.RSAKeypair()

    def test_wrong_types(self):
        bad_private_key = len(self.private_key)
        bad_public_key = len(self.public_key)
        with pytest.raises(ValueError):
            kp = rsa.RSAKeypair(public_key=bad_public_key,
                                private_key=bad_private_key)

    def test_key_size(self):
        kp_2048 = rsa.RSAKeypair(public_key=self.public_key,
                                 private_key=self.private_key)
        kp_1024 = rsa.RSAKeypair(public_key=self.public_key_2,
                                 private_key=self.private_key_2)
        assert kp_2048.key_size() == 256
        assert kp_1024.key_size() == 128



class TestPublicDerivation:
    """Test public key derivation from private one."""

    private_key = open(os.path.join(TEST_PATH, 'rsa_keys/private_2048.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_keys/public_2048.pem'), 'rb').read()

    def test_correspondence(self):
        derived_public = rsa.public_from_private(self.private_key)
        assert derived_public == self.public_key



class TestRSASign:
    """Test RSA signing."""

    private_key = open(os.path.join(TEST_PATH, 'rsa_keys/private_2048.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_keys/public_2048.pem'), 'rb').read()
    private_key_2 = open(os.path.join(TEST_PATH, 'rsa_keys/private_1024.pem'), 'rb').read()
    good_message = b'This is a good message to sign'*100

    def test_sign_verify(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        assert signer.verify(self.good_message, signature)

    def test_sign_verify_with_pubkey(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)

        kp2 = rsa.RSAKeypair(public_key=self.public_key)
        signer2 = rsa.RSASign_SHA512(kp2)
        assert signer2.verify(self.good_message, signature)

    def test_sign_with_pubkey(self):
        kp = rsa.RSAKeypair(public_key=self.public_key)
        signer = rsa.RSASign_SHA512(kp)
        with pytest.raises(ValueError):
            signature = signer.sign(self.good_message)

    def test_sign_verify_different_keylength(self):
        kp = rsa.RSAKeypair(private_key=self.private_key_2)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        assert signer.verify(self.good_message, signature)

    def test_sign_verify_nonstandart_hash(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        rsasign_streebog = rsa.RSASign.new(Streebog512)
        signer = rsasign_streebog(kp)
        signature = signer.sign(self.good_message)
        assert signer.verify(self.good_message, signature)

    def test_wrong_keypair(self):
        kp = (1,2,3)
        with pytest.raises(ValueError):
            signer = rsa.RSASign_SHA512(kp)

    def test_wrong_type_sign_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        with pytest.raises(ValueError):
            signer.sign(12345)

    def test_wrong_type_verify_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        with pytest.raises(ValueError):
            signer.verify(12345, signature)

    def test_wrong_type_verify_signature(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        with pytest.raises(ValueError):
            signer.verify(self.good_message, 12345678)

    def test_tampered_signature(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        bad_signature = b'\x01' + signature[1:]
        assert not signer.verify(self.good_message, bad_signature)

    def test_tampered_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        bad_message = self.good_message[2:]
        assert not signer.verify(bad_message, signature)

    def test_wrong_signature_length(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign_SHA512(kp)
        signature = signer.sign(self.good_message)
        bad_signature = signature[3:]
        assert not signer.verify(self.good_message, bad_signature)

    def test_inheritance_identification(self):
        assert issubclass(rsa.RSASign_SHA512, rsa.RSASign)


class TestRSACrypt:
    good_msg = b'Some message to asymmetrically encrypt. 1234567890'
    private_key = open(os.path.join(TEST_PATH, 'rsa_keys/private_2048.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_keys/public_2048.pem'), 'rb').read()

    def test_encrypt_decrypt(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        rsacrypt = rsa.RSACrypt_AES256(kp)
        enc_msg, sess_key, iv = rsacrypt.encrypt(self.good_msg)
        dec_msg = rsacrypt.decrypt(enc_msg, sess_key, iv)
        assert dec_msg == self.good_msg

    def test_tampered_session_key(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        rsacrypt = rsa.RSACrypt_AES256(kp)
        enc_msg, sess_key, iv = rsacrypt.encrypt(self.good_msg)
        bad_sess_key = sess_key[1:]
        with pytest.raises(LibreSSLError):
            dec_msg = rsacrypt.decrypt(enc_msg, bad_sess_key, iv)

    def test_inheritance_identification(self):
        assert issubclass(rsa.RSACrypt_AES256, rsa.RSACrypt)


class TestRSAKeygen:
    def test_create(self):
        KEY_SIZE_BITS = 2048
        privkey = rsa.generate_rsa_key(KEY_SIZE_BITS)
        kp = rsa.RSAKeypair(private_key=privkey)
        assert kp.key_size() * 8 == KEY_SIZE_BITS

    def test_wrong_types(self):
        with pytest.raises(ValueError):
            privkey = rsa.generate_rsa_key('asdfasdf')
        with pytest.raises(ValueError):
            privkey = rsa.generate_rsa_key(2048, 'asdfasdf')

    def test_even_exponent(self):
        exponent = 2
        with pytest.raises(ValueError):
            privkey = rsa.generate_rsa_key(exponent=exponent)
