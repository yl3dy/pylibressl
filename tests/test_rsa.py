import pylibressl.rsa as rsa
import pylibressl.cipher as cipher
from pylibressl.exceptions import *
from pylibressl.digest import Streebog512
import pytest
import os

TEST_PATH = os.path.abspath(os.path.dirname(__file__))

class TestRSAKeypair:
    """Test RSA keypair container."""

    private_key = open(os.path.join(TEST_PATH, 'rsa_private.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_public.pem'), 'rb').read()

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

class TestRSASign:
    """Test RSA signing."""

    private_key = open(os.path.join(TEST_PATH, 'rsa_private.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_public.pem'), 'rb').read()
    good_message = b'This is a good message to sign'*100

    def test_sign_verify(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        assert signer.verify(self.good_message, signature)

    def test_sign_verify_nonstandart_hash(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp, Streebog512)
        signature = signer.sign(self.good_message)
        assert signer.verify(self.good_message, signature)

    def test_wrong_keypair(self):
        kp = (1,2,3)
        with pytest.raises(ValueError):
            signer = rsa.RSASign.new(kp)

    def test_wrong_type_sign_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        with pytest.raises(ValueError):
            signer.sign(12345)

    def test_wrong_type_verify_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        with pytest.raises(ValueError):
            signer.verify(12345, signature)

    def test_wrong_type_verify_signature(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        with pytest.raises(ValueError):
            signer.verify(self.good_message, 12345678)

    def test_tampered_signature(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        bad_signature = b'\x01' + signature[1:]
        assert not signer.verify(self.good_message, bad_signature)

    def test_tampered_message(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        bad_message = self.good_message[2:]
        assert not signer.verify(bad_message, signature)

    def test_wrong_signature_length(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        signer = rsa.RSASign.new(kp)
        signature = signer.sign(self.good_message)
        bad_signature = signature[3:]
        assert not signer.verify(self.good_message, bad_signature)


class TestRSACrypt:
    good_msg = b'Some message to asymmetrically encrypt. 1234567890'
    private_key = open(os.path.join(TEST_PATH, 'rsa_private.pem'), 'rb').read()
    public_key = open(os.path.join(TEST_PATH, 'rsa_public.pem'), 'rb').read()

    def test_encrypt_decrypt(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        rsacrypt = rsa.RSACrypt.new(kp)
        enc_msg, sess_key, iv = rsacrypt.encrypt(self.good_msg)
        dec_msg = rsacrypt.decrypt(enc_msg, sess_key, iv)
        assert dec_msg == self.good_msg

    def test_tampered_session_key(self):
        kp = rsa.RSAKeypair(private_key=self.private_key)
        rsacrypt = rsa.RSACrypt.new(kp)
        enc_msg, sess_key, iv = rsacrypt.encrypt(self.good_msg)
        bad_sess_key = sess_key[1:]
        with pytest.raises(LibreSSLError):
            dec_msg = rsacrypt.decrypt(enc_msg, bad_sess_key, iv)
