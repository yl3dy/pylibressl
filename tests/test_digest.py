import pylibressl.digest as dgst
from pylibressl.exceptions import DigestReuseError
import pytest

class GenericHashTest:
    """Base class for hash tests

    The following variables should be set:

        - HASH_CLASS    : name of hash class
        - GOOD_STRING   : valid hash test string
        - GOOD_HASH     : correct binary hash value for `good_string`
        - HASH_LENGTH   : correct length of hash in bytes


    """

    def test_output_length(self):
        hash = self.HASH_CLASS(self.GOOD_STRING).digest()
        assert len(hash) == self.HASH_LENGTH

    def test_wrong_type_input(self):
        bad_string = 'lorem ipsum'
        with pytest.raises(ValueError):
            hash = self.HASH_CLASS(bad_string)

    def test_fast_init(self):
        hash_fast = self.HASH_CLASS(self.GOOD_STRING)
        hash_seq = self.HASH_CLASS()
        hash_seq.update(self.GOOD_STRING)
        assert hash_fast.digest() == hash_seq.digest()

    def test_digest_type(self):
        hash = self.HASH_CLASS(self.GOOD_STRING).digest()
        assert type(hash) == type(b'')

    def test_good_string(self):
        hash = self.HASH_CLASS(self.GOOD_STRING).digest()
        assert hash == self.GOOD_HASH

    def test_append_data(self):
        good_string_2 = b'lorem ipsum \x12\xfa'
        good_string_long = self.GOOD_STRING + good_string_2

        hash_long = self.HASH_CLASS(good_string_long).digest()

        hash_inst = self.HASH_CLASS(self.GOOD_STRING)
        hash_inst.update(good_string_2)
        hash_seq = hash_inst.digest()

        assert hash_long == hash_seq

    def test_no_update_after_digest(self):
        hash = self.HASH_CLASS(self.GOOD_STRING)
        d = hash.digest()
        with pytest.raises(DigestReuseError):
            hash.update(b'asdfasdf')

    def test_size_sanity(self):
        assert self.HASH_CLASS.size() <= self.HASH_CLASS.max_size()


class TestSHA256(GenericHashTest):
    HASH_CLASS = dgst.SHA256
    HASH_LENGTH = 32
    GOOD_STRING = b'abcdefghijklmnopqrstvwxyz1234567890'
    GOOD_HASH = b'[(z)\xae2\xa1z\xb2m\x05\xf6\xcf\xd4\x891\x04U\xa2\xe8\x0b\xf9va\xfc\xe1\x1a\xb4eO\xe1\xc6'

    def test_size_from_book(self):
        assert self.HASH_CLASS.size() == 256 / 8
        assert self.HASH_CLASS.block_size() == 512 / 8

class TestStreebog512(GenericHashTest):
    HASH_CLASS = dgst.Streebog512
    HASH_LENGTH = 64
    GOOD_STRING = b'abcdefghijklmnopqrstvwxyz1234567890'
    GOOD_HASH = b'\r\xcf\xb2\xfb\x89\xb1\xe1\x1e\xa1\xa6=\x92\xfc!&\xd7w|\xa9E@)\tffe\xf0\x02\x17\xe9b\xc0\xd13\x1b\xe50\x81Z\xaa\xd8p\xa9\x15V\x85\x93{\xff\xce\xc1\x0elv\xcf<\x8a\x8c\xc4\xb3&5\xf6D'

    def test_size_from_book(self):
        assert self.HASH_CLASS.size() == 512 / 8

class TestSHA512(GenericHashTest):
    HASH_CLASS = dgst.SHA512
    HASH_LENGTH = 64
    GOOD_STRING = b'abcdefghijklmnopqrstvwxyz1234567890'
    GOOD_HASH = b'\x06iV\xb5\xdcW\xee\xe9\xa2\x8d\xb2G\xed)VjT\xab\x9d3\xf6\xa2\x8f\x83\xbe\xc8\xca8\xf0\x82\x00\xe6\xe6*4\xa0y\x19\x9f\xad]\xf9|.[\xcf\xd3\x84\xad\x01\x80\xaf\xa3\xda\x95\x8e\x9b\xe0\x93\xa7\xd6./\x1b'

    def test_size_from_book(self):
        assert self.HASH_CLASS.size() == 512 / 8
        assert self.HASH_CLASS.block_size() == 1024 / 8
