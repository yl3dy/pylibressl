import cryptomodule.digest as dgst
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
        hash = self.HASH_CLASS.new(self.GOOD_STRING).digest()
        assert len(hash) == self.HASH_LENGTH

    def test_wrong_type_input(self):
        bad_string = 'lorem ipsum'
        with pytest.raises(ValueError):
            hash = self.HASH_CLASS.new(bad_string)

    def test_fast_init(self):
        hash_fast = self.HASH_CLASS.new(self.GOOD_STRING)
        hash_seq = self.HASH_CLASS.new()
        hash_seq.update(self.GOOD_STRING)
        assert hash_fast.digest() == hash_seq.digest()

    def test_digest_type(self):
        hash = self.HASH_CLASS.new(self.GOOD_STRING).digest()
        assert type(hash) == type(b'')

    def test_good_string(self):
        hash = self.HASH_CLASS.new(self.GOOD_STRING).digest()
        assert hash == self.GOOD_HASH

    def test_append_data(self):
        good_string_2 = b'lorem ipsum \x12\xfa'
        good_string_long = self.GOOD_STRING + good_string_2

        hash_long = self.HASH_CLASS.new(good_string_long).digest()

        hash_inst = self.HASH_CLASS.new(self.GOOD_STRING)
        hash_inst.update(good_string_2)
        hash_seq = hash_inst.digest()

        assert hash_long == hash_seq

class TestStreebog512(GenericHashTest):
    HASH_CLASS = dgst.Streebog512
    HASH_LENGTH = 64
    GOOD_STRING = b'abcdefghijklmnopqrstvwxyz1234567890'
    GOOD_HASH = b'\r\xcf\xb2\xfb\x89\xb1\xe1\x1e\xa1\xa6=\x92\xfc!&\xd7w|\xa9E@)\tffe\xf0\x02\x17\xe9b\xc0\xd13\x1b\xe50\x81Z\xaa\xd8p\xa9\x15V\x85\x93{\xff\xce\xc1\x0elv\xcf<\x8a\x8c\xc4\xb3&5\xf6D'

class TestSHA512(GenericHashTest):
    HASH_CLASS = dgst.SHA512
    HASH_LENGTH = 64
    GOOD_STRING = b'abcdefghijklmnopqrstvwxyz1234567890'
    GOOD_HASH = b'\x06iV\xb5\xdcW\xee\xe9\xa2\x8d\xb2G\xed)VjT\xab\x9d3\xf6\xa2\x8f\x83\xbe\xc8\xca8\xf0\x82\x00\xe6\xe6*4\xa0y\x19\x9f\xad]\xf9|.[\xcf\xd3\x84\xad\x01\x80\xaf\xa3\xda\x95\x8e\x9b\xe0\x93\xa7\xd6./\x1b'
