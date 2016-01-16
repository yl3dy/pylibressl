import cryptomodule as cm
import pytest

class GenericHashTest:
    """Base class for hash tests

    The following variables should be set:

        - hash_class    : name of hash class
        - good_string   : valid hash test string
        - good_hash     : correct binary hash value for `good_string`
        - hash_length   : correct length of hash in bytes


    """

    def test_output_length(self):
        hash = self.hash_class.new(self.good_string).digest()
        assert len(hash) == self.hash_length

    def test_wrong_type_input(self):
        bad_string = 'lorem ipsum'
        with pytest.raises(ValueError):
            hash = self.hash_class.new(bad_string)

    def test_fast_init(self):
        hash_fast = self.hash_class.new(self.good_string)
        hash_seq = self.hash_class.new()
        hash_seq.update(self.good_string)
        assert hash_fast.digest() == hash_seq.digest()

    def test_digest_type(self):
        hash = self.hash_class.new(self.good_string).digest()
        assert type(hash) == type(b'')

    def test_good_string(self):
        hash = self.hash_class.new(self.good_string).digest()
        assert hash == self.good_hash

class TestStreebog512(GenericHashTest):
    hash_class = cm.Streebog512Hash
    hash_length = 64
    good_string = b'abcdefghijklmnopqrstvwxyz1234567890'
    good_hash = b'\r\xcf\xb2\xfb\x89\xb1\xe1\x1e\xa1\xa6=\x92\xfc!&\xd7w|\xa9E@)\tffe\xf0\x02\x17\xe9b\xc0\xd13\x1b\xe50\x81Z\xaa\xd8p\xa9\x15V\x85\x93{\xff\xce\xc1\x0elv\xcf<\x8a\x8c\xc4\xb3&5\xf6D'

class TestSHA512(GenericHashTest):
    hash_class = cm.SHA512Hash
    hash_length = 64
    good_string = b'abcdefghijklmnopqrstvwxyz1234567890'
    good_hash = b'\x06iV\xb5\xdcW\xee\xe9\xa2\x8d\xb2G\xed)VjT\xab\x9d3\xf6\xa2\x8f\x83\xbe\xc8\xca8\xf0\x82\x00\xe6\xe6*4\xa0y\x19\x9f\xad]\xf9|.[\xcf\xd3\x84\xad\x01\x80\xaf\xa3\xda\x95\x8e\x9b\xe0\x93\xa7\xd6./\x1b'
