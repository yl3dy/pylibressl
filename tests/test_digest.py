import cryptomodule as cm
import pytest

class TestStreebog512:
    good_string = b'abcdefghijklmnopqrstvwxyz1234567890'
    good_hash = b'\xd0sUD\xae+\xa4\xe5#$=8\x7f\xebM\xda=r\x0e:N\x1f\x06\x07^\x1e\xb9\xebTcMUT\x01z\x8d\xf3\x062p\xc9\xa0w\xc3\x9e\x1a\x1c0+0\xfcv [\xc8\xae\x04E\xaa\x86\xd2g\x17D'

    def test_output_length(self):
        hash = cm.Streebog512Hash.new(self.good_string).digest()
        assert len(hash) == 64

    def test_wrong_type_input(self):
        bad_string = 'lorem ipsum'
        with pytest.raises(ValueError):
            hash = cm.Streebog512Hash.new(bad_string)

    def test_fast_init(self):
        hash_fast = cm.Streebog512Hash.new(self.good_string)
        hash_seq = cm.Streebog512Hash.new()
        hash_seq.update(self.good_string)
        assert hash_fast.digest() == hash_seq.digest()

    def test_digest_type(self):
        hash = cm.Streebog512Hash.new(self.good_string).digest()
        assert type(hash) == type(b'')

    def test_good_string(self):
        hash = cm.Streebog512Hash.new(self.good_string).digest()
        assert hash == self.good_hash
