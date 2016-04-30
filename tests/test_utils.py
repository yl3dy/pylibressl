import pylibressl.utils as utils
import pytest

class TestSecureCompare:
    def test_correct_args(self):
        rhs = b'asdf \x00 \xfe 23456'
        lhs = b'asdf \x00 \xfe 23456'
        assert utils.secure_compare(rhs, lhs)

    def test_the_same_string(self):
        rhs = lhs = b'abcdef'
        assert utils.secure_compare(rhs, lhs)

    def test_unequal_args(self):
        rhs = b'asdf \xff'
        lhs = b'123456'
        assert not utils.secure_compare(rhs, lhs)

    def test_different_lengths(self):
        rhs = b'123456789'
        lhs = b'1234567'
        with pytest.raises(ValueError):
            utils.secure_compare(rhs, lhs)
