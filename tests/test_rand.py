import pytest
from pylibressl.rand import get_random_bytes

def test_too_short_length():
    with pytest.raises(ValueError):
        random = get_random_bytes(0)

def test_too_short_length():
    with pytest.raises(ValueError):
        random = get_random_bytes(-10)

def test_non_int_length():
    with pytest.raises(TypeError):
        random = get_random_bytes('asdfasdf')

def test_output_length():
    length = 64
    assert len(get_random_bytes(length)) == length
