import pytest
from pylibressl.rand import get_random_bytes, libressl_get_random_bytes

class GenericRandTest:
    _randfunc = (None,)    # ugly hack to prevent making _randfunc a method

    def test_too_short_length(self):
        _randfunc = self._randfunc[0]
        with pytest.raises(ValueError):
            random = _randfunc(0)

    def test_too_short_length(self):
        _randfunc = self._randfunc[0]
        with pytest.raises(ValueError):
            random = _randfunc(-10)

    def test_non_int_length(self):
        _randfunc = self._randfunc[0]
        with pytest.raises(TypeError):
            random = _randfunc('asdfasdf')

    def test_output_length(self):
        _randfunc = self._randfunc[0]
        length = 64
        assert len(_randfunc(length)) == length

    def test_repeated_invocation(self):
        _randfunc = self._randfunc[0]
        randstr1 = _randfunc(64)
        randstr2 = _randfunc(64)
        assert randstr1 != randstr2


class TestSystemRand(GenericRandTest):
    _randfunc = (get_random_bytes,)

class TestLibreSSLRand(GenericRandTest):
    _randfunc = (libressl_get_random_bytes,)
