from setuptools import setup

setup(
    setup_requires=['cffi>=1.0.0'],
    cffi_modules=['cryptomodule/digest/build.py:ffi',
                  'cryptomodule/cipher/build.py:ffi'],
    install_requires=['cffi>=1.0.0']
)
