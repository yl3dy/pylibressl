from setuptools import setup

setup(
    setup_requires=['cffi>=1.0.0'],
    cffi_modules=['cryptomodule/build.py:ffi'],
    install_requires=['cffi>=1.0.0']
)
