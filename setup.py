from setuptools import setup, find_packages

setup(
    name='pylibressl',
    version='0.4.1',

    packages=find_packages(),
    package_data={'pylibressl': ['libressl/lib/*.*']},

    setup_requires=['cffi>=1.0.0', 'pytest-runner'],
    cffi_modules=['pylibressl/build.py:ffi'],
    install_requires=['cffi>=1.0.0'],
    tests_require=['pytest'],

    zip_safe=False
)
