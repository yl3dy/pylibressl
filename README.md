# LibreSSL bindings for Python using CFFI

## Requirements

* LibreSSL >= 2.3.3
* cffi > 1.0.0
* pytest (optional, running tests)
* make (optional, building docs)
* sphinx (optional, building docs)


## Building prerequisities

### GNU/Linux

Unpack LibreSSL source tarball (can be found
[here](http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.1.tar.gz) ) and
execute `./configure --prefix=PREFIX`,  `make` and `make install`.  You may run `make check` as well.
`PREFIX` should be `$package_path/libressl`. `$package_path` is a path of
`pylibressl` directory inside distribution root (package root).

### Windows (Visual Studio)

First of all, [cmake](https://cmake.org/download/) should be installed. The following steps were tested with cmake 3.5 and Visual Studio 2015, but it should work for sufficiently recent versions too.

Unpack LibreSSL sources and execute the following in the source root:

    mkdir build-vs
    cd build-vs
    cmake -G"Visual Studio 14 2015" ..

It will generate Visual Studio solution and other build files. Then you can
build it in MSBuild console using `msbuild.exe LibreSSL.sln`.

Create directories `$package_path\libressl\{include,lib}`. Copy `build-vs\crypto\Debug\crypto.lib` to `$package_path\libressl\lib\`, `include\openssl` to `$package_path\libressl\include\`.


## Building and running

### GNU/Linux

Before testing/building `export LD_LIBRARY_PATH=$package_path/libressl/lib` should be
called. To build extensions in dev mode, call `make devbuild`. Run tests using
`make tests` or `make quiet_tests`. To build package so it would be available
to other tools use `python setup.py install` or `python setup.py develop`.

### Windows

Add `$package_path\libressl\lib` to your PATH. Build and install package using
`python setup.py install` or `python setup.py develop`. Optionally you can run
tests using `python setup.py tests` or `python -m pytest` in the project root.


## Building documentation

To build documentation, install `sphinx` and run the following in project root:

    sphinx-apidoc -e -M -o docs/ . setup.py
    cd docs/
    make html

or just

    make docs

at the project root.

HTMLs will be in `docs/_build/html` directory.
