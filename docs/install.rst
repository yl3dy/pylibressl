Installation
============

Requirements
------------

* LibreSSL >= 2.3.3
* cffi > 1.0.0
* pytest (optional, running tests)
* make (optional, building docs)
* sphinx (optional, building docs)
* sphinx-autoapi (optional, building docs)

Build dependencies:

* *Windows*: Microsoft Visual Studio 2015, cmake >=3.5
* *GNU/Linux*: gcc, make, autotools


Prerequisities
--------------

In the following ``$package_path`` means the path to pylibressl's extracted/cloned source tree root.

GNU/Linux
^^^^^^^^^

Unpack LibreSSL source tarball (can be found `here <http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.3.tar.gz>`_) and execute ``./configure --prefix=PREFIX``,  ``make`` and ``make install``.  You might want to run ``make check`` as well. ``PREFIX`` should be ``$package_path/pylibressl/libressl``.

Windows (Visual Studio)
^^^^^^^^^^^^^^^^^^^^^^^

First of all, `cmake <https://cmake.org/download/>`_ should be installed. The following steps were tested with cmake 3.5 and Visual Studio 2015, but it should work for sufficiently recent versions too.

Unpack LibreSSL sources and execute the following in the source root::

    mkdir build-vs
    cd build-vs
    cmake -G"Visual Studio 14 2015" ..

It will generate Visual Studio solution and other build files. Then you can
build it in MSBuild console using ``msbuild.exe LibreSSL.sln``.

Create directories ``$package_path\pylibressl\libressl\{include,lib}``. Copy ``build-vs\crypto\Debug\crypto.lib`` to ``$package_path\pylibressl\libressl\lib``, ``include\openssl`` to ``$package_path\pylibressl\libressl\include``.


Building and running
--------------------

GNU/Linux
^^^^^^^^^

Before testing/building run ::

    export LD_LIBRARY_PATH=$package_path/pylibressl/libressl/lib

To build extensions in dev mode, call ``make devbuild``. Run tests using ``make test`` or ``make quiet_test``. To build the package so that it would be available to other tools use ``python setup.py install`` or ``python setup.py develop``.

Windows
^^^^^^^

Add ``$package_path\libressl\lib`` to your ``PATH``. Build and install package using ``python setup.py install`` or ``python setup.py develop``. Optionally you can run tests using ``python setup.py tests`` or ``python -m pytest`` in the project root.


Generating documentation
------------------------

To build the documentation, install ``sphinx`` and ``sphinx-autoapi`` and run the following in the project root::

    sphinx-apidoc -e -M -o docs/ . setup.py
    cd docs/
    make html

or just ::

    make docs

HTMLs will be written to ``docs/_build/html``.
