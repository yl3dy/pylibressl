LibreSSL bindings for Python using CFFI
=======================================

Requirements
------------

* LibreSSL (headers and libs should be in `/usr/local/ssl/include` and `/usr/local/ssl/lib` respectively)
* cffi > 1.0.0
* pytest
* make (optional)

Building prerequisities
-----------------------

Unpack LibreSSL source tarball (can be found
[here](http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.1.tar.gz) ) and
execute `./configure` and `make` as usual.  You may run `make check` as well.
Then do `make install --prefix=PREFIX` where `PREFIX` may be `/usr/local/ssl`
or some temporary path (then you should copy created dirs to `/usr/local/ssl`).

Building and running
--------------------

Before testing/building `export LD_LIBRARY_PATH=/usr/local/ssl/lib` should be
called. To build extensions in dev mode, call `make devbuild`. Run tests using
`make tests` or `make quiet_tests`.
