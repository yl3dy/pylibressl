LibreSSL cffi bindings for Korobok
==================================

Requirements:

* LibreSSL (headers and libs should be in `/usr/local/ssl/include` and `/usr/local/ssl/lib` respectively)
* cffi > 1.0.0
* pytest

Before testing/building `export LD_LIBRARY_PATH=/usr/local/ssl/lib` should be
called. To build extensions in dev mode, call `./dev_build.sh`. Run tests using
`python3 -m pytest`.
