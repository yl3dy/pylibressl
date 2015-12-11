LibreSSL cffi bindings for Korobok
==================================

Requires LibreSSL and cffi. Headers and libs should be in
`/usr/local/ssl/include` and `/usr/local/ssl/lib` respectively. Use `python3
cryptomodule/build.py` to build extensions in development mode. Run tests using
`LD_LIBRARY_PATH=/usr/local/ssl/lib python3 testt.py`.
