import os

TOPLEVEL_PACKAGE_PATH = os.path.abspath(os.path.dirname(__file__))
LIBRARIES = ['crypto']
LIBRARY_DIRS = ['/usr/local/ssl/lib']
INCLUDE_DIRS = ['/usr/local/ssl/include', TOPLEVEL_PACKAGE_PATH]
EXTRA_COMPILE_ARGS = []
EXTRA_LINK_ARGS = []

def is_filename_source(fname):
    """Check if specified filename is a valid C source.

    Rules: '.c' extension and never starts with '_' (not to mix with
    CFFI-generated sources).

    """
    return fname.endswith('.c') and not fname.startswith('_')

def configure_ffi(ffi, package_name, cdef):
    """Configure FFI object using default settings.

    Assume that the main header is {package_name}.h and grab all C source files
    in package directory.
    """
    join = os.path.join   # just a shorthand

    ffi.cdef(cdef)

    source = '#include "{pkg}/{pkg}.h"'.format(pkg=package_name)
    # Look for additional source files in package directory
    source_files = [join('cryptomodule', package_name, fname) for fname in
                    os.listdir(join(TOPLEVEL_PACKAGE_PATH, package_name)) if
                    is_filename_source(fname)]
    ffi.set_source('cryptomodule.{pkg}._{pkg}'.format(pkg=package_name),
                   source, libraries=LIBRARIES, library_dirs=LIBRARY_DIRS,
                   include_dirs=INCLUDE_DIRS, sources=source_files,
                   extra_compile_args=EXTRA_COMPILE_ARGS,
                   extra_link_args=EXTRA_LINK_ARGS)
