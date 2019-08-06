# LibXLPy:
A libxl python wrapper

# Installation on a 32-bit system:

python setup32.py install

# Installation on a 64-bit system:

python setup64.py install

# Issues

If you see the following error:

libxlpy.c:1:20: fatal error: Python.h: No such file or directory
 #include <Python.h>

Please install header files and a static library for Python:

apt-get install python-dev

# Dependencies:
* libxl

# Usage:
See tests under `./tests` folder.
