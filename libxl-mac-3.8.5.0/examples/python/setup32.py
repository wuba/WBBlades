from distutils.core import setup, Extension

module = Extension('libxlpy'
        , sources = [
            'libxlpy.c',
            'book.c',
            'sheet.c',
            'format.c',
            'font.c'
            ]
        , extra_compile_args = ['-I../../include_c']
        , extra_link_args = ['-L../../lib', '-lxl', '-Wl,-rpath,../../lib']
        )
 
setup (name = 'libxlpy'
        , version = '1.0'
        , description = 'libxl python wrapper'
        , ext_modules = [module]
        )
