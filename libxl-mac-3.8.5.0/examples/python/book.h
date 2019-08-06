#ifndef __LIBXLPY_BOOK__
#define __LIBXLPY_BOOK__

#include <libxl.h>

typedef struct {
	PyObject_HEAD
	BookHandle handler;
} XLPyBook;

#endif
