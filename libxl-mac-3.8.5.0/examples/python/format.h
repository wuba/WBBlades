#ifndef __LIBXLPY_FORMAT__
#define __LIBXLPY_FORMAT__

#include <libxl.h>

typedef struct {
	PyObject_HEAD
	FormatHandle handler;
} XLPyFormat;

#endif
