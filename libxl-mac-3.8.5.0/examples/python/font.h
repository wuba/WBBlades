#ifndef __LIBXLPY_FONT__
#define __LIBXLPY_FONT__

#include <libxl.h>

typedef struct {
	PyObject_HEAD
	FontHandle handler;
} XLPyFont;

#endif

